# SPDX-License-Identifier: AGPL-3.0-or-later
package PVE::EasyActions::Config;

use strict;
use warnings;
use feature 'fc';

use Digest::SHA qw(sha256_hex);
use Encode qw(encode_utf8);
use Errno qw(EEXIST ENOENT EWOULDBLOCK);
use Fcntl qw(O_CREAT O_NOFOLLOW O_WRONLY FD_CLOEXEC F_SETFD LOCK_EX LOCK_NB);
use File::Temp ();
use JSON::PP;

use constant MAX_CONFIG_BYTES => 96 * 1024;
use constant MAX_COMMAND_BYTES => 8 * 1024;
use constant MAX_ACTIONS => 12;
use constant MAX_STEPS => 20;
use constant MAX_TIMEOUT => 1800;
use constant MAX_SECRET_BINDINGS => 8;
use constant MAX_ACTION_SECRET_BYTES => 64 * 1024;
use constant SECRET_NAME_PATTERN => '[A-Za-z][A-Za-z0-9_-]{0,47}';

my $json = JSON::PP->new->canonical->utf8;

sub valid_name {
    my ($value) = @_;
    return defined($value) && !ref($value) && length($value) <= 64
        && $value =~ /\A\S(?:.*\S)?\z/ && $value !~ /[\p{Cc}\p{Cf}]/;
}

sub validate_bindings {
    my ($bindings, $label) = @_;
    die "$label must have a list of up to 8 secret bindings.\n"
        if ref($bindings) ne 'ARRAY' || @$bindings > MAX_SECRET_BINDINGS;
    my %environment;
    my @validated;
    my $secret_name = SECRET_NAME_PATTERN;
    for my $binding (@$bindings) {
        die "$label has an invalid secret binding.\n"
            if ref($binding) ne 'HASH' || keys(%$binding) != 3;
        my ($name, $env, $mode) = @{$binding}{qw(name env mode)};
        die "$label has an invalid secret name.\n"
            if !defined($name) || ref($name) || $name !~ /\A$secret_name\z/;
        die "$label has an invalid or reserved secret environment variable.\n"
            if !defined($env) || ref($env) || $env !~ /\A[A-Z_][A-Z0-9_]{0,63}\z/
            || $env =~ /\A(?:BASH_|LD_|DYLD_|EASY_ACTIONS_)/
            || $env =~ /\A(?:_|ENV|SHELLOPTS|BASHOPTS|IFS|PATH|CDPATH|UID|EUID|PPID|GROUPS|PWD|OLDPWD|GLOBIGNORE|PROMPT_COMMAND)\z/;
        die "$label assigns the same environment variable more than once.\n" if $environment{$env}++;
        die "$label must expose each secret as a file or environment value.\n"
            if !defined($mode) || ref($mode) || $mode !~ /\A(?:file|env)\z/;
        push @validated, { name => "$name", env => "$env", mode => "$mode" };
    }
    return \@validated;
}

sub decode_actions {
    my ($input) = @_;
    my $bytes = encode_utf8($input);
    die "Actions JSON exceeds 96 KiB.\n" if length($bytes) > MAX_CONFIG_BYTES;
    my $value = eval { $json->decode($bytes) };
    die "Actions must be a valid JSON array.\n" if $@;
    return validate_sized_actions($value);
}

sub validate_config_size {
    my ($actions) = @_;
    die "Actions JSON exceeds 96 KiB.\n" if length($json->encode($actions)) > MAX_CONFIG_BYTES;
}

sub validate_sized_actions {
    my ($actions) = @_;
    my $validated = validate_actions($actions);
    validate_config_size($validated);
    return $validated;
}

sub validate_actions {
    my ($actions) = @_;
    die "Provide an array of up to 12 actions.\n"
        if ref($actions) ne 'ARRAY' || @$actions > MAX_ACTIONS;

    my %names = map { $_ => 1 } qw(config history);
    my @validated;
    for my $action (@$actions) {
        my $action_label = 'Action ' . (1 + @validated);
        die "$action_label must contain a valid name of up to 64 characters and steps.\n"
            if ref($action) ne 'HASH' || !valid_name($action->{name})
            || grep { $_ ne 'name' && $_ ne 'steps' && $_ ne 'secrets' } keys(%$action);
        my $name = "$action->{name}";
        die "$action_label has a duplicate or reserved name.\n" if $names{fc($name)}++;
        my $steps = $action->{steps};
        die "$action_label must have between 1 and 20 steps.\n"
            if ref($steps) ne 'ARRAY' || !@$steps || @$steps > MAX_STEPS;

        my @validated_steps;
        for my $step (@$steps) {
            my $label = "$action_label, step " . (1 + @validated_steps);
            die "$label must contain a valid name of up to 64 characters, command and timeout.\n"
                if ref($step) ne 'HASH' || keys(%$step) != 3 || !valid_name($step->{name});
            my $command = $step->{command};
            die "$label needs a command of up to 8192 bytes without NUL bytes.\n"
                if !defined($command) || ref($command) || $command !~ /\S/
                || $command =~ /\x00/ || length(encode_utf8($command)) > MAX_COMMAND_BYTES;
            my $timeout = $step->{timeout};
            die "$label needs a whole timeout between 1 and 1800 seconds.\n"
                if !defined($timeout) || ref($timeout) || $timeout !~ /\A[1-9][0-9]{0,3}\z/
                || $timeout > MAX_TIMEOUT;

            # Form controls on some platforms supply CRLF line endings.
            $command =~ s/\r\n?/\n/g;
            push @validated_steps, { name => "$step->{name}", command => "$command", timeout => 0 + $timeout };
        }
        my $validated_action = { name => $name, steps => \@validated_steps };
        if (exists($action->{secrets})) {
            my $bindings = validate_bindings($action->{secrets}, $action_label);
            $validated_action->{secrets} = $bindings if @$bindings;
        }
        push @validated, $validated_action;
    }

    return \@validated;
}

sub ensure_directory {
    my ($directory) = @_;
    mkdir($directory, 0700) || $! == EEXIST or die "Unable to create Easy Actions storage: $!\n";
    my @info = lstat($directory);
    die "Easy Actions storage must be a private directory owned by the service.\n"
        if !@info || !-d _ || $info[4] != $> || ($info[2] & 0777) != 0700;
}

sub try_lock {
    my ($path) = @_;
    sysopen(my $lock, $path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600)
        or die "Unable to open Easy Actions lock: $!\n";
    # The native worker inherits this descriptor, its guest transport processes do not.
    defined(fcntl($lock, F_SETFD, FD_CLOEXEC)) or die "Unable to configure Easy Actions lock: $!\n";
    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        return undef if $! == EWOULDBLOCK;
        die "Unable to acquire Easy Actions lock: $!\n";
    }
    return $lock;
}

sub read_config {
    my ($path, $identity, $include_vault_slot) = @_;
    my ($raw, $saved);
    if (open(my $fh, '<:raw', $path)) {
        $raw = '';
        while (!eof($fh)) {
            my $read = read($fh, my $chunk, 8192);
            die "Unable to read Easy Actions config: $!\n" if !defined($read);
            $raw .= $chunk;
            die "Saved Easy Actions config exceeds available storage limit.\n"
                if length($raw) > MAX_CONFIG_BYTES + 256;
        }
        close($fh) or die "Unable to close Easy Actions config: $!\n";
        $saved = eval { $json->decode($raw) };
        die "Saved Easy Actions config is invalid.\n"
            if $@ || ref($saved) ne 'HASH' || ($saved->{version} // 0) ne '1'
            || ($saved->{identity} // '') !~ /\A[0-9a-f]{64}\z/;
        die "Saved Easy Actions vault slot is invalid.\n"
            if exists($saved->{vaultSlot}) && !valid_vault_slot($saved->{vaultSlot});
        $saved->{actions} = validate_actions($saved->{actions});
    } elsif ($! != ENOENT) {
        die "Unable to open Easy Actions config: $!\n";
    }

    # Include the guest identity even before the first save and after a guest is replaced.
    my $config = { revision => sha256_hex($identity . "\n" . ($raw // '')), actions => [] };
    $config->{vaultSlot} = $saved ? $saved->{vaultSlot} // 0 : 0 if $include_vault_slot;
    return $config if !$saved;
    if ($saved->{identity} eq $identity) {
        $config->{actions} = $saved->{actions};
    } elsif (@{ $saved->{actions} }) {
        $config->{previousActions} = $saved->{actions};
    }
    return $config;
}

sub valid_vault_slot {
    my ($slot) = @_;
    return defined($slot) && !ref($slot) && $slot =~ /\A[01]\z/;
}

sub prepare_config {
    my ($directory, $identity, $actions, $slot) = @_;
    $slot //= 0;
    die "Invalid Easy Actions vault slot.\n" if !valid_vault_slot($slot);
    validate_config_size($actions);
    my $saved = { version => 1, identity => $identity, actions => $actions };
    $saved->{vaultSlot} = 1 if $slot;
    my $raw = $json->encode($saved);
    my $fh = File::Temp->new(TEMPLATE => '.config-XXXXXX', DIR => $directory, UNLINK => 1);
    binmode($fh, ':raw') or die "Unable to set Easy Actions config mode: $!\n";
    print {$fh} $raw or die "Unable to write Easy Actions config: $!\n";
    $fh->flush && $fh->sync or die "Unable to sync Easy Actions config: $!\n";
    close($fh) or die "Unable to close Easy Actions config: $!\n";
    return ($fh, { revision => sha256_hex($identity . "\n" . $raw), actions => $actions });
}

sub publish_config {
    my ($temporary, $path) = @_;
    rename($temporary->filename, $path) or die "Unable to save Easy Actions config: $!\n";
}

sub write_config {
    my ($directory, $path, $identity, $actions, $slot) = @_;
    my ($temporary, $config) = prepare_config($directory, $identity, $actions, $slot);
    publish_config($temporary, $path);
    return $config;
}

1;
