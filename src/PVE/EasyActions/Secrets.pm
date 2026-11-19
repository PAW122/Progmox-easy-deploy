# SPDX-License-Identifier: AGPL-3.0-or-later
package PVE::EasyActions::Secrets;

use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use Encode qw(decode encode FB_CROAK LEAVE_SRC);
use Errno qw(EEXIST EINTR ENOENT);
use Fcntl qw(O_DIRECTORY O_NOFOLLOW O_NONBLOCK O_RDONLY S_ISDIR S_ISREG);
use File::Basename qw(basename dirname);
use File::Temp ();
use IO::Handle ();
use JSON::PP ();
use MIME::Base64 qw(decode_base64 encode_base64);

use PVE::EasyActions::Config ();

use constant MAX_SECRETS => 24;
use constant MAX_SECRET_BYTES => 32 * 1024;
use constant KEY_BYTES => 32;
use constant NONCE_BYTES => 12;
use constant TAG_BYTES => 16;
use constant IDENTITY_BYTES => 64;
use constant VAULT_MAGIC => "PVE-EasyActions-Vault\x01\n";
use constant HEADER_BYTES => length(VAULT_MAGIC) + IDENTITY_BYTES + NONCE_BYTES + TAG_BYTES;
use constant MAX_ENCODED_VALUE_BYTES => 4 * int((MAX_SECRET_BYTES + 2) / 3);
use constant MAX_VAULT_BYTES => HEADER_BYTES + 2 + MAX_SECRETS * (MAX_ENCODED_VALUE_BYTES + 160);

my $json = JSON::PP->new->canonical->utf8;
my $secret_name = PVE::EasyActions::Config::SECRET_NAME_PATTERN();

sub valid_secret_name {
    my ($name) = @_;
    return defined($name) && !ref($name) && $name =~ /\A$secret_name\z/;
}

sub valid_secret_value {
    my ($value) = @_;
    return 0 if !defined($value) || ref($value) || !length($value)
        || length($value) > MAX_SECRET_BYTES || $value =~ /\x00/;
    my $encoded = eval { encode('UTF-8', $value, FB_CROAK | LEAVE_SRC) };
    return defined($encoded) && length($encoded) <= MAX_SECRET_BYTES;
}

sub validate_secrets {
    my ($secrets) = @_;
    die "Invalid Easy Actions secrets.\n" if ref($secrets) ne 'HASH' || keys(%$secrets) > MAX_SECRETS;
    my %validated;
    for my $name (keys %$secrets) {
        my $record = $secrets->{$name};
        die "Invalid Easy Actions secret.\n" if !valid_secret_name($name) || ref($record) ne 'HASH'
            || keys(%$record) != 2 || !valid_secret_value($record->{value})
            || !defined($record->{updatedAt}) || ref($record->{updatedAt})
            || $record->{updatedAt} !~ /\A[0-9]{1,12}\z/;
        $validated{$name} = { value => "$record->{value}", updatedAt => 0 + $record->{updatedAt} };
    }
    return \%validated;
}

sub encode_secrets {
    my ($secrets) = @_;
    # Base64 bounds the expansion of arbitrary UTF-8 text in the encrypted JSON.
    my %encoded;
    for my $name (keys %$secrets) {
        my $record = $secrets->{$name};
        $encoded{$name} = {
            %$record,
            value => encode_base64(encode('UTF-8', $record->{value}, FB_CROAK | LEAVE_SRC), ''),
        };
    }
    return $json->encode(\%encoded);
}

sub decode_secrets {
    my ($plaintext) = @_;
    my $records = $json->decode($plaintext);
    die "Invalid Easy Actions secrets.\n" if ref($records) ne 'HASH' || keys(%$records) > MAX_SECRETS;
    for my $record (values %$records) {
        die "Invalid Easy Actions secret.\n" if ref($record) ne 'HASH';
        my $value = $record->{value};
        die "Invalid Easy Actions secret encoding.\n"
            if !defined($value) || ref($value) || length($value) > MAX_ENCODED_VALUE_BYTES
            || length($value) % 4 || $value !~ m{\A[A-Za-z0-9+/]+={0,2}\z};
        $record->{value} = decode('UTF-8', decode_base64($value), FB_CROAK | LEAVE_SRC);
    }
    return validate_secrets($records);
}

sub assert_private_directory {
    my ($directory) = @_;
    my @info = lstat($directory);
    die "Easy Actions secret storage requires a private 0700 directory owned by the service.\n"
        if !@info || !S_ISDIR($info[2]) || $info[4] != $> || ($info[2] & 07777) != 0700;
}

sub private_file_info {
    my ($info, $label) = @_;
    die "Easy Actions $label must be a regular 0600 file owned by the service.\n"
        if !@$info || !S_ISREG($info->[2]) || $info->[4] != $> || ($info->[2] & 07777) != 0600;
}

sub read_private_file {
    my ($path, $maximum, $label) = @_;
    my $fh;
    if (!sysopen($fh, $path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) {
        return undef if $! == ENOENT;
        die "Unable to open Easy Actions $label: $!\n";
    }
    my @info = stat($fh);
    private_file_info(\@info, $label);
    die "Easy Actions $label exceeds its storage limit.\n" if $info[7] > $maximum;
    binmode($fh, ':raw') or die "Unable to set Easy Actions $label mode: $!\n";

    my $raw = '';
    while (1) {
        my $read = sysread($fh, my $chunk, 64 * 1024);
        next if !defined($read) && $! == EINTR;
        die "Unable to read Easy Actions $label: $!\n" if !defined($read);
        last if !$read;
        $raw .= $chunk;
        die "Easy Actions $label exceeds its storage limit.\n" if length($raw) > $maximum;
    }
    close($fh) or die "Unable to close Easy Actions $label: $!\n";
    return $raw;
}

sub random_bytes {
    my ($length) = @_;
    # The kernel supplies fresh bytes independently of the Perl worker's fork state.
    open(my $source, '<:raw', '/dev/urandom') or die "Unable to open Easy Actions entropy source: $!\n";
    my $bytes = '';
    while (length($bytes) < $length) {
        my $read = sysread($source, my $chunk, $length - length($bytes));
        next if !defined($read) && $! == EINTR;
        die "Unable to read Easy Actions entropy.\n" if !$read;
        $bytes .= $chunk;
    }
    close($source) or die "Unable to close Easy Actions entropy source: $!\n";
    return $bytes;
}

sub write_temporary_file {
    my ($directory, $label, $raw) = @_;
    my $fh = File::Temp->new(TEMPLATE => '.secrets-XXXXXX', DIR => $directory, UNLINK => 1);
    binmode($fh, ':raw') or die "Unable to set Easy Actions $label mode: $!\n";
    chmod(0600, $fh->filename) or die "Unable to restrict Easy Actions $label permissions: $!\n";
    print {$fh} $raw or die "Unable to write Easy Actions $label: $!\n";
    $fh->flush && $fh->sync or die "Unable to sync Easy Actions $label: $!\n";
    close($fh) or die "Unable to close Easy Actions $label: $!\n";
    return $fh;
}

sub sync_directory {
    my ($directory) = @_;
    sysopen(my $fh, $directory, O_DIRECTORY | O_NOFOLLOW | O_RDONLY)
        or die "Unable to open Easy Actions directory: $!\n";
    $fh->sync or die "Unable to sync Easy Actions directory: $!\n";
    close($fh) or die "Unable to close Easy Actions directory: $!\n";
}

sub master_key {
    my ($key_directory, $vault_directory, $writing, $allow_create) = @_;
    my @key_dir_info = lstat($key_directory);
    if (!@key_dir_info && $! == ENOENT && $allow_create) {
        mkdir($key_directory, 0700) || $! == EEXIST or die "Unable to create Easy Actions key directory: $!\n";
    }
    assert_private_directory($key_directory) if @key_dir_info || $allow_create;
    my $path = "$key_directory/master.key";
    my $key = read_private_file($path, KEY_BYTES, 'master key');
    if (!defined($key) && $allow_create) {
        opendir(my $entries, $vault_directory) or die "Unable to open Easy Actions vault directory: $!\n";
        local $! = 0;
        my $has_vault = grep { /\A(?:lxc|qemu)-[0-9]+\.json\.secrets\z/ } readdir($entries);
        die "Unable to list Easy Actions vaults: $!\n" if $!;
        closedir($entries) or die "Unable to close Easy Actions vault directory: $!\n";
        if (!$has_vault) {
            my $temporary = write_temporary_file($key_directory, 'master key', random_bytes(KEY_BYTES));
            # Publish the complete key without replacing one installed by a concurrent guest save.
            link($temporary->filename, $path) || $! == EEXIST
                or die "Unable to install Easy Actions master key: $!\n";
        }
        $key = read_private_file($path, KEY_BYTES, 'master key');
    }
    die "Easy Actions master key is missing. Restore the original key to access saved secrets.\n"
        if !defined($key);
    die "Easy Actions master key is invalid.\n" if length($key) != KEY_BYTES;
    if ($writing) {
        # A concurrent writer can see the key as soon as link() succeeds.
        # Ensure it is durable before publishing a vault that depends on it.
        sync_directory($key_directory);
        sync_directory(dirname($key_directory));
    }
    return $key;
}

sub vault_context {
    my ($path, $identity) = @_;
    return VAULT_MAGIC . basename($path) . "\x00" . $identity;
}

sub vault_state {
    my ($context, $raw, $secrets) = @_;
    return { revision => sha256_hex($context . "\x00" . $raw), secrets => $secrets };
}

sub read_vault {
    my ($path, $identity, $key_directory) = @_;
    die "Invalid Easy Actions secret vault identity.\n"
        if !defined($identity) || $identity !~ /\A[0-9a-f]{64}\z/;
    my $context = vault_context($path, $identity);
    my $raw = read_private_file($path, MAX_VAULT_BYTES, 'secret vault');
    return vault_state($context, '', {}) if !defined($raw);
    my $directory = dirname($path);
    assert_private_directory($directory);

    die "Saved Easy Actions secret vault is invalid.\n" if length($raw) <= HEADER_BYTES;
    my ($magic, $stored_identity, $nonce, $tag, $ciphertext) = unpack(
        'a' . length(VAULT_MAGIC) . 'a' . IDENTITY_BYTES . 'a' . NONCE_BYTES . 'a' . TAG_BYTES . 'a*', $raw,
    );
    die "Saved Easy Actions secret vault is invalid.\n"
        if $magic ne VAULT_MAGIC || $stored_identity !~ /\A[0-9a-f]{64}\z/;

    require Crypt::AuthEnc::GCM;
    my $key = master_key($key_directory, $directory, 0, 0);
    # The fixed-width header supplies exactly 16 bytes to the one-shot tag verifier.
    my $plaintext = eval {
        Crypt::AuthEnc::GCM::gcm_decrypt_verify(
            'AES', $key, $nonce, vault_context($path, $stored_identity), $ciphertext, $tag,
        );
    };
    die "Unable to authenticate the saved Easy Actions secret vault.\n" if !defined($plaintext);
    return vault_state($context, $raw, {}) if $stored_identity ne $identity;

    my $secrets = eval { decode_secrets($plaintext) };
    die "Saved Easy Actions secret vault is invalid.\n" if !defined($secrets);
    return vault_state($context, $raw, $secrets);
}

sub write_vault {
    my ($path, $identity, $key_directory, $secrets) = @_;
    die "Invalid Easy Actions secret vault identity.\n"
        if !defined($identity) || $identity !~ /\A[0-9a-f]{64}\z/;
    $secrets = validate_secrets($secrets);
    my $directory = dirname($path);
    assert_private_directory($directory);
    my @existing = lstat($path);
    if (@existing) {
        private_file_info(\@existing, 'secret vault');
    } elsif ($! != ENOENT) {
        die "Unable to inspect Easy Actions secret vault: $!\n";
    }

    require Crypt::AuthEnc::GCM;
    my $key = master_key($key_directory, $directory, 1, !@existing);
    my $nonce = random_bytes(NONCE_BYTES);
    my $context = vault_context($path, $identity);
    my ($ciphertext, $tag) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate(
        'AES', $key, $nonce, $context, encode_secrets($secrets),
    );
    my $raw = VAULT_MAGIC . $identity . $nonce . $tag . $ciphertext;
    my $temporary = write_temporary_file($directory, 'secret vault', $raw);
    rename($temporary->filename, $path) or die "Unable to save Easy Actions secret vault: $!\n";
    sync_directory($directory);
    return vault_state($context, $raw, $secrets);
}

1;
