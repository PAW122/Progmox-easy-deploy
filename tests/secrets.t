# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;
use utf8;

use File::Temp qw(tempdir);
use POSIX ();
use Test::More;

use PVE::EasyActions::Secrets;

plan skip_all => 'Vault tests require Linux filesystem semantics.' if $^O ne 'linux';

sub read_raw {
    my ($path) = @_;
    open(my $fh, '<:raw', $path) or die "Unable to read test file: $!\n";
    local $/;
    return <$fh>;
}

sub write_raw {
    my ($path, $value) = @_;
    open(my $fh, '>:raw', $path) or die "Unable to open test file: $!\n";
    print {$fh} $value or die "Unable to write test file: $!\n";
    close($fh) or die "Unable to close test file: $!\n";
    chmod(0600, $path) or die "Unable to set test file permissions: $!\n";
}

my $temp = tempdir(CLEANUP => 1);
my $directory = "$temp/vaults";
my $key_directory = "$temp/keys";
my $key_path = "$key_directory/master.key";
mkdir($directory, 0700) or die "Unable to create test vault directory: $!\n";
my $path = "$directory/qemu-200.json.secrets";
my $other_path = "$directory/qemu-201.json.secrets";
my $identity = 'a' x 64;
my $other_identity = 'b' x 64;
my $label = 'ExampleSecretName';
my $value = "zażółć 😀\n'\"&<>\\\r\n\tExampleValue";
my $secrets = { $label => { value => $value, updatedAt => 1750000000 } };

subtest 'Empty vaults do not need a key' => sub {
    my $state = PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory);
    is_deeply($state->{secrets}, {}, 'an absent vault is empty');
    like($state->{revision}, qr/\A[0-9a-f]{64}\z/, 'revision has the API format');
    is_deeply(PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory), $state,
        'revision remains stable');
    isnt(PVE::EasyActions::Secrets::read_vault($path, $other_identity, $key_directory)->{revision},
        $state->{revision}, 'empty revisions bind guest identity');
    isnt(PVE::EasyActions::Secrets::read_vault($other_path, $identity, $key_directory)->{revision},
        $state->{revision}, 'empty revisions bind guest filename');
    ok(!-e $key_directory, 'reading an absent vault does not create key files');
};

subtest 'Concurrent first writes share one persisted key' => sub {
    pipe(my $start, my $release) or die "Unable to create test pipe: $!\n";
    my @workers;
    for my $guest_path ($path, $other_path) {
        my $pid = fork();
        die "Unable to fork test worker: $!\n" if !defined($pid);
        if (!$pid) {
            close($release);
            my $written = eval {
                my $read = sysread($start, my $signal, 1);
                die "Unable to start test worker.\n" if !$read;
                PVE::EasyActions::Secrets::write_vault($guest_path, $identity, $key_directory, $secrets);
            };
            warn $@ if !$written;
            POSIX::_exit($written ? 0 : 1);
        }
        push @workers, $pid;
    }
    close($start);
    print {$release} 'go' or die "Unable to release test workers: $!\n";
    close($release);
    for my $pid (@workers) {
        waitpid($pid, 0);
        is($?, 0, 'concurrent write succeeds');
    }

    is((stat($key_directory))[2] & 07777, 0700, 'key directory permissions are private');
    is((stat($key_path))[2] & 07777, 0600, 'key file permissions are private');
    is(length(read_raw($key_path)), 32, 'master key contains 32 bytes');
    for my $guest_path ($path, $other_path) {
        is((stat($guest_path))[2] & 07777, 0600, 'vault file permissions are private');
        is_deeply(PVE::EasyActions::Secrets::read_vault($guest_path, $identity, $key_directory)->{secrets},
            $secrets, 'persisted key can read the exact multiline Unicode value');
    }
};

subtest 'Encrypted bytes bind the vault to its guest' => sub {
    my $previous = PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory);
    my $previous_raw = read_raw($path);
    unlike($previous_raw, qr/ExampleSecretName|ExampleValue/, 'secret name and value are encrypted');
    my $current = PVE::EasyActions::Secrets::write_vault($path, $identity, $key_directory, $secrets);
    my $raw = read_raw($path);
    my $nonce_offset = length(PVE::EasyActions::Secrets::VAULT_MAGIC()) + 64;
    isnt(substr($raw, $nonce_offset, 12), substr($previous_raw, $nonce_offset, 12), 'each save uses a fresh nonce');
    isnt($current->{revision}, $previous->{revision}, 'an identical save has a fresh revision');
    is_deeply(PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory), $current,
        'the read and write revisions agree');

    my $replacement = PVE::EasyActions::Secrets::read_vault($path, $other_identity, $key_directory);
    is_deeply($replacement->{secrets}, {}, 'a guest replacement cannot read old values');
    isnt($replacement->{revision}, $current->{revision}, 'replacement receives its own revision');

    my $forged_identity = $raw;
    substr($forged_identity, length(PVE::EasyActions::Secrets::VAULT_MAGIC()), 64, $other_identity);
    write_raw($path, $forged_identity);
    eval { PVE::EasyActions::Secrets::read_vault($path, $other_identity, $key_directory) };
    like($@, qr/authenticate/, 'changing the recorded guest identity fails authentication');

    my $tampered = $raw;
    substr($tampered, $nonce_offset + 12, 1) ^= "\x01";
    write_raw($path, $tampered);
    eval { PVE::EasyActions::Secrets::read_vault($path, $other_identity, $key_directory) };
    like($@, qr/authenticate/, 'a replacement does not silently accept a bad authentication tag');
    write_raw($path, $raw);

    my $other_raw = read_raw($other_path);
    write_raw($other_path, $raw);
    eval { PVE::EasyActions::Secrets::read_vault($other_path, $identity, $key_directory) };
    like($@, qr/authenticate/, 'another guest filename cannot read the ciphertext even with the same identity');
    write_raw($other_path, $other_raw);
};

subtest 'Key loss and unsafe storage fail closed' => sub {
    rename($key_path, "$key_path.backup") or die "Unable to move test key: $!\n";
    eval { PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory) };
    like($@, qr/master key is missing/, 'saved vault cannot be read without its key');
    eval { PVE::EasyActions::Secrets::write_vault($path, $identity, $key_directory, $secrets) };
    like($@, qr/master key is missing/, 'an existing vault cannot be overwritten without its key');
    eval { PVE::EasyActions::Secrets::write_vault("$directory/lxc-202.json.secrets", $identity, $key_directory, $secrets) };
    like($@, qr/master key is missing/, 'a new guest cannot regenerate the key when existing vaults need it');
    ok(!-e $key_path, 'no replacement key was generated');
    symlink("$key_path.backup", $key_path) or die "Unable to create test symlink: $!\n";
    eval { PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory) };
    like($@, qr/open Easy Actions master key/, 'symlinked key files are rejected');
    unlink($key_path) or die "Unable to remove test symlink: $!\n";
    rename("$key_path.backup", $key_path) or die "Unable to restore test key: $!\n";

    chmod(0644, $key_path) or die "Unable to change test key permissions: $!\n";
    eval { PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory) };
    like($@, qr/master key must be a regular 0600 file/, 'keys with broader permissions are rejected');
    chmod(0600, $key_path) or die "Unable to restore test key permissions: $!\n";

    chmod(0644, $path) or die "Unable to change test vault permissions: $!\n";
    eval { PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory) };
    like($@, qr/vault must be a regular 0600 file/, 'vaults with broader permissions are rejected');
    chmod(0600, $path) or die "Unable to restore test vault permissions: $!\n";
    is_deeply(PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory)->{secrets}, $secrets,
        'restoring the original key and permissions recovers access');
};

subtest 'Failed vault saves preserve revisions and the master key' => sub {
    my $separate_key_directory = "$temp/separate-keys";
    my $separate_vault_directory = "$temp/separate-vaults";
    my $separate_path = "$separate_vault_directory/lxc-300.json.secrets";
    mkdir($separate_vault_directory, 0700) or die "Unable to create test vault directory: $!\n";
    my $write_temporary_file = \&PVE::EasyActions::Secrets::write_temporary_file;
    my $fail_save = sub {
        no warnings 'redefine';
        local *PVE::EasyActions::Secrets::write_temporary_file = sub {
            die "Simulated encrypted vault write failure.\n" if $_[1] eq 'secret vault';
            return $write_temporary_file->(@_);
        };
        eval { PVE::EasyActions::Secrets::write_vault($separate_path, $identity, $separate_key_directory, $secrets) };
        like($@, qr/Simulated encrypted vault write failure/, 'interrupted save reports failure');
    };

    $fail_save->();
    ok(!-e $separate_path, 'failed first save does not publish an incomplete vault');
    my $key = read_raw("$separate_key_directory/master.key");
    my $state = PVE::EasyActions::Secrets::write_vault($separate_path, $identity, $separate_key_directory, $secrets);
    is(read_raw("$separate_key_directory/master.key"), $key, 'retry reuses the original key');
    $fail_save->();
    is_deeply(PVE::EasyActions::Secrets::read_vault($separate_path, $identity, $separate_key_directory), $state,
        'failed update leaves the previous vault and revision available');
    is(read_raw("$separate_key_directory/master.key"), $key, 'updating a secret preserves the node key');
};

subtest 'Value constraints are measured in UTF-8 bytes' => sub {
    ok(PVE::EasyActions::Secrets::valid_secret_name('Name_-123'), 'permitted name characters are accepted');
    ok(!PVE::EasyActions::Secrets::valid_secret_name('_Name'), 'initial name character must be a letter');
    ok(!PVE::EasyActions::Secrets::valid_secret_value(''), 'empty values are rejected');
    ok(PVE::EasyActions::Secrets::valid_secret_value(" \n\t"), 'whitespace in a nonempty value is preserved');
    ok(PVE::EasyActions::Secrets::valid_secret_value('ą' x 16384), 'the exact UTF-8 byte limit is accepted');
    ok(!PVE::EasyActions::Secrets::valid_secret_value('ą' x 16385), 'oversized UTF-8 values are rejected');
    ok(!PVE::EasyActions::Secrets::valid_secret_value("before\0after"), 'NUL bytes are rejected');

    my $maximum = { map { ("Name$_" => { value => "\x01" x 32768, updatedAt => 1750000000 }) } (1 .. 24) };
    PVE::EasyActions::Secrets::write_vault($path, $identity, $key_directory, $maximum);
    my $state = PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory);
    is_deeply($state->{secrets}, $maximum, 'a full vault can store maximum-length values that require JSON escaping');
    eval { PVE::EasyActions::Secrets::write_vault($path, $identity, $key_directory, { %$maximum, %$secrets }) };
    like($@, qr/Invalid Easy Actions secrets/, 'too many values are rejected before writing');
    is_deeply(PVE::EasyActions::Secrets::read_vault($path, $identity, $key_directory), $state,
        'an invalid write leaves the previous vault intact');
};

done_testing;
