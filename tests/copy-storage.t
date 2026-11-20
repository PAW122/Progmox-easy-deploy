# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;

use File::Temp qw(tempdir);
use Test::More;

use PVE::EasyActions::Config ();
use PVE::EasyActions::Secrets ();

plan skip_all => 'Copy storage tests require Linux filesystem semantics.' if $^O ne 'linux';

my $directory = tempdir(CLEANUP => 1);
my $key_directory = "$directory/keys";
my $path = "$directory/lxc-100.json";
my $identity = 'a' x 64;
my $legacy_vault = PVE::EasyActions::Secrets::guest_vault_path($path, 0);
my $alternate_vault = PVE::EasyActions::Secrets::guest_vault_path($path, 1);
my $before_actions = [{ name => 'Build', steps => [{ name => 'Run', command => 'true', timeout => 1 }] }];
my $after_actions = [{
    name => 'Deploy', steps => [{ name => 'Run', command => 'true', timeout => 2 }],
    secrets => [{ name => 'Token', env => 'TOKEN', mode => 'env' }],
}];
my $before_secrets = { OldToken => { value => 'old value', updatedAt => 1750000000 } };
my $after_secrets = { Token => { value => 'new value', updatedAt => 1750000001 } };

sub read_config {
    return PVE::EasyActions::Config::read_config($path, $identity, 1);
}

sub read_active_vault {
    my $active_path = PVE::EasyActions::Secrets::guest_vault_path($path, read_config()->{vaultSlot});
    return PVE::EasyActions::Secrets::read_vault($active_path, $identity, $key_directory);
}

subtest 'Legacy configuration and empty copies' => sub {
    is(read_config()->{vaultSlot}, 0, 'an unconfigured guest uses the legacy slot');
    PVE::EasyActions::Config::write_config($directory, $path, $identity, $before_actions);
    is(read_config()->{vaultSlot}, 0, 'an existing legacy configuration uses the legacy slot');
    my $copied = PVE::EasyActions::Secrets::replace_guest_state($path, $identity, $key_directory, $before_actions, {}, 0);
    is_deeply($copied, PVE::EasyActions::Config::read_config($path, $identity), 'the slot is internal');
    is(read_config()->{vaultSlot}, 1, 'the config selects the staged slot');
    is_deeply(read_active_vault()->{secrets}, {}, 'copied configuration has an empty vault');
    ok(!-e $key_directory, 'copying actions without secrets does not create a key');
    my $slot = read_config()->{vaultSlot};
    PVE::EasyActions::Config::write_config($directory, $path, $identity, $before_actions, $slot);
    is(read_config()->{vaultSlot}, 1, 'a normal action save can retain the active slot');
};

subtest 'Interrupted write publishes neither half' => sub {
    PVE::EasyActions::Secrets::write_vault($alternate_vault, $identity, $key_directory, $before_secrets);
    my $before = read_config();
    my $before_vault = read_active_vault();
    {
        no warnings 'redefine';
        local *PVE::EasyActions::Config::publish_config = sub { die "Simulated config publication failure.\n"; };
        eval {
            PVE::EasyActions::Secrets::replace_guest_state($path, $identity, $key_directory,
                $after_actions, $after_secrets, $before->{vaultSlot});
        };
        like($@, qr/Simulated config publication failure/, 'a failed rename reports failure');
    }
    is_deeply(read_config(), $before, 'active actions and revision stay unchanged');
    is_deeply(read_active_vault(), $before_vault, 'active secret values and revision stay unchanged');

    PVE::EasyActions::Secrets::replace_guest_state($path, $identity, $key_directory,
        $after_actions, $after_secrets, $before->{vaultSlot});
    is_deeply(read_config()->{actions}, $after_actions, 'retry publishes the copied actions');
    is_deeply(read_active_vault()->{secrets}, $after_secrets, 'retry publishes the copied secrets');
    ok(!-e $alternate_vault, 'the retired vault is removed after the commit');
};

subtest 'Failure to sync the config directory keeps both slots available' => sub {
    my $before = read_config();
    my $sync_directory = \&PVE::EasyActions::Secrets::sync_directory;
    {
        no warnings 'redefine';
        local *PVE::EasyActions::Secrets::sync_directory = sub {
            die "Simulated config directory sync failure.\n"
                if $_[0] eq $directory && read_config()->{vaultSlot} != $before->{vaultSlot};
            return $sync_directory->(@_);
        };
        eval {
            PVE::EasyActions::Secrets::replace_guest_state($path, $identity, $key_directory,
                $before_actions, $before_secrets, $before->{vaultSlot});
        };
        like($@, qr/Simulated config directory sync failure/, 'post-rename sync failure reports failure');
    }
    is_deeply(read_config()->{actions}, $before_actions, 'visible config and vault select the same generation');
    is_deeply(read_active_vault()->{secrets}, $before_secrets, 'the new vault is complete');
    ok(-e $legacy_vault && -e $alternate_vault, 'both vaults remain available after a sync failure');
};

subtest 'Alternate vaults prevent master key regeneration' => sub {
    my $other_guest = "$directory/lxc-101.json.secrets";
    my $master_key = "$key_directory/master.key";
    unlink($legacy_vault) or die "Unable to remove the retired test vault: $!\n";
    rename($master_key, "$master_key.backup") or die "Unable to move the test master key: $!\n";
    eval { PVE::EasyActions::Secrets::write_vault($other_guest, $identity, $key_directory, $before_secrets); };
    like($@, qr/master key is missing/, 'an alternate vault blocks key regeneration');
    ok(!-e $master_key && !-e $other_guest, 'a failed save leaves the existing vault and key alone');
};

done_testing;
