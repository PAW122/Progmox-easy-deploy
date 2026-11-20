# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;
use utf8;

use File::Temp qw(tempdir tempfile);
use Digest::SHA qw(sha256_hex);
use Encode qw(encode_utf8);
use IPC::Open3 ();
use JSON::PP ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Test::More;

# Run on plain Debian without importing the node's Proxmox services or guest config.
BEGIN {
    package HTTP::Status;
    $INC{'HTTP/Status.pm'} = __FILE__;
    use Exporter 'import';
    our @EXPORT_OK = qw(HTTP_CONFLICT HTTP_NOT_FOUND);
    use constant HTTP_CONFLICT => 409;
    use constant HTTP_NOT_FOUND => 404;

    package JSON;
    $INC{'JSON.pm'} = __FILE__;
    sub true { return JSON::PP::true(); }

    package PVE::Cluster;
    $INC{'PVE/Cluster.pm'} = __FILE__;

    package PVE::INotify;
    $INC{'PVE/INotify.pm'} = __FILE__;

    package PVE::RPCEnvironment;
    $INC{'PVE/RPCEnvironment.pm'} = __FILE__;
    our $user = 'test@pve';
    our @workers;
    sub get { return bless {}, __PACKAGE__; }
    sub get_user { return $user; }
    sub fork_worker { push @workers, $_[4]; return 'UPID:fixture'; }

    package PVE::QemuConfig;
    $INC{'PVE/QemuConfig.pm'} = __FILE__;

    package PVE::LXC::Config;
    $INC{'PVE/LXC/Config.pm'} = __FILE__;

    package PVE::JSONSchema;
    $INC{'PVE/JSONSchema.pm'} = __FILE__;
    use Exporter 'import';
    our @EXPORT_OK = qw(get_standard_option);
    sub get_standard_option { return { type => 'string' }; }

    package PVE::Exception;
    $INC{'PVE/Exception.pm'} = __FILE__;
    use Exporter 'import';
    our @EXPORT_OK = qw(raise raise_param_exc raise_perm_exc);
    sub raise { die $_[0]; }
    sub raise_param_exc { die join("\n", values %{ $_[0] }); }
    sub raise_perm_exc { die "Permission denied: $_[0]\n"; }

    package PVE::RESTHandler;
    $INC{'PVE/RESTHandler.pm'} = __FILE__;
    our @methods;
    sub register_method { push @methods, $_[1]; }

    package PVE::QemuServer::Agent;
    $INC{'PVE/QemuServer/Agent.pm'} = __FILE__;
    use Exporter 'import';
    our @EXPORT_OK = qw(check_agent_error);
    sub check_agent_error { die "$_[1]\n" unless ref($_[0]) eq 'HASH' && !$_[0]{error}; }

    package PVE::QemuServer::Monitor;
    $INC{'PVE/QemuServer/Monitor.pm'} = __FILE__;
    use Exporter 'import';
    our @EXPORT_OK = qw(mon_cmd);
    our $mock;
    sub mon_cmd { return $mock->(@_); }
}

use PVE::EasyActions::API;
use PVE::EasyActions::Config;
use PVE::EasyActions::Runner;

my $directory = tempdir(CLEANUP => 1);
my $path = "$directory/lxc-100.json";

subtest 'Validate and save guest actions' => sub {
    PVE::EasyActions::Config::ensure_directory($directory) if $^O eq 'linux';
    my ($identity, $other_identity) = ('a' x 64, 'b' x 64);
    my $initial = PVE::EasyActions::Config::read_config($path, $identity);
    is_deeply($initial->{actions}, [], 'guest without a saved config has no actions');

    my $actions = PVE::EasyActions::Config::decode_actions(JSON::PP->new->encode([
        { name => 'Wdrożenie', steps => [{ name => 'Test', command => "echo ż\r\ntrue", timeout => 9 }] },
    ]));
    is($actions->[0]{steps}[0]{command}, "echo ż\ntrue", 'normalizes CRLF and preserves Unicode');
    my $saved = PVE::EasyActions::Config::write_config($directory, $path, $identity, $actions);
    is_deeply(PVE::EasyActions::Config::read_config($path, $identity), $saved, 'reads the saved config');

    eval { PVE::EasyActions::API::verify_revision($saved, $initial->{revision}); };
    like($@, qr/configuration changed/, 'rejects a stale revision');
    my $previous = PVE::EasyActions::Config::read_config($path, $other_identity);
    isnt($previous->{revision}, $saved->{revision}, 'replacement guest gets a distinct revision');
    is_deeply($previous->{actions}, [], 'replacement guest cannot run previous actions');
    is_deeply($previous->{previousActions}, $actions, 'previous config remains available for manual review');

    my %vm = (smbios1 => 'uuid=b607e20d-e8a9-4c62-8469-898240dc551e', meta => 'ctime=10');
    is(PVE::EasyActions::API::guest_identity('qemu', \%vm, $path),
        PVE::EasyActions::API::guest_identity('qemu', { %vm, name => 'renamed' }, $path),
        'renaming a VM preserves its identity');
    my %ct = (rootfs => 'local-lvm:container-volume,size=4G', net0 => 'name=eth0,hwaddr=12:34:56:78:90:12');
    isnt(PVE::EasyActions::API::guest_identity('lxc', \%ct, $path),
        PVE::EasyActions::API::guest_identity('lxc', { %ct, net0 => 'name=eth0,hwaddr=12:34:56:78:90:AB' }, $path),
        'a changed LXC network identity prevents automatic reuse');

    eval { PVE::EasyActions::Config::decode_actions('[{"name":"Config","steps":[]}]'); };
    like($@, qr/reserved/, 'rejects reserved name');
    eval { PVE::EasyActions::Config::decode_actions('[{"name":"A","steps":[{"name":"B","command":"true","timeout":1801}]}]'); };
    like($@, qr/1800/, 'rejects excessive timeout');
    eval { PVE::EasyActions::Config::decode_actions(' ' x (96 * 1024 + 1)); };
    like($@, qr/exceeds 96 KiB/, 'rejects an oversized payload');

    my $lock = PVE::EasyActions::Config::try_lock("$path.lock");
    ok($lock, 'acquires lock');
    ok(!PVE::EasyActions::Config::try_lock("$path.lock"), 'rejects a concurrent lock');
    close($lock);
    ok(PVE::EasyActions::Config::try_lock("$path.lock"), 'allows a retry after release');
};

subtest 'Require root PAM on all endpoints' => sub {
    is_deeply([map { "$_->{method} $_->{path}" } @PVE::RESTHandler::methods],
        [
            'GET {type}/{vmid}', 'PUT {type}/{vmid}', 'GET {type}/{vmid}/secrets',
            'PUT {type}/{vmid}/secrets', 'DELETE {type}/{vmid}/secrets',
            'GET {type}/{vmid}/copy', 'POST {type}/{vmid}/copy', 'POST {type}/{vmid}/copy-action',
            'POST {type}/{vmid}/run',
        ],
        'registers the API routes');
    for my $method (@PVE::RESTHandler::methods) {
        ok($method->{protected} && !$method->{allowtoken}, "$method->{method} requires pvedaemon and a ticket");
        for my $user ('test@pve', 'root@pam!token') {
            local $PVE::RPCEnvironment::user = $user;
            eval { $method->{code}->({}); };
            like($@, qr/Permission denied: root\@pam is required/, "$method->{method} denies $user");
        }
    }
    local $PVE::RPCEnvironment::user = 'root@pam';
    ok(PVE::EasyActions::API::admin_environment(), 'accepts the PAM root account');
};

subtest 'Validate secret bindings and preserve legacy actions' => sub {
    my $action = { name => 'Secrets', steps => [{ name => 'Test', command => 'true', timeout => 10 }] };
    is_deeply(PVE::EasyActions::Config::validate_actions([$action]), [$action],
        'an older action called Secrets stays valid');
    my $binding = { name => 'deploy_key', env => 'DEPLOY_KEY_FILE', mode => 'file' };
    $action->{secrets} = [$binding];
    is_deeply(PVE::EasyActions::Config::validate_actions([$action]), [$action],
        'retains the binding rather than a secret value');
    $action->{secrets} = [$binding, { %$binding, name => 'other_key' }];
    eval { PVE::EasyActions::Config::validate_actions([$action]); };
    like($@, qr/same environment variable/, 'rejects ambiguous bindings');
    $action->{secrets} = [{ %$binding, env => 'BASH_ENV' }];
    eval { PVE::EasyActions::Config::validate_actions([$action]); };
    like($@, qr/reserved secret environment variable/, 'protects shell control variables');
};

subtest 'Validate and persist optional action groups' => sub {
    my $fixture = tempdir(CLEANUP => 1);
    my $config_path = "$fixture/lxc-123.json";
    my $identity = 'a' x 64;
    my $group = "Wdro\x{17c}enia";
    my $action = { name => 'Build', steps => [{ name => 'Test', command => 'true', timeout => 10 }] };
    my $actions = [$action, { %$action, name => 'Deploy', group => $group }, { %$action, name => 'Check', group => $group }];
    my $decoded = PVE::EasyActions::Config::decode_actions(JSON::PP->new->encode($actions));
    is_deeply($decoded, $actions, 'keeps optional Unicode group names shared by distinct actions');
    my $saved = PVE::EasyActions::Config::write_config($fixture, $config_path, $identity, $decoded);
    is_deeply(PVE::EasyActions::Config::read_config($config_path, $identity), $saved, 'saved groups roundtrip');
    my $maximum = "\x{17c}" x 64;
    is(PVE::EasyActions::Config::validate_actions([{ %$action, group => $maximum }])->[0]{group}, $maximum,
        'the group length limit counts Unicode characters');
    for my $invalid ('', ' padded ', "new\nline", "zero\x{200d}width", 'x' x 65, undef, []) {
        eval { PVE::EasyActions::Config::validate_actions([{ %$action, group => $invalid }]); };
        like($@, qr/valid group name/, 'rejects an invalid explicit group');
    }
};

SKIP: {
    skip 'Vault API integration requires Linux and CryptX', 3
        if $^O ne 'linux' || !eval { require Crypt::AuthEnc::GCM; 1 };

    subtest 'Save, bind and rotate a secret without returning its value' => sub {
        require PVE::EasyActions::Secrets;
        my $fixture = tempdir(CLEANUP => 1);
        my $config_path = "$fixture/lxc-123.json";
        my $key_directory = "$fixture/keys";
        my %endpoints = map { $_->{name} => $_->{code} } @PVE::RESTHandler::methods;
        my %guest = (node => 'fixture', type => 'lxc', vmid => 123);
        my $read = \&PVE::EasyActions::Secrets::read_vault;
        my $write = \&PVE::EasyActions::Secrets::write_vault;
        my @resolved;

        no warnings 'redefine';
        local $PVE::RPCEnvironment::user = 'root@pam';
        local @PVE::RPCEnvironment::workers;
        local *PVE::EasyActions::API::config_path = sub { return $config_path; };
        local *PVE::EasyActions::API::guest_context = sub { return ('a' x 64, {}); };
        local *PVE::EasyActions::Secrets::read_vault = sub {
            return $read->($_[0], $_[1], $key_directory);
        };
        local *PVE::EasyActions::Secrets::write_vault = sub {
            return $write->($_[0], $_[1], $key_directory, $_[3]);
        };
        local *PVE::EasyActions::Runner::run_action = sub { push @resolved, $_[4][0]{value}; };

        my $initial = $endpoints{get_secrets}->({ %guest });
        is_deeply($initial->{secrets}, [], 'empty secret list');
        my $saved = $endpoints{save_secret}->({
            %guest, revision => $initial->{revision}, name => 'deploy_key', value => "fixture-key-v1\n",
        });
        is_deeply($saved, $endpoints{get_secrets}->({ %guest }), 'save and list have the same metadata');
        is_deeply([sort keys %{ $saved->{secrets}[0] }], ['name', 'updatedAt'], 'metadata contains no value');

        my $action = {
            name => 'Deploy',
            group => 'Release',
            steps => [{ name => 'Test', command => 'true', timeout => 10 }],
            secrets => [{ name => 'deploy_key', env => 'DEPLOY_KEY_FILE', mode => 'file' }],
        };
        my $current = $endpoints{get_actions}->({ %guest });
        my $config = $endpoints{save_actions}->({
            %guest, revision => $current->{revision}, actions => JSON::PP->new->encode([$action]),
        });
        is_deeply($config->{actions}, [$action], 'action config preserves its group and the binding');
        eval {
            $endpoints{delete_secret}->({ %guest, revision => $saved->{revision}, name => 'deploy_key' });
        };
        like($@, qr/assigned to an action/, 'protects secrets that still have bindings');
        my %run = (%guest, revision => $config->{revision}, name => 'Deploy');
        is($endpoints{run_action}->({ %run }), 'UPID:fixture', 'starts a task');
        my $rotated = $endpoints{save_secret}->({
            %guest, revision => $saved->{revision}, name => 'deploy_key', value => "fixture-key-v2\n",
        });
        isnt($rotated->{revision}, $saved->{revision}, 'rotation changes the secret revision');
        shift(@PVE::RPCEnvironment::workers)->();
        is_deeply(\@resolved, ["fixture-key-v1\n"], 'running task retains the original value');
        is($endpoints{run_action}->({ %run }), 'UPID:fixture', 'unchanged action config starts again');
        shift(@PVE::RPCEnvironment::workers)->();
        is_deeply(\@resolved, ["fixture-key-v1\n", "fixture-key-v2\n"], 'next task receives the rotated value');
    };

    subtest 'Copy saved container state and preserve secret bindings on append' => sub {
        require PVE::EasyActions::Copy;
        my $fixture = tempdir(CLEANUP => 1);
        my $key_directory = "$fixture/keys";
        my %endpoints = map { $_->{name} => $_->{code} } @PVE::RESTHandler::methods;
        my %source = (node => 'fixture', type => 'lxc', vmid => 123);
        my %target = (%source, vmid => 124);
        my %request = (%source, targetNode => $target{node}, targetVmid => $target{vmid});
        my $read = \&PVE::EasyActions::Secrets::read_vault;
        my $write = \&PVE::EasyActions::Secrets::write_vault;
        my $step = { name => 'Check', command => 'true', timeout => 10 };
        my $binding = { name => 'Token', env => 'DEPLOY_TOKEN', mode => 'env' };
        my $source_action = { name => 'Deploy', group => 'Release', steps => [$step], secrets => [$binding] };
        my $target_action = { %$source_action, name => 'DEPLOY', group => 'Checks' };
        my $source_secrets = {
            Token => { value => "source-value\n", updatedAt => 12 },
            Unbound => { value => 'unbound-value', updatedAt => 13 },
        };
        my $target_secrets = { Token => { value => 'target-value', updatedAt => 14 } };

        no warnings qw(redefine once);
        local $PVE::RPCEnvironment::user = 'root@pam';
        local *PVE::INotify::nodename = sub { return 'fixture'; };
        local *PVE::LXC::Config::lock_config_full = sub { return $_[3]->(); };
        local *PVE::EasyActions::API::config_path = sub { return "$fixture/lxc-$_[0]{vmid}.json"; };
        local *PVE::EasyActions::API::guest_context = sub { return (sha256_hex($_[0]{vmid}), {}); };
        local *PVE::EasyActions::Secrets::read_vault = sub { return $read->($_[0], $_[1], $key_directory); };
        local *PVE::EasyActions::Secrets::write_vault = sub { return $write->($_[0], $_[1], $key_directory, $_[3]); };

        my $source_path = PVE::EasyActions::API::config_path(\%source);
        my $target_path = PVE::EasyActions::API::config_path(\%target);
        my $source_identity = sha256_hex($source{vmid});
        my $target_identity = sha256_hex($target{vmid});
        my $source_config = PVE::EasyActions::Config::write_config(
            $fixture, $source_path, $source_identity, [$source_action, { name => 'Deploy (2)', steps => [$step] }],
        );
        $write->("$source_path.secrets", $source_identity, $key_directory, $source_secrets);

        my $empty = $endpoints{inspect_copy_destination}->(\%target);
        is_deeply([@$empty{qw(occupied actions secrets)}], [0, 0, 0], 'detects an empty container');
        eval { $endpoints{copy_actions}->({ %request, targetVmid => $source{vmid}, mode => 'empty', revision => $empty->{revision} }); };
        like($@, qr/Select a different container/, 'rejects self-copy');
        is_deeply($endpoints{copy_actions}->({ %request, mode => 'empty', revision => $empty->{revision} }),
            { actions => 2, secrets => 2 }, 'copies actions, including unbound secrets, to a fresh target');
        my $copied = $endpoints{get_actions}->(\%target);
        is_deeply($copied->{actions}, $source_config->{actions}, 'initial action order and names are preserved');
        my $saved = $endpoints{save_actions}->({
            %target, revision => $copied->{revision}, actions => JSON::PP::encode_json([$target_action]),
        });
        is_deeply($saved->{actions}, [$target_action], 'editing the copied actions retains the active vault');

        my $metadata = $endpoints{get_secrets}->(\%target);
        $endpoints{delete_secret}->({ %target, revision => $metadata->{revision}, name => 'Unbound' });
        my $preview = $endpoints{inspect_copy_destination}->(\%target);
        is_deeply([@$preview{qw(occupied actions secrets)}], [1, 1, 1], 'reports occupied without returning values');
        $metadata = $endpoints{get_secrets}->(\%target);
        $endpoints{save_secret}->({ %target, revision => $metadata->{revision}, name => 'Token', value => 'target-value' });
        eval { $endpoints{copy_actions}->({ %request, mode => 'overwrite', revision => $preview->{revision} }); };
        like($@, qr/destination configuration changed/, 'secret-only changes invalidate the destination revision');
        $preview = $endpoints{inspect_copy_destination}->(\%target);
        eval { $endpoints{copy_actions}->({ %request, mode => 'empty', revision => $preview->{revision} }); };
        like($@, qr/destination configuration changed/, 'an occupied target requires an explicit mode');
        $endpoints{copy_actions}->({ %request, mode => 'append', revision => $preview->{revision} });
        my $appended = $endpoints{get_actions}->(\%target)->{actions};
        is_deeply([map { $_->{name} } @$appended], ['DEPLOY', 'Deploy (3)', 'Deploy (2)'],
            'appends in source order, avoids case-folded conflicts and preserves incoming names when possible');
        is_deeply([map { $_->{group} } @$appended], ['Checks', 'Release', undef],
            'append preserves groups of existing and copied actions');
        is($appended->[0]{secrets}[0]{name}, 'Token', 'existing action keeps its binding');
        is($appended->[1]{secrets}[0]{name}, 'Token_2', 'copied action references the renamed secret');
        my $config = PVE::EasyActions::Config::read_config($target_path, $target_identity, 1);
        my $vault = PVE::EasyActions::API::read_guest_vault($target_path, $target_identity, $config->{vaultSlot});
        is_deeply({ map { $_ => $vault->{secrets}{$_}{value} } keys %{ $vault->{secrets} } },
            { Token => $target_secrets->{Token}{value}, Token_2 => "source-value\n", Unbound => 'unbound-value' },
            'append retains both secret values and copies the unbound secret');

        $preview = $endpoints{inspect_copy_destination}->(\%target);
        $endpoints{copy_actions}->({ %request, mode => 'overwrite', revision => $preview->{revision} });
        $config = PVE::EasyActions::Config::read_config($target_path, $target_identity, 1);
        is_deeply($config->{actions}, $source_config->{actions}, 'overwrite replaces the complete action list');
        is_deeply(PVE::EasyActions::API::read_guest_vault($target_path, $target_identity, $config->{vaultSlot})->{secrets},
            $source_secrets, 'overwrite replaces the whole live vault');
        is_deeply($endpoints{get_actions}->(\%source), $source_config, 'copy leaves source actions intact');
        is_deeply($read->("$source_path.secrets", $source_identity, $key_directory)->{secrets},
            $source_secrets, 'copy leaves source secrets intact');
    };

    subtest 'Append a single saved action between a VM and a container' => sub {
        require PVE::EasyActions::Secrets;
        my $fixture = tempdir(CLEANUP => 1);
        my $key_directory = "$fixture/keys";
        my %endpoints = map { $_->{name} => $_->{code} } @PVE::RESTHandler::methods;
        my %source = (node => 'fixture', type => 'lxc', vmid => 123);
        my %target = (%source, type => 'qemu', vmid => 124);
        my %types = ($source{vmid} => $source{type}, $target{vmid} => $target{type});
        my $read = \&PVE::EasyActions::Secrets::read_vault;
        my $write = \&PVE::EasyActions::Secrets::write_vault;
        my @locked;

        no warnings qw(redefine once);
        local $PVE::RPCEnvironment::user = 'root@pam';
        local *PVE::INotify::nodename = sub { return 'fixture'; };
        my $lock_config = sub { push @locked, $_[0]; return $_[3]->(); };
        local *PVE::LXC::Config::lock_config_full = $lock_config;
        local *PVE::QemuConfig::lock_config_full = $lock_config;
        local *PVE::EasyActions::API::config_path = sub { return "$fixture/$_[0]{type}-$_[0]{vmid}.json"; };
        local *PVE::EasyActions::API::guest_context = sub {
            my ($guest) = @_;
            die "Guest $guest->{vmid} is no longer on this node.\n"
                if ($types{$guest->{vmid}} // '') ne $guest->{type} || $guest->{node} ne 'fixture';
            return (sha256_hex($guest->{vmid}), {});
        };
        local *PVE::EasyActions::Secrets::read_vault = sub { return $read->($_[0], $_[1], $key_directory); };
        local *PVE::EasyActions::Secrets::write_vault = sub { return $write->($_[0], $_[1], $key_directory, $_[3]); };

        my $step = { name => 'Check', command => 'true', timeout => 10 };
        my $binding = { name => 'Token', env => 'DEPLOY_TOKEN', mode => 'env' };
        my $file_binding = { name => 'Token', env => 'DEPLOY_TOKEN_FILE', mode => 'file' };
        my $source_action = { name => 'Deploy', group => 'Release', steps => [$step], secrets => [$binding, $file_binding] };
        my $other_action = {
            name => 'Check', steps => [$step], secrets => [{ %$binding, name => 'OtherToken' }],
        };
        my $target_action = { %$source_action, name => 'DEPLOY', group => 'Checks', secrets => [$binding] };
        my $source_secrets = {
            Token => { value => "source-value\n", updatedAt => 12 },
            OtherToken => { value => 'other-action-value', updatedAt => 13 },
            Unbound => { value => 'unbound-value', updatedAt => 14 },
        };
        my $target_secrets = { Token => { value => 'target-value', updatedAt => 15 } };
        my $source_path = PVE::EasyActions::API::config_path(\%source);
        my $target_path = PVE::EasyActions::API::config_path(\%target);
        my $source_identity = sha256_hex($source{vmid});
        my $target_identity = sha256_hex($target{vmid});
        my $source_config = PVE::EasyActions::Config::write_config(
            $fixture, $source_path, $source_identity, [$source_action, $other_action],
        );
        PVE::EasyActions::Config::write_config($fixture, $target_path, $target_identity, [$target_action]);
        $write->("$source_path.secrets", $source_identity, $key_directory, $source_secrets);
        $write->("$target_path.secrets", $target_identity, $key_directory, $target_secrets);

        my $preview = $endpoints{inspect_copy_destination}->(\%target);
        is_deeply([@$preview{qw(actions secrets)}], [1, 1], 'the preview reads an occupied VM');
        my %request = (
            %source, name => 'Deploy', sourceRevision => $source_config->{revision},
            targetType => $target{type}, targetNode => $target{node}, targetVmid => $target{vmid},
            revision => $preview->{revision},
        );
        my $copy_action = $endpoints{copy_selected_action};
        eval { $copy_action->({ %request, sourceRevision => '0' x 64 }); };
        like($@, qr/configuration changed/i, 'rejects a stale source revision');
        eval { $copy_action->({ %request, targetVmid => $source{vmid}, targetType => $source{type} }); };
        like($@, qr/Select a different/i, 'rejects copying to the source guest');
        eval { $copy_action->({ %request, targetVmid => 999 }); };
        like($@, qr/no longer on this node/i, 'rejects a missing destination');
        eval { $copy_action->({ %request, revision => '0' x 64 }); };
        like($@, qr/destination configuration changed/i, 'rejects a stale VM destination revision');
        is_deeply($endpoints{inspect_copy_destination}->(\%target), $preview, 'rejections preserve the destination');

        is_deeply($copy_action->({ %request }), { actions => 1, secrets => 1 },
            'copies the selected action and its one distinct bound secret');
        is($locked[-1], 'PVE::QemuConfig', 'copies under the VM configuration lock');
        my $target_config = PVE::EasyActions::Config::read_config($target_path, $target_identity, 1);
        my $copied_action = {
            %$source_action, name => 'Deploy (2)',
            secrets => [map { { %$_, name => 'Token_2' } } @{ $source_action->{secrets} }],
        };
        is_deeply($target_config->{actions}, [$target_action, $copied_action],
            'appends only the selected action, preserving its group and remapping both bindings');
        is_deeply(PVE::EasyActions::API::read_guest_vault($target_path, $target_identity, $target_config->{vaultSlot})->{secrets},
            { %$target_secrets, Token_2 => $source_secrets->{Token} },
            'retains the previous VM secret and excludes unrelated source secrets');
        is_deeply($endpoints{get_actions}->(\%source), $source_config, 'copy leaves the source actions unchanged');
        is_deeply($read->("$source_path.secrets", $source_identity, $key_directory)->{secrets},
            $source_secrets, 'copy leaves the source secrets unchanged');

        $preview = $endpoints{inspect_copy_destination}->(\%source);
        is_deeply($copy_action->({
            %target, name => $copied_action->{name}, sourceRevision => $target_config->{revision},
            targetType => $source{type}, targetNode => $source{node}, targetVmid => $source{vmid},
            revision => $preview->{revision},
        }), { actions => 1, secrets => 1 }, 'also copies a VM action to a container');
        is($locked[-1], 'PVE::LXC::Config', 'copies under the container configuration lock');
        is_deeply($endpoints{get_actions}->(\%source)->{actions}, [$source_action, $other_action, $copied_action],
            'the container keeps its original actions and receives the selected VM action');
    };
}

sub capture_action {
    my ($type, $action, $verify, $secrets) = @_;
    # Keep the real STDOUT descriptor available to IPC::Open3 in the child.
    my ($output) = tempfile();
    my $previous = select($output);
    eval { PVE::EasyActions::Runner::run_action($type, 100, $action, $verify, $secrets); };
    my $error = $@;
    select($previous);
    seek($output, 0, 0) or die "Unable to read task log: $!";
    local $/;
    my $log = <$output>;
    return ($log, $error);
}

subtest 'Fail fast and keep scripts out of host process arguments' => sub {
    my ($exit_first, @requests);
    local $PVE::QemuServer::Monitor::mock = sub {
        my ($vmid, $method, %arguments) = @_;
        return {} if $method eq 'guest-ping';
        if ($method eq 'guest-exec') {
            push @requests, \%arguments;
            return { pid => scalar(@requests) };
        }
        return { exited => 1, exitcode => ($exit_first && $arguments{pid} == 1) ? 17 : 0,
            'out-data' => encode_base64("example guest output\nTASK OK\n", '') };
    };

    my $action = { name => 'Smoke', steps => [
        { name => 'One', timeout => 2, command => 'echo CHECK_SCRIPT_STDIN' },
        { name => 'Two', timeout => 2, command => 'echo SECOND' },
    ] };
    my $checks = 0;
    my $verify = sub { ++$checks; return { agent => 1 }; };
    my ($log, $error) = capture_action('qemu', $action, $verify);
    is($error, '', 'success exits successfully');
    like($log, qr/Action PASS/, 'records an action pass');
    like($log, qr/^\[guest\] TASK OK$/m, 'prefixes guest output to protect native task log status');
    is($checks, 2, 'rechecks guest identity before each step');
    is($requests[0]{path}, '/usr/bin/flock', 'runs a fixed guest executable');
    ok(!(grep { /CHECK_SCRIPT_STDIN/ } @{ $requests[0]{arg} }), 'script is absent from transport arguments');
    is_deeply([split(/\0/, decode_base64($requests[0]{'input-data'}), -1)],
        ['PEA1', $action->{steps}[0]{command}, 0, 'END', ''], 'script is framed on stdin');

    @requests = ();
    $exit_first = 1;
    ($log, $error) = capture_action('qemu', $action, $verify);
    like($error, qr/Step 1 failed with exit code 17/, 'reports a failing step and exit code');
    unlike($log, qr/Action PASS/, 'failure never records a pass');
    is(scalar(@requests), 1, 'skips the remaining steps');
};

subtest 'Snapshot secret inputs and redact exact values from QGA output' => sub {
    my $env_value = 'deploy-token-fixture-78';
    my $file_value = "synthetic key\nwith several lines\n";
    my $secrets = [
        { name => 'token', env => 'DEPLOY_TOKEN', mode => 'env', value => $env_value },
        { name => 'key', env => 'DEPLOY_KEY', mode => 'file', value => $file_value },
    ];
    my @requests;
    local $PVE::QemuServer::Monitor::mock = sub {
        my ($vmid, $method, %arguments) = @_;
        return {} if $method eq 'guest-ping';
        if ($method eq 'guest-exec') {
            push @requests, \%arguments;
            return { pid => scalar(@requests) };
        }
        return { exited => 1, exitcode => 0, 'out-data' => encode_base64("before:$env_value:after\n$file_value", ''),
            'err-data' => encode_base64('log boundary ' . substr($env_value, 0, 13), ''), 'err-truncated' => 1 };
    };
    my $action = { name => 'Snapshot', steps => [
        { name => 'One', timeout => 2, command => 'first script' },
        { name => 'Two', timeout => 2, command => 'second script' },
    ] };
    my $verify = sub { $secrets->[0]{value} = 'rotated elsewhere'; return { agent => 1 }; };
    my ($log, $error) = capture_action('qemu', $action, $verify, $secrets);
    is($error, '', 'runs both steps using the resolved snapshot');
    is(scalar(@requests), 2, 'transport receives both steps');
    for my $i (0 .. $#requests) {
        my $request = $requests[$i];
        is_deeply([split(/\0/, decode_base64($request->{'input-data'}), -1)],
            ['PEA1', $action->{steps}[$i]{command}, 2, 'DEPLOY_TOKEN', 'env', $env_value,
                'DEPLOY_KEY', 'file', $file_value, 'END', ''], 'snapshot values travel only in framed stdin');
        unlike(join(' ', @{ $request->{arg} }), qr/\Q$env_value\E|\Q$file_value\E/, 'no secret value in arguments');
    }
    like($log, qr/before:\[secret redacted\]:after/, 'preserves non-secret stdout');
    unlike($log, qr/deploy-token|synthetic key|with several lines/, 'removes raw values and truncated prefixes');
    like($log, qr/log boundary \[secret redacted\]/, 'redacts a partial value at the stream truncation boundary');
};

subtest 'Reject unsafe secret values and redact overlapping truncation' => sub {
    eval { PVE::EasyActions::Runner::encode_bindings([{ env => 'TOKEN', mode => 'env', value => "bad\0input" }]); };
    like($@, qr/Invalid Easy Actions secret/, 'a value cannot inject framing delimiters');
    eval { PVE::EasyActions::Runner::encode_bindings([{ env => 'TOKEN', mode => 'env', value => 'x' x (32 * 1024 + 1) }]); };
    like($@, qr/exceed the permitted input size/, 'enforces the per-secret byte limit');
    my $redactor = PVE::EasyActions::Runner::build_log_redactor([
        [FIRST => 'env', 'abcdef'], [SECOND => 'file', 'defghi'],
    ]);
    is(PVE::EasyActions::Runner::redact_output('log abcdef', 1, $redactor), 'log [secret redacted]',
        'redacts a whole secret crossing a partially truncated secret');
};

SKIP: {
    skip 'Guest wrapper requires Linux Bash, GNU timeout and util-linux flock', 1
        if $^O ne 'linux' || grep { !-x $_ } qw(/bin/bash /usr/bin/timeout /usr/bin/flock);

    subtest 'Container transport sends stdin and honors the guest timeout' => sub {
        # Execute the guest wrapper locally with harmless fixture scripts and an
        # isolated lock instead of requiring a running container and root.
        no warnings 'redefine';
        local *PVE::EasyActions::Runner::open3 = sub {
            my @guest_command = @_[9 .. $#_];
            for my $argument (@guest_command) {
                $argument = "$directory/guest.lock" if $argument eq '/run/proxmox-easy-actions.lock';
                $argument = $directory if $argument eq '/run';
            }
            return IPC::Open3::open3($_[0], $_[1], $_[2], @guest_command);
        };

        my $action = { name => 'Container', steps => [
            { name => 'Test', timeout => 2, command => 'printf "container command passed\\n"' },
        ] };
        my ($log, $error) = capture_action('lxc', $action, sub { return {}; });
        is($error, '', 'passes the script through both pipes');
        like($log, qr/\[guest\] container command passed/, 'captures actual Bash output');
        like($log, qr/Action PASS/, 'reports the transport exit status');

        $action->{steps}[0] = { name => 'Timeout', timeout => 1, command => 'sleep 10' };
        ($log, $error) = capture_action('lxc', $action, sub { return {}; });
        like($error, qr/Step 1 failed with exit code 124/, 'GNU timeout stops a blocked guest step');
        unlike($log, qr/Action PASS/, 'the timeout is reported as a failure');

        $action->{steps}[0] = { name => 'Forced timeout', timeout => 1, command => q{trap '' TERM; exec sleep 10} };
        ($log, $error) = capture_action('lxc', $action, sub { return {}; });
        like($error, qr/Step 1 failed with exit code 137/, 'timeout kills a command that ignores TERM');

        my $env_value = 'plaintext-deploy-fixture';
        my $file_value = "synthetic SSH key\nłóżko\n\n";
        my $secrets = [
            { name => 'token', env => 'DEPLOY_TOKEN', mode => 'env', value => $env_value },
            { name => 'key', env => 'DEPLOY_KEY', mode => 'file', value => $file_value },
        ];
        local $ENV{DEPLOY_TOKEN} = 'host-sentinel';
        $action->{steps}[0] = { name => 'Private file', timeout => 2, command => <<'BASH' };
test "$(stat -c %a -- "$DEPLOY_KEY")" = 600
test "$(stat -c %a -- "${DEPLOY_KEY%/*}")" = 700
sha256sum < "$DEPLOY_KEY"
printf 'token=%s\n' "$DEPLOY_TOKEN"
cat -- "$DEPLOY_KEY" >&2
BASH
        ($log, $error) = capture_action('lxc', $action, sub { return {}; }, $secrets);
        is($error, '', 'env and file bindings are usable inside a guest step');
        like($log, qr/^\[guest\] \Q@{[sha256_hex(encode_utf8($file_value))]}\E\s+-$/m,
            'guest private file preserves the exact UTF-8 content and trailing newlines');
        like($log, qr/token=\[secret redacted\]/, 'guest env value is injected and redacted from output');
        unlike($log, qr/plaintext-deploy-fixture|synthetic SSH key/, 'known stdout and stderr values are redacted');
        is($ENV{DEPLOY_TOKEN}, 'host-sentinel', 'bindings do not modify the host process environment');
        is_deeply([glob("$directory/proxmox-easy-actions.*")], [], 'removes private files after success');

        $action->{steps}[0]{command} = 'test -f "$DEPLOY_KEY" && exit 23';
        ($log, $error) = capture_action('lxc', $action, sub { return {}; }, $secrets);
        like($error, qr/exit code 23/, 'preserves failure status after exposing the private file');
        is_deeply([glob("$directory/proxmox-easy-actions.*")], [], 'removes private files after failure');

        $action->{steps}[0] = { name => 'Timed out', timeout => 1,
            command => q{test -f "$DEPLOY_KEY"; trap '' TERM; exec sleep 10} };
        ($log, $error) = capture_action('lxc', $action, sub { return {}; }, $secrets);
        like($error, qr/exit code 137/, 'still reports the timeout when the action ignores TERM');
        is_deeply([glob("$directory/proxmox-easy-actions.*")], [], 'removes private files after forced timeout');

        my @wrapped = PVE::EasyActions::Runner::guest_command(2);
        my $encoded = PVE::EasyActions::Runner::encode_bindings($secrets);
        my $payload = PVE::EasyActions::Runner::step_payload('printf UNEXPECTED_SCRIPT_EXECUTION', $encoded);
        for my $invalid (substr($payload, 0, -1), "$payload\0") {
            my $result = PVE::EasyActions::Runner::run_container_step(100, \@wrapped, $invalid, 2);
            is($result, 2, 'incomplete or trailing input is rejected before running a script');
            is_deeply([glob("$directory/proxmox-easy-actions.*")], [], 'invalid input creates no secret files');
        }
    };
}

done_testing();
