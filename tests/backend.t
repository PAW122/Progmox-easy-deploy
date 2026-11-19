# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;
use utf8;

use File::Temp qw(tempdir tempfile);
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
    sub get { return bless {}, __PACKAGE__; }
    sub get_user { return $user; }

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
    sub raise_param_exc { die $_[0]{actions}; }
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
        ['GET {type}/{vmid}', 'PUT {type}/{vmid}', 'POST {type}/{vmid}/run'], 'registers the API routes');
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

sub capture_action {
    my ($type, $action, $verify) = @_;
    # Keep the real STDOUT descriptor available to IPC::Open3 in the child.
    my ($output) = tempfile();
    my $previous = select($output);
    eval { PVE::EasyActions::Runner::run_action($type, 100, $action, $verify); };
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
    is(decode_base64($requests[0]{'input-data'}), $action->{steps}[0]{command}, 'script is sent via stdin');

    @requests = ();
    $exit_first = 1;
    ($log, $error) = capture_action('qemu', $action, $verify);
    like($error, qr/Step 1 failed with exit code 17/, 'reports a failing step and exit code');
    unlike($log, qr/Action PASS/, 'failure never records a pass');
    is(scalar(@requests), 1, 'skips the remaining steps');
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
    };
}

done_testing();
