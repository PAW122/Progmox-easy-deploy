#!/usr/bin/perl -T
# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir tempfile);
use IPC::Open3 ();
use JSON::PP ();
use Scalar::Util qw(tainted);
use Test::More;

BEGIN {
    package JSON;
    $INC{'JSON.pm'} = __FILE__;
    sub true { return JSON::PP::true(); }

    package PVE::QemuServer::Monitor;
    $INC{'PVE/QemuServer/Monitor.pm'} = __FILE__;
    sub import {}
}

use PVE::EasyActions::Config;
use PVE::EasyActions::Runner;

ok(${^TAINT}, 'taint mode is active as in pvedaemon');
$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

my $directory = tempdir(CLEANUP => 1);
my $path = "$directory/lxc-100.json";
my $identity = 'a' x 64;
my $command = 'printf fixture-script';
PVE::EasyActions::Config::write_config($directory, $path, $identity, [
    { name => 'Deploy', steps => [{ name => 'Run', command => $command, timeout => 19 }] },
]);
my $action = PVE::EasyActions::Config::read_config($path, $identity)->{actions}[0];
ok(tainted($action->{steps}[0]{timeout}), 'validated timeout from persisted JSON remains tainted');
ok(tainted($action->{steps}[0]{command}), 'validated script from persisted JSON remains tainted');

my ($parameters) = tempfile(UNLINK => 1);
print {$parameters} "100\nfixture-credential\n" or die "Write input fixture: $!";
seek($parameters, 0, 0) or die "Read input fixture: $!";
chomp(my $vmid = <$parameters>);
chomp(my $secret = <$parameters>);
my $bindings = [{ name => 'fixture', env => 'DEPLOY_TOKEN', mode => 'env', value => $secret }];
ok(tainted($vmid) && tainted($secret), 'guest ID and secret inputs are tainted');

# Replace pct with an unprivileged process and retain every production argument
# in the real Open3 exec. The fixture reports a digest of its stdin only.
my $pct_fixture = <<'PERL';
use Digest::SHA qw(sha256_hex);
binmode(STDIN);
local $/;
print 'fixture stdin SHA-256 ', sha256_hex(<STDIN>), "\n";
PERL
my @pct_args;
{
    no warnings 'redefine';
    local *PVE::EasyActions::Runner::open3 = sub {
        @pct_args = @_[3 .. $#_];
        return IPC::Open3::open3($_[0], $_[1], $_[2], '/usr/bin/perl', '-e', $pct_fixture, '--', @pct_args);
    };

    my ($log) = tempfile(UNLINK => 1);
    my $previous = select($log);
    eval { PVE::EasyActions::Runner::run_action('lxc', $vmid, $action, sub { return {} }, $bindings); };
    my $error = $@;
    select($previous);
    is($error, '', 'LXC launch uses IPC::Open3 under -T');

    seek($log, 0, 0) or die "Read task log: $!";
    my $output = do { local $/; <$log> };
    my $digest = sha256_hex(join("\0", 'PEA1', $command, 1, 'DEPLOY_TOKEN', 'env', $secret, 'END', ''));
    like($output, qr/fixture stdin SHA-256 $digest/, 'script and secret remain in the stdin payload');
    like($output, qr/Action PASS/, 'the native action reaches completion');
    is_deeply([@pct_args[0 .. 5]], ['/usr/sbin/pct', 'exec', '100', '--keep-env', '0', '--'],
        'exec arguments retain the canonical VMID and environment isolation');
    ok((grep { $_ eq '19' } @pct_args), 'exec arguments contain the saved timeout');
    ok(!(grep { tainted($_) } @pct_args), 'all exec arguments are untainted');
    ok(!(grep { index($_, $command) >= 0 || index($_, $secret) >= 0 } @pct_args),
        'exec arguments exclude the script and secret');

    @pct_args = ();
    $previous = select($log);
    eval { PVE::EasyActions::Runner::run_action('lxc', "$vmid\n", $action, sub { return {} }, $bindings); };
    my $invalid_guest_error = $@;
    select($previous);
    like($invalid_guest_error, qr/Invalid Easy Actions guest ID/, 'input with a noncanonical VMID is rejected');
    is_deeply(\@pct_args, [], 'invalid VMID never launches a process');
}

eval { PVE::EasyActions::Runner::guest_command('1801'); };
like($@, qr/Invalid Easy Actions step timeout/, 'out-of-range timeout is rejected');
eval { PVE::EasyActions::Runner::guest_command('1; false'); };
like($@, qr/Invalid Easy Actions step timeout/, 'nondecimal timeout is rejected');

done_testing();
