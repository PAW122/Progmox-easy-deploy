# SPDX-License-Identifier: AGPL-3.0-or-later
package PVE::EasyActions::Copy;

use strict;
use warnings;
use feature 'fc';

use JSON::PP ();

use PVE::EasyActions::Secrets ();

use constant MAX_TRANSFER_BYTES => 2 * 1024 * 1024;

sub available_name {
    my ($name, $used, $maximum, $suffix, $key) = @_;
    my $number = 2;
    while (1) {
        my $ending = $suffix->($number++);
        my $prefix = substr($name, 0, $maximum - length($ending));
        $prefix =~ s/\s+\z//;
        my $candidate = $prefix . $ending;
        return $candidate if !$used->{ $key->($candidate) }++;
    }
}

sub append {
    my ($actions, $secrets, $incoming_actions, $incoming_secrets) = @_;
    my %action_names = map { fc($_->{name}) => 1 } (@$actions, @$incoming_actions);
    my %existing_actions = map { fc($_->{name}) => 1 } @$actions;
    my %existing_secret_names = map { $_ => 1 } keys %$secrets;
    for my $action (@$actions) {
        $existing_secret_names{$_->{name}} = 1 for @{ $action->{secrets} // [] };
    }
    my %secret_names = (%existing_secret_names, map { $_ => 1 } keys %$incoming_secrets);
    for my $action (@$incoming_actions) {
        $secret_names{$_->{name}} = 1 for @{ $action->{secrets} // [] };
    }
    my %bindings;

    my %combined_secrets = %$secrets;
    for my $name (sort keys %$incoming_secrets) {
        my $destination = $existing_secret_names{$name}
            ? available_name($name, \%secret_names, 48, sub { "_$_[0]" }, sub { $_[0] })
            : $name;
        $bindings{$name} = $destination;
        $combined_secrets{$destination} = $incoming_secrets->{$name};
    }

    my @combined_actions = @$actions;
    for my $action (@$incoming_actions) {
        my %copy = %$action;
        if ($existing_actions{fc($action->{name})}) {
            $copy{name} = available_name(
                $action->{name}, \%action_names, 64, sub { " ($_[0])" }, sub { fc($_[0]) },
            );
        }
        if ($action->{secrets}) {
            $copy{secrets} = [map { { %$_, name => $bindings{$_->{name}} // $_->{name} } } @{ $action->{secrets} }];
        }
        push @combined_actions, \%copy;
    }

    return (\@combined_actions, \%combined_secrets);
}

sub send_to_node {
    my ($node, $request) = @_;
    require PVE::SSHInfo;
    require PVE::Tools;

    # PVE's cluster SSH setup supplies the trusted per-node host key. Keep the
    # transfer payload on stdin so it stays out of process arguments and logs.
    my ($safe_node) = $node =~ /\A([A-Za-z0-9][A-Za-z0-9-]*)\z/;
    die "Invalid destination node.\n" if !defined($safe_node);
    my $info = PVE::SSHInfo::get_ssh_info($safe_node);
    my ($ip) = ($info->{ip} // '') =~ /\A([0-9a-fA-F:.]+)\z/;
    die "Invalid destination node IP.\n" if !defined($ip);
    $info->{ip} = $ip;
    my $ssh = PVE::SSHInfo::ssh_info_to_command(
        $info, '-T', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
    );
    my $input = JSON::PP::encode_json({
        %$request,
        secrets => PVE::EasyActions::Secrets::encode_secrets($request->{secrets}),
    });
    die "Easy Actions copy exceeds the transfer size limit.\n" if length($input) > MAX_TRANSFER_BYTES;

    my $output = '';
    local $ENV{PATH} = '/usr/sbin:/usr/bin:/sbin:/bin';
    local @ENV{qw(IFS CDPATH ENV BASH_ENV)};
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
    local $SIG{PIPE} = sub { }; # The receiver may disconnect while SSH is reading stdin.
    PVE::Tools::run_command(
        [@$ssh, '/usr/lib/proxmox-easy-actions/receive-copy'],
        input => $input,
        timeout => 20,
        errfunc => sub { },
        outfunc => sub {
            $output .= $_[0];
            die "Invalid copy response.\n" if length($output) > 4096;
        },
    );
    my $result = JSON::PP::decode_json($output);
    die "Invalid copy response.\n" if ref($result) ne 'HASH';
    return $result;
}

1;
