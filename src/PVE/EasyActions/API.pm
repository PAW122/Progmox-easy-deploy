# SPDX-License-Identifier: AGPL-3.0-or-later
package PVE::EasyActions::API;

use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use Encode qw(encode_utf8);
use HTTP::Status qw(HTTP_CONFLICT HTTP_NOT_FOUND);

use PVE::Cluster;
use PVE::EasyActions::Config;
use PVE::EasyActions::Runner;
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::LXC::Config;
use PVE::QemuConfig;
use PVE::RPCEnvironment;
use base qw(PVE::RESTHandler);

use constant STATE_DIRECTORY => '/var/lib/proxmox-easy-actions';

my %guest_params = (
    node => get_standard_option('pve-node'),
    vmid => get_standard_option('pve-vmid'),
    type => { type => 'string', enum => ['qemu', 'lxc'], description => 'Guest type.' },
);
my $revision = {
    type => 'string',
    pattern => '[0-9a-f]{64}',
    minLength => 64,
    maxLength => 64,
    description => 'Revision returned by the last configuration read.',
};
my $config_response = {
    type => 'object',
    properties => {
        revision => $revision,
        actions => { type => 'array', items => { type => 'object' } },
        previousActions => { type => 'array', items => { type => 'object' }, optional => 1 },
    },
};

sub admin_environment {
    my $rpcenv = PVE::RPCEnvironment::get();
    raise_perm_exc('root@pam is required') if ($rpcenv->get_user() // '') ne 'root@pam';
    return $rpcenv;
}

sub guest_identity {
    my ($type, $config, $file) = @_;
    if ($type eq 'qemu') {
        my ($uuid) = ($config->{smbios1} // '') =~ /(?:\A|,)uuid=([0-9a-f-]{36})(?:,|\z)/i;
        $uuid //= $config->{vmgenid} // '';
        if ($uuid =~ /\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/i) {
            my ($created) = ($config->{meta} // '') =~ /(?:\A|,)ctime=(\d+)(?:,|\z)/;
            return sha256_hex(join("\n", $type, lc($uuid), $created // ''));
        }
    } else {
        my ($volume) = split(/,/, $config->{rootfs} // '');
        if (defined($volume)) {
            $volume =~ s/\Avolume=//;
            my @macs;
            for my $key (grep { /\Anet\d+\z/ } keys(%$config)) {
                my ($mac) = $config->{$key} =~ /(?:\A|,)hwaddr=((?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?:,|\z)/i;
                push @macs, lc($mac) if defined($mac);
            }
            return sha256_hex(encode_utf8(join("\n", $type, $volume, sort(@macs)))) if @macs;
        }
    }

    # A guest without durable identity data requires re-confirmation after a native
    # config change. Include the modification time to detect ordinary ID reuse.
    my @stat = stat($file);
    die "Guest configuration changed while being read. Try again.\n" if !@stat;
    die "Unable to determine the guest configuration digest.\n" if !defined($config->{digest});
    return sha256_hex(join("\n", $type, $config->{digest}, $stat[9]));
}

sub guest_context {
    my ($params, $for_run) = @_;
    my ($node, $type, $vmid) = @{$params}{qw(node type vmid)};
    my $local_node = PVE::INotify::nodename();
    raise("Guest $vmid is not on this node.\n", code => HTTP_NOT_FOUND)
        if $node ne $local_node;

    my $class = $type eq 'qemu' ? 'PVE::QemuConfig' : 'PVE::LXC::Config';
    my $file = $class->config_file($vmid, $local_node);
    PVE::Cluster::cfs_update(1);
    raise("Guest $vmid is no longer on this node.\n", code => HTTP_NOT_FOUND) if !-f $file;
    my $config = $class->load_config($vmid, $local_node);
    if ($for_run) {
        raise("Actions require a running guest. This guest is a template.\n", code => HTTP_CONFLICT)
            if $config->{template};
        raise("Guest $vmid is locked by another Proxmox operation.\n", code => HTTP_CONFLICT)
            if $config->{lock};
    }
    return (guest_identity($type, $config, $file), $config);
}

sub config_path {
    my ($params) = @_;
    return STATE_DIRECTORY . "/$params->{type}-$params->{vmid}.json";
}

sub verify_revision {
    my ($config, $supplied) = @_;
    raise("The action configuration changed. Reload it and try again.\n", code => HTTP_CONFLICT)
        if $config->{revision} ne $supplied;
}

__PACKAGE__->register_method({
    name => 'get_actions',
    path => '{type}/{vmid}',
    method => 'GET',
    description => 'Read the action configuration for a guest on this node.',
    protected => 1,
    proxyto => 'node',
    allowtoken => 0,
    permissions => { description => 'Restricted to root@pam.' },
    parameters => { additionalProperties => 0, properties => { %guest_params } },
    returns => $config_response,
    code => sub {
        my ($params) = @_;
        admin_environment();
        my ($identity) = guest_context($params);
        PVE::EasyActions::Config::ensure_directory(STATE_DIRECTORY);
        return PVE::EasyActions::Config::read_config(config_path($params), $identity);
    },
});

__PACKAGE__->register_method({
    name => 'save_actions',
    path => '{type}/{vmid}',
    method => 'PUT',
    description => 'Replace all actions for a guest on this node.',
    protected => 1,
    proxyto => 'node',
    allowtoken => 0,
    permissions => { description => 'Restricted to root@pam.' },
    parameters => {
        additionalProperties => 0,
        properties => {
            %guest_params,
            revision => $revision,
            actions => {
                type => 'string',
                maxLength => PVE::EasyActions::Config::MAX_CONFIG_BYTES(),
                description => 'JSON-encoded array of actions.',
            },
        },
    },
    returns => $config_response,
    code => sub {
        my ($params) = @_;
        admin_environment();
        my $actions = eval { PVE::EasyActions::Config::decode_actions($params->{actions}) };
        raise_param_exc({ actions => $@ }) if $@;
        PVE::EasyActions::Config::ensure_directory(STATE_DIRECTORY);
        my $path = config_path($params);
        my $lock = PVE::EasyActions::Config::try_lock("$path.save.lock");
        raise("Another administrator is saving actions for this guest. Try again.\n", code => HTTP_CONFLICT)
            if !$lock;
        my ($identity) = guest_context($params);
        my $current = PVE::EasyActions::Config::read_config($path, $identity);
        verify_revision($current, $params->{revision});
        return PVE::EasyActions::Config::write_config(STATE_DIRECTORY, $path, $identity, $actions);
    },
});

__PACKAGE__->register_method({
    name => 'run_action',
    path => '{type}/{vmid}/run',
    method => 'POST',
    description => 'Start a previously saved action as a Proxmox task.',
    protected => 1,
    proxyto => 'node',
    allowtoken => 0,
    permissions => { description => 'Restricted to root@pam.' },
    parameters => {
        additionalProperties => 0,
        properties => {
            %guest_params,
            revision => $revision,
            name => { type => 'string', minLength => 1, maxLength => 64, description => 'Action name.' },
        },
    },
    returns => { type => 'string', description => 'Proxmox task UPID.' },
    code => sub {
        my ($params) = @_;
        my $rpcenv = admin_environment();
        my ($identity) = guest_context($params, 1);
        PVE::EasyActions::Config::ensure_directory(STATE_DIRECTORY);
        my $path = config_path($params);
        my $config = PVE::EasyActions::Config::read_config($path, $identity);
        verify_revision($config, $params->{revision});
        my ($action) = grep { $_->{name} eq $params->{name} } @{ $config->{actions} };
        raise("The action is not configured for this guest.\n", code => HTTP_NOT_FOUND) if !$action;

        # Holding an open descriptor across fork transfers the local run lock to
        # the worker. Releasing the parent's copy does not unlock the worker.
        my $lock = PVE::EasyActions::Config::try_lock("$path.run.lock");
        raise("An action is already running for this guest.\n", code => HTTP_CONFLICT) if !$lock;
        my $worker = sub {
            my $verify_guest = sub {
                my ($current_identity, $guest_config) = guest_context($params, 1);
                die "The guest identity changed. Review its action configuration.\n"
                    if $current_identity ne $identity;
                return $guest_config;
            };
            PVE::EasyActions::Runner::run_action($params->{type}, $params->{vmid}, $action, $verify_guest);
            close($lock);
        };
        return $rpcenv->fork_worker('easyactions', $params->{vmid}, $rpcenv->get_user(), $worker);
    },
});

1;
