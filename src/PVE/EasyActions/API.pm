# SPDX-License-Identifier: AGPL-3.0-or-later
package PVE::EasyActions::API;

use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use Encode qw(encode_utf8);
use File::Basename qw(dirname);
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
use constant KEY_DIRECTORY => '/etc/proxmox-easy-actions';

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
my %secret_endpoint = (
    path => '{type}/{vmid}/secrets',
    protected => 1,
    proxyto => 'node',
    allowtoken => 0,
    permissions => { description => 'Restricted to root@pam.' },
);
my $secret_response = {
    type => 'object',
    properties => {
        revision => $revision,
        secrets => {
            type => 'array',
            items => {
                type => 'object',
                properties => {
                    name => { type => 'string' },
                    updatedAt => { type => 'integer' },
                },
            },
        },
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
    PVE::EasyActions::Config::ensure_directory(STATE_DIRECTORY);
    return STATE_DIRECTORY . "/$params->{type}-$params->{vmid}.json";
}

sub lock_configuration {
    my ($path) = @_;
    my $lock = PVE::EasyActions::Config::try_lock("$path.save.lock");
    raise("This guest's Actions configuration is being updated. Try again.\n", code => HTTP_CONFLICT)
        if !$lock;
    return $lock;
}

sub verify_revision {
    my ($config, $supplied) = @_;
    raise("The action configuration changed. Reload it and try again.\n", code => HTTP_CONFLICT)
        if $config->{revision} ne $supplied;
}

sub read_guest_vault {
    my ($path, $identity) = @_;
    require PVE::EasyActions::Secrets;
    return PVE::EasyActions::Secrets::read_vault("$path.secrets", $identity, KEY_DIRECTORY);
}

sub secret_metadata {
    my ($vault) = @_;
    return {
        revision => $vault->{revision},
        secrets => [
            map { { name => $_, updatedAt => $vault->{secrets}{$_}{updatedAt} } }
                sort keys %{ $vault->{secrets} }
        ],
    };
}

sub resolve_action_secrets {
    my ($action, $secrets) = @_;
    my @resolved;
    my $total_bytes = 0;
    for my $binding (@{ $action->{secrets} // [] }) {
        my $name = $binding->{name};
        my $record = $secrets->{$name};
        raise("The secret '$name' is missing for this guest. Open Actions > Secrets to add it.\n",
            code => HTTP_CONFLICT) if !$record;
        $total_bytes += length(encode_utf8($record->{value}));
        push @resolved, { %$binding, value => $record->{value} };
    }
    raise("An action can use up to 64 KiB of secret data. Review its secret bindings.\n", code => HTTP_CONFLICT)
        if $total_bytes > PVE::EasyActions::Config::MAX_ACTION_SECRET_BYTES();
    return \@resolved;
}

sub edit_guest_secret {
    my ($params, $remove) = @_;
    admin_environment();
    my $name = $params->{name};
    # Keep submitted values out of subsequent parameter-based diagnostics.
    my $value = delete($params->{value});
    require PVE::EasyActions::Secrets;
    raise_param_exc({ value => "Enter a nonempty secret of up to 32 KiB without NUL bytes." })
        if !$remove && !PVE::EasyActions::Secrets::valid_secret_value($value);

    my $path = config_path($params);
    my $lock = lock_configuration($path);
    my ($identity) = guest_context($params);
    my $vault = read_guest_vault($path, $identity);
    raise("The secret list changed. Reload it and try again.\n", code => HTTP_CONFLICT)
        if $vault->{revision} ne $params->{revision};
    my $secrets = $vault->{secrets};
    if ($remove) {
        raise("This secret does not exist.\n", code => HTTP_NOT_FOUND) if !exists($secrets->{$name});
        my $config = PVE::EasyActions::Config::read_config($path, $identity);
        for my $action (@{ $config->{actions} }) {
            raise("This secret is assigned to an action. Remove the binding in Config first.\n",
                code => HTTP_CONFLICT)
                    if grep { $_->{name} eq $name } @{ $action->{secrets} // [] };
        }
        delete($secrets->{$name});
    } else {
        raise("A guest can have up to 24 secrets.\n", code => HTTP_CONFLICT)
            if !exists($secrets->{$name}) && keys(%$secrets) >= PVE::EasyActions::Secrets::MAX_SECRETS();
        $secrets->{$name} = { value => $value, updatedAt => time() };
    }
    return secret_metadata(
        PVE::EasyActions::Secrets::write_vault("$path.secrets", $identity, KEY_DIRECTORY, $secrets),
    );
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
        my $path = config_path($params);
        my $lock = lock_configuration($path);
        my ($identity) = guest_context($params);
        my $current = PVE::EasyActions::Config::read_config($path, $identity);
        verify_revision($current, $params->{revision});
        if (grep { $_->{secrets} } @$actions) {
            my $vault = read_guest_vault($path, $identity);
            resolve_action_secrets($_, $vault->{secrets}) for @$actions;
        }
        return PVE::EasyActions::Config::write_config(dirname($path), $path, $identity, $actions);
    },
});

__PACKAGE__->register_method({
    %secret_endpoint,
    name => 'get_secrets',
    method => 'GET',
    description => 'List the secret names and modification times for a guest.',
    parameters => { additionalProperties => 0, properties => { %guest_params } },
    returns => $secret_response,
    code => sub {
        my ($params) = @_;
        admin_environment();
        my ($identity) = guest_context($params);
        return secret_metadata(read_guest_vault(config_path($params), $identity));
    },
});

my %secret_edit_params = (
    %guest_params,
    revision => $revision,
    name => {
        type => 'string',
        pattern => PVE::EasyActions::Config::SECRET_NAME_PATTERN(),
        description => 'Case-sensitive secret name.',
    },
);

__PACKAGE__->register_method({
    %secret_endpoint,
    name => 'save_secret',
    method => 'PUT',
    description => 'Save or replace the value of a secret.',
    parameters => {
        additionalProperties => 0,
        properties => {
            %secret_edit_params,
            value => { type => 'string', description => 'Secret value, up to 32 KiB.' },
        },
    },
    returns => $secret_response,
    code => sub { return edit_guest_secret($_[0], 0); },
});

__PACKAGE__->register_method({
    %secret_endpoint,
    name => 'delete_secret',
    method => 'DELETE',
    description => 'Delete a secret that is not assigned to an action.',
    parameters => { additionalProperties => 0, properties => { %secret_edit_params } },
    returns => $secret_response,
    code => sub { return edit_guest_secret($_[0], 1); },
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
        my $path = config_path($params);
        # Snapshot the action and all of its secrets under the same lock. The
        # worker keeps this version even if a secret is rotated during the run.
        my $configuration_lock = lock_configuration($path);
        my $config = PVE::EasyActions::Config::read_config($path, $identity);
        verify_revision($config, $params->{revision});
        my ($action) = grep { $_->{name} eq $params->{name} } @{ $config->{actions} };
        raise("The action is not configured for this guest.\n", code => HTTP_NOT_FOUND) if !$action;

        # Holding an open descriptor across fork transfers the local run lock to
        # the worker. Releasing the parent's copy does not unlock the worker.
        my $lock = PVE::EasyActions::Config::try_lock("$path.run.lock");
        raise("An action is already running for this guest.\n", code => HTTP_CONFLICT) if !$lock;
        my $resolved = [];
        if ($action->{secrets}) {
            my $vault = read_guest_vault($path, $identity);
            $resolved = resolve_action_secrets($action, $vault->{secrets});
        }
        close($configuration_lock);
        my $worker = sub {
            my $verify_guest = sub {
                my ($current_identity, $guest_config) = guest_context($params, 1);
                die "The guest identity changed. Review its action configuration.\n"
                    if $current_identity ne $identity;
                return $guest_config;
            };
            PVE::EasyActions::Runner::run_action($params->{type}, $params->{vmid}, $action, $verify_guest, $resolved);
            close($lock);
        };
        return $rpcenv->fork_worker('easyactions', $params->{vmid}, $rpcenv->get_user(), $worker);
    },
});

1;
