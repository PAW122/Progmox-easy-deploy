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
my $actions_param = {
    type => 'string',
    maxLength => PVE::EasyActions::Config::MAX_CONFIG_BYTES(),
    description => 'JSON-encoded array of actions.',
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
                    updatedAt => { type => 'integer', optional => 1 },
                    missing => { type => 'boolean', optional => 1 },
                },
            },
        },
    },
};
my %copy_params = (
    %guest_params,
    type => { type => 'string', enum => ['lxc'], description => 'Container type.' },
);
my %copy_endpoint = (
    path => '{type}/{vmid}/copy',
    protected => 1,
    proxyto => 'node',
    allowtoken => 0,
    permissions => { description => 'Restricted to root@pam.' },
);
my %copy_counts = (
    actions => { type => 'integer', minimum => 0 },
    secrets => { type => 'integer', minimum => 0 },
);
my %copy_target_params = (
    targetNode => get_standard_option('pve-node'),
    targetVmid => get_standard_option('pve-vmid'),
    revision => $revision,
);
my $action_name = { type => 'string', minLength => 1, maxLength => 64, description => 'Action name.' };

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
    my ($path, $identity, $slot) = @_;
    require PVE::EasyActions::Secrets;
    my $vault_path = PVE::EasyActions::Secrets::guest_vault_path($path, $slot);
    return PVE::EasyActions::Secrets::read_vault($vault_path, $identity, KEY_DIRECTORY);
}

sub missing_secret_names {
    my ($actions, $secrets) = @_;
    my %missing;
    for my $action (@$actions) {
        for my $binding (@{ $action->{secrets} // [] }) {
            my $name = $binding->{name};
            $missing{$name} = 1 if !exists($secrets->{$name});
        }
    }
    return \%missing;
}

sub secret_metadata {
    my ($vault, $actions) = @_;
    my $secrets = $vault->{secrets};
    my $missing = missing_secret_names($actions, $secrets);
    return {
        revision => $vault->{revision},
        secrets => [
            map { $missing->{$_} ? { name => $_, missing => 1 } : { name => $_, updatedAt => $secrets->{$_}{updatedAt} } }
                sort(keys(%$secrets), keys(%$missing))
        ],
    };
}

sub resolve_action_secrets {
    my ($action, $secrets, $allowed_missing) = @_;
    my @resolved;
    my $total_bytes = 0;
    for my $binding (@{ $action->{secrets} // [] }) {
        my $name = $binding->{name};
        my $record = $secrets->{$name};
        next if !$record && $allowed_missing && $allowed_missing->{$name};
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
    my $config = PVE::EasyActions::Config::read_config($path, $identity, 1);
    my $vault = read_guest_vault($path, $identity, $config->{vaultSlot});
    raise("The secret list changed. Reload it and try again.\n", code => HTTP_CONFLICT)
        if $vault->{revision} ne $params->{revision};
    my $secrets = $vault->{secrets};
    if ($remove) {
        for my $action (@{ $config->{actions} }) {
            raise("This secret is assigned to an action. Remove the binding in Config first.\n",
                code => HTTP_CONFLICT)
                    if grep { $_->{name} eq $name } @{ $action->{secrets} // [] };
        }
        raise("This secret does not exist.\n", code => HTTP_NOT_FOUND) if !exists($secrets->{$name});
        delete($secrets->{$name});
    } else {
        raise("A guest can have up to 24 secrets.\n", code => HTTP_CONFLICT)
            if !exists($secrets->{$name}) && keys(%$secrets) >= PVE::EasyActions::Secrets::MAX_SECRETS();
        $secrets->{$name} = { value => $value, updatedAt => time() };
    }
    my $vault_path = PVE::EasyActions::Secrets::guest_vault_path($path, $config->{vaultSlot});
    my $saved = PVE::EasyActions::Secrets::write_vault($vault_path, $identity, KEY_DIRECTORY, $secrets);
    return secret_metadata($saved, $config->{actions});
}

sub copy_guest_context {
    my ($params) = @_;
    my ($identity, $native) = guest_context($params);
    raise("Choose a VM or container outside template mode.\n", code => HTTP_CONFLICT) if $native->{template};
    raise("This guest is locked by another Proxmox operation. Try again.\n", code => HTTP_CONFLICT)
        if $native->{lock};
    return $identity;
}

sub read_copy_state {
    my ($path, $identity) = @_;
    my $config = PVE::EasyActions::Config::read_config($path, $identity, 1);
    my $vault = read_guest_vault($path, $identity, $config->{vaultSlot});
    my $metadata = {
        revision => sha256_hex($config->{revision} . $vault->{revision}),
        actions => scalar(@{ $config->{actions} }),
        secrets => scalar(keys %{ $vault->{secrets} }),
    };
    $metadata->{occupied} = ($metadata->{actions} || $metadata->{secrets}) ? 1 : 0;
    return ($metadata, $config, $vault);
}

sub apply_copy {
    my ($request) = @_;
    require PVE::EasyActions::Copy;

    my ($vmid) = ($request->{vmid} // '') =~ /\A([1-9][0-9]{2,8})\z/;
    my $node = PVE::INotify::nodename();
    # Earlier senders omitted the type because full copies always targeted LXC.
    my ($type) = ($request->{type} // 'lxc') =~ /\A(qemu|lxc)\z/;
    my $mode = $request->{mode} // '';
    die "Invalid Easy Actions copy request.\n"
        if !defined($vmid) || !defined($type) || ($request->{node} // '') ne $node
        || $mode !~ /\A(?:empty|append|overwrite)\z/
        || ($request->{revision} // '') !~ /\A[0-9a-f]{64}\z/;

    my $incoming_actions = PVE::EasyActions::Config::validate_sized_actions($request->{actions});
    my $incoming_secrets = PVE::EasyActions::Secrets::validate_secrets($request->{secrets});
    my $incoming_missing = missing_secret_names($incoming_actions, $incoming_secrets);
    resolve_action_secrets($_, $incoming_secrets, $incoming_missing) for @$incoming_actions;

    my $target = { node => $node, type => $type, vmid => $vmid };
    my $class = $type eq 'qemu' ? 'PVE::QemuConfig' : 'PVE::LXC::Config';
    return $class->lock_config_full($vmid, 3, sub {
        my $path = config_path($target);
        my $lock = lock_configuration($path);
        my $identity = copy_guest_context($target);
        my ($metadata, $config, $vault) = read_copy_state($path, $identity);
        raise("The destination configuration changed. Select it again and review the copy options.\n",
            code => HTTP_CONFLICT)
            if $metadata->{revision} ne $request->{revision} || ($mode eq 'empty' && $metadata->{occupied});

        my ($actions, $secrets) = ($incoming_actions, $incoming_secrets);
        if ($mode eq 'append') {
            ($actions, $secrets) = PVE::EasyActions::Copy::append(
                $config->{actions}, $vault->{secrets}, $incoming_actions, $incoming_secrets,
            );
        }
        raise("The destination would exceed the limit of 24 secrets.\n", code => HTTP_CONFLICT)
            if keys(%$secrets) > PVE::EasyActions::Secrets::MAX_SECRETS();
        $actions = eval { PVE::EasyActions::Config::validate_sized_actions($actions) };
        raise($@, code => HTTP_CONFLICT) if $@;
        my $missing = missing_secret_names($actions, $secrets);
        resolve_action_secrets($_, $secrets, $missing) for @$actions;

        PVE::EasyActions::Secrets::replace_guest_state(
            $path, $identity, KEY_DIRECTORY, $actions, $secrets, $config->{vaultSlot},
        );
        return { actions => scalar(@$incoming_actions), secrets => scalar(keys %$incoming_secrets) };
    });
}

sub copy_from_guest {
    my ($params, $selected) = @_;
    admin_environment();
    my ($target_node, $target_vmid) = @{$params}{qw(targetNode targetVmid)};
    my $target_type = $selected ? $params->{targetType} : 'lxc';
    raise_param_exc({ targetVmid => $selected ? 'Select a different guest.' : 'Select a different container.' })
        if $target_vmid == $params->{vmid};

    my $path = config_path($params);
    my $lock = lock_configuration($path);
    my $identity = copy_guest_context($params);
    my $config = PVE::EasyActions::Config::read_config($path, $identity, 1);
    my $actions = $config->{actions};
    my $bindings = [];
    if ($selected) {
        verify_revision($config, $params->{sourceRevision});
        my ($action) = grep { $_->{name} eq $params->{name} } @$actions;
        raise("The selected action is not configured for this guest.\n", code => HTTP_NOT_FOUND) if !$action;
        $actions = [$action];
        $bindings = $action->{secrets} // [];
    }

    my $secrets = !$selected || @$bindings ? read_guest_vault($path, $identity, $config->{vaultSlot})->{secrets} : {};
    close($lock);
    raise("There are no saved actions or secrets to copy.\n", code => HTTP_CONFLICT)
        if !@$actions && !keys(%$secrets);
    my $missing = missing_secret_names($actions, $secrets);
    resolve_action_secrets($_, $secrets, $missing) for @$actions;
    $secrets = { map { $_->{name} => $secrets->{$_->{name}} } grep { !$missing->{$_->{name}} } @$bindings } if $selected;

    my $request = {
        node => $target_node, vmid => $target_vmid, type => $target_type,
        mode => $selected ? 'append' : $params->{mode}, revision => $params->{revision},
        actions => $actions, secrets => $secrets,
    };
    return apply_copy($request) if $target_node eq $params->{node};

    PVE::Cluster::cfs_update(1);
    my $target = PVE::Cluster::get_vmlist()->{ids}{$target_vmid};
    raise("The destination guest is no longer on the selected node.\n", code => HTTP_NOT_FOUND)
        if !$target || $target->{type} ne $target_type || $target->{node} ne $target_node;
    require PVE::EasyActions::Copy;
    my $result = eval { PVE::EasyActions::Copy::send_to_node($target_node, $request) };
    die "Could not confirm the copy on the destination node. Reopen Copy to check its configuration.\n"
        if !$result;
    if ($result->{error}) {
        my $code = $result->{code};
        raise($result->{error}, code => $code)
            if defined($code) && ($code == HTTP_CONFLICT || $code == HTTP_NOT_FOUND);
        die "The destination node could not save the Easy Actions configuration.\n";
    }
    die "Could not confirm the copy on the destination node. Reopen Copy to check its configuration.\n"
        if !$result->{ok};
    return { actions => scalar(@$actions), secrets => scalar(keys %$secrets) };
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
            actions => $actions_param,
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
        my $current = PVE::EasyActions::Config::read_config($path, $identity, 1);
        verify_revision($current, $params->{revision});
        if (grep { $_->{secrets} } @$actions) {
            my $vault = read_guest_vault($path, $identity, $current->{vaultSlot});
            my $missing = missing_secret_names($current->{actions}, $vault->{secrets});
            resolve_action_secrets($_, $vault->{secrets}, $missing) for @$actions;
        }
        return PVE::EasyActions::Config::write_config(dirname($path), $path, $identity, $actions, $current->{vaultSlot});
    },
});

__PACKAGE__->register_method({
    name => 'import_actions',
    path => '{type}/{vmid}/import',
    method => 'POST',
    description => 'Import actions and secret bindings from a configuration file.',
    protected => 1,
    proxyto => 'node',
    allowtoken => 0,
    permissions => { description => 'Restricted to root@pam.' },
    parameters => {
        additionalProperties => 0,
        properties => {
            %guest_params,
            revision => $revision,
            mode => { type => 'string', enum => ['append', 'overwrite'] },
            actions => $actions_param,
        },
    },
    returns => {
        type => 'object',
        properties => {
            %{ $config_response->{properties} },
            missingSecrets => { type => 'array', items => { type => 'string' } },
        },
    },
    code => sub {
        my ($params) = @_;
        admin_environment();
        my $actions = eval { PVE::EasyActions::Config::decode_actions($params->{actions}) };
        raise_param_exc({ actions => $@ }) if $@;

        my $path = config_path($params);
        my $lock = lock_configuration($path);
        my ($identity) = guest_context($params);
        my $current = PVE::EasyActions::Config::read_config($path, $identity, 1);
        verify_revision($current, $params->{revision});

        if ($params->{mode} eq 'append') {
            require PVE::EasyActions::Copy;
            ($actions) = PVE::EasyActions::Copy::append($current->{actions}, {}, $actions, {});
            $actions = eval { PVE::EasyActions::Config::validate_sized_actions($actions) };
            raise($@, code => HTTP_CONFLICT) if $@;
        }
        my $missing = {};
        if (grep { $_->{secrets} } @$actions) {
            my $vault = read_guest_vault($path, $identity, $current->{vaultSlot});
            $missing = missing_secret_names($actions, $vault->{secrets});
            resolve_action_secrets($_, $vault->{secrets}, $missing) for @$actions;
        }
        my $saved = PVE::EasyActions::Config::write_config(dirname($path), $path, $identity, $actions, $current->{vaultSlot});
        return { %$saved, missingSecrets => [sort keys %$missing] };
    },
});

__PACKAGE__->register_method({
    %secret_endpoint,
    name => 'get_secrets',
    method => 'GET',
    description => 'List saved and missing secret names for a guest.',
    parameters => { additionalProperties => 0, properties => { %guest_params } },
    returns => $secret_response,
    code => sub {
        my ($params) = @_;
        admin_environment();
        my $path = config_path($params);
        my $lock = lock_configuration($path);
        my ($identity) = guest_context($params);
        my $config = PVE::EasyActions::Config::read_config($path, $identity, 1);
        my $vault = read_guest_vault($path, $identity, $config->{vaultSlot});
        return secret_metadata($vault, $config->{actions});
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
    %copy_endpoint,
    name => 'inspect_copy_destination',
    method => 'GET',
    description => 'Inspect a guest configuration before copying actions and secrets to it.',
    parameters => { additionalProperties => 0, properties => { %guest_params } },
    returns => {
        type => 'object',
        properties => { %copy_counts, revision => $revision, occupied => { type => 'boolean' } },
    },
    code => sub {
        my ($params) = @_;
        admin_environment();
        my $path = config_path($params);
        my $lock = lock_configuration($path);
        my $identity = copy_guest_context($params);
        my ($metadata) = read_copy_state($path, $identity);
        return $metadata;
    },
});

__PACKAGE__->register_method({
    %copy_endpoint,
    name => 'copy_actions',
    method => 'POST',
    description => 'Copy saved actions and secrets to another container.',
    parameters => {
        additionalProperties => 0,
        properties => {
            %copy_params,
            %copy_target_params,
            mode => { type => 'string', enum => ['empty', 'append', 'overwrite'] },
        },
    },
    returns => { type => 'object', properties => { %copy_counts } },
    code => \&copy_from_guest,
});

__PACKAGE__->register_method({
    %copy_endpoint,
    path => '{type}/{vmid}/copy-action',
    name => 'copy_selected_action',
    method => 'POST',
    description => 'Append one saved action and its bound secrets to another VM or container.',
    parameters => {
        additionalProperties => 0,
        properties => {
            %guest_params,
            %copy_target_params,
            name => $action_name,
            sourceRevision => $revision,
            targetType => { %{$guest_params{type}}, description => 'Destination guest type.' },
        },
    },
    returns => { type => 'object', properties => { %copy_counts } },
    code => sub { return copy_from_guest($_[0], 1); },
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
            name => $action_name,
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
        my $config = PVE::EasyActions::Config::read_config($path, $identity, 1);
        verify_revision($config, $params->{revision});
        my ($action) = grep { $_->{name} eq $params->{name} } @{ $config->{actions} };
        raise("The action is not configured for this guest.\n", code => HTTP_NOT_FOUND) if !$action;

        # Holding an open descriptor across fork transfers the local run lock to
        # the worker. Releasing the parent's copy does not unlock the worker.
        my $lock = PVE::EasyActions::Config::try_lock("$path.run.lock");
        raise("An action is already running for this guest.\n", code => HTTP_CONFLICT) if !$lock;
        my $resolved = [];
        if ($action->{secrets}) {
            my $vault = read_guest_vault($path, $identity, $config->{vaultSlot});
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
