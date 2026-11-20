# Proxmox Easy Actions

Proxmox Easy Actions adds an **Actions** menu to the toolbar of each VM and LXC container in Proxmox VE. Each guest has its own list of actions. The first menu item, **Config**, opens an editor for action names, step order, Bash commands, and timeouts. The step editor highlights Bash syntax as you type.

Each action runs as a Proxmox VE task. You can close the task window and reopen the log from Task History. If a step fails or times out, the task stops and identifies the failed step.

## Installation

The package targets Proxmox VE **8.4 and 9.x**. Open **Shell** on the Proxmox VE node and paste the block below as `root`. It clones the repository into a temporary directory, builds the Debian package, and installs it. If the node needs Git, run `apt install git` first.

```bash
bash -c '
set -e
build_dir="$(mktemp -d)"
git clone --depth 1 https://github.com/PAW122/Progmox-easy-deploy.git "$build_dir"
cd "$build_dir"
bash scripts/build-deb.sh
apt install "./dist/proxmox-easy-actions_$(cat packaging/VERSION)_all.deb"
'
```

**Multi-node clusters.** Run the installation command on every node in the cluster and use the same package version throughout. The web interface loads the menu from the node you connect to. The node hosting the guest loads its configuration and runs its actions.

Refresh the desktop web interface and sign in as `root@pam`.

### Installing a local package

If you have a source checkout, run `bash scripts/build-deb.sh` on Debian, Ubuntu, or Proxmox VE with `bash` and `dpkg-deb` installed. Copy the `.deb` file from `dist/` or a project release to the node. Run this command as `root` from the directory containing the package.

```bash
apt install ./proxmox-easy-actions_0.3.2_all.deb
```

## Update

Wait for running actions to finish, then paste the block below into the Proxmox VE node's **Shell** as `root`. It builds the version in the repository, backs up the node's configuration, and upgrades the package in place. The package preserves existing actions and encrypted vaults.

```bash
bash -c '
set -e
installed="$(dpkg-query -W -f="\${Version}" proxmox-easy-actions)"
build_dir="$(mktemp -d)"
git clone --depth 1 https://github.com/PAW122/Progmox-easy-deploy.git "$build_dir"
cd "$build_dir"
version="$(cat packaging/VERSION)"

if ! dpkg --compare-versions "$version" gt "$installed"; then
    printf "Installed version %s is current or newer than repository version %s.\n" "$installed" "$version"
    exit 0
fi

bash scripts/build-deb.sh "$version"

if [ -d /var/lib/proxmox-easy-actions ]; then
    backup="$(mktemp -d /root/proxmox-easy-actions-backup.XXXXXX)"
    cp -a /var/lib/proxmox-easy-actions "$backup/"
    printf "Configuration backup: %s\n" "$backup"
fi

if [ -f /etc/proxmox-easy-actions/master.key ]; then
    key_backup="$(mktemp -d /root/proxmox-easy-actions-key.XXXXXX)"
    cp -a /etc/proxmox-easy-actions/master.key "$key_backup/"
    printf "Master key backup: %s\n" "$key_backup"
fi

apt install "./dist/proxmox-easy-actions_${version}_all.deb"
dpkg-query -W proxmox-easy-actions
'
```

Update every cluster node individually to the same version. After the update, refresh the web interface and check that the existing actions are visible. The package reloads `pvedaemon` and `pveproxy` during the update.

If you already have a newer `.deb`, make the same backups and run `apt install ./NEW_PACKAGE.deb`. If package configuration is interrupted, resume it with `dpkg --configure -a`. The add-on reapplies its integration when `pve-manager` files change and validates the integration points before patching them. If a Proxmox update changes those integration points, remove the add-on until a compatible package is available.

## Configuring and running actions

1. Select a running VM or container and open **Actions → Config**.
2. Add an action, such as `Deploy`, and define its steps. Each step runs in its own shell. Use absolute paths or run `cd` in the same step as the commands that need it.
3. Save the configuration. Open **Actions**, select the action, and confirm the run.
4. Check the log and result in the task window. If you close it, find the task by guest ID in Task History.

Commands run as `root` **inside the guest**. The guest needs Linux, `/bin/bash`, GNU `timeout`, `flock` from util-linux, and a writable `/run`. For VMs, enable **Options → QEMU Guest Agent** and start the `qemu-guest-agent` service inside the guest. The add-on uses `pct exec` for containers. Only `root@pam` can configure and run actions.

- Verify command execution, task results, and whether later steps are skipped after a failure with [Smoke Pass and Smoke Fail](examples/smoke-actions.json).
- The Go deployment example fetches the latest commit from `main`, tests and builds the candidate, stops the service, runs migrations, replaces the binary, starts the service, and checks `/healthz`. [Go deployment action](examples/go-deploy.json) · [Customization and import guide](examples/README.md)

## Copying actions and secrets

On the source container, open **Actions → Copy** and select another LXC container. The copy uses the source's saved actions and all its saved secrets. If the target has any actions or secrets, choose one of these options.

- **Append** keeps the target configuration and adds the source actions after the existing ones. When a name already exists, the copied action gets a suffix like ` (2)` and the copied secret gets a suffix like `_2`. Copied actions use the renamed secrets automatically.
- **Overwrite** replaces all actions and secrets on the target with the source configuration.

For a target on another node, install the same version of the add-on on both nodes. The copy uses the cluster's trusted SSH connection and the destination node encrypts the secrets with its own key.

To copy one action, open **Actions → Config**, select a saved action, and click **Copy**. Choose another VM or LXC container. The copy is added to the destination with the secrets bound to that action. Existing actions and secrets are kept, and duplicate names receive the same suffixes as **Append**.

## Secrets

1. Open **Actions → Secrets** on your guest. Create a secret such as `deploy_key` and paste its value.
2. Open **Actions → Config**, select your action, and add `deploy_key` under **Secret bindings**. Enter `DEPLOY_SSH_KEY_FILE` as the variable name and choose **Temporary file path** for an SSH private key.
3. Save and run the action. Each step receives the variable inside the guest. **Temporary file path** gives the step the path to a file with permissions `0600`. **Value in environment** gives it the secret value, for example an API token.

For a repository with an SSH remote, a step can use the file binding like this. The guest's SSH client must already trust the Git server's host key.

```bash
GIT_SSH_COMMAND="ssh -o BatchMode=yes -o IdentitiesOnly=yes -i \"$DEPLOY_SSH_KEY_FILE\"" git fetch origin
```

Replace the value in **Actions → Secrets** to rotate it. Each run takes a snapshot of its secret bindings at startup, so the next run uses the new value. Variables and temporary files are scoped to the action steps. An already running service keeps its existing environment. When rotating an SSH key pair, register the new public key with the remote Git server.

The **Secrets** menu lists names and modification times. Action configurations and exports store only binding names, modes, and variable names. The runner masks known secret values in task output. Keep secret values out of step output, including any encoded or transformed forms.

Each node stores encrypted guest vaults in `/var/lib/proxmox-easy-actions` and the node key in `/etc/proxmox-easy-actions/master.key`. Protect and back up the key separately from the vaults. When a guest moves to a different node, recreate its secrets before loading or importing its action bindings. A guest supports up to 24 secrets of 32 KiB each. An action can bind up to eight secrets with up to 64 KiB of combined values.

## Uninstall

Run `apt remove proxmox-easy-actions` as `root` after running actions finish. Removal reloads `pvedaemon` and `pveproxy` and preserves guest configurations and vaults.

## Storage and execution behavior

The add-on stores configurations on the node in `/var/lib/proxmox-easy-actions`. Back up this directory with the host configuration. After a VM or LXC migration, action settings remain on the source node. On the destination node, recreate the actions or import them through the API. If the guest identity changes, you can load the previous configuration in **Config**, review it, and save it for the current guest. [Import guide](examples/README.md)

A node can run one action task per guest at a time. Stopping the task in the web interface cancels later steps after the current step finishes or times out. A failed action may leave migrations applied or a service stopped. Deployment scripts and rollback procedures are part of each application's configuration. Command output goes to the Proxmox VE task log.

The add-on registers its own API routes and loads its script through the desktop web interface template. These integration points come from the Proxmox VE source and may change in future releases. When reporting an issue, include the output of `pveversion -v`, the package version, and the task message.

## Source layout and testing

| Directory | Contents |
| --- | --- |
| `src/PVE/EasyActions/` | Proxmox VE API, configuration storage, encrypted secrets, and action execution |
| `src/ui/` | Menu, editor, and task viewer integration |
| `scripts/`, `packaging/` | Debian package build and lifecycle scripts |
| `examples/` | Smoke tests and a deployment example |
| `tests/` | Add-on tests |

Run these checks locally on Linux with `libcryptx-perl` installed.

```bash
prove -I src tests/*.t
perl scripts/test-package-integration.pl
node --check src/ui/easy-actions.js
```

The GitHub Actions workflow runs these checks and produces the `proxmox-easy-actions-deb` artifact with the package and `SHA256SUMS`.

On a Proxmox VE node, configure both actions from `examples/smoke-actions.json` on a test VM and a test LXC container. Run both actions on each guest and check the logs. `Smoke Pass` should end with `TASK OK`. `Smoke Fail` should report exit code `7` and skip the step named `Must be skipped`. Refresh the web interface and verify that each guest retains its configuration. Sign in with another account and verify that the button is hidden and the API denies access.

### Upstream references

- [Guest panels in Proxmox VE](https://github.com/proxmox/pve-docs/blob/master/pve-gui.adoc#guests)
- [QEMU and Guest Agent configuration](https://github.com/proxmox/pve-docs/blob/master/qm.adoc)
- [Containers and the `pct` command](https://github.com/proxmox/pve-docs/blob/master/pct.adoc)
- [API registration in Proxmox VE](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Nodes.pm)

## License

Independent community project licensed under [AGPL-3.0-or-later](LICENSE).

