# Proxmox Easy Actions

Proxmox Easy Actions adds an **Actions** menu to the toolbar of each VM and LXC container in Proxmox VE. Each guest has its own list of actions. The first menu item, **Config**, opens an editor for action names, step order, Bash commands, and timeouts.

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
apt install ./proxmox-easy-actions_0.1.0_all.deb
```

## Configuring and running actions

1. Select a running VM or container and open **Actions → Config**.
2. Add an action, such as `Deploy`, and define its steps. Each step runs in its own shell. Use absolute paths or run `cd` in the same step as the commands that need it.
3. Save the configuration. Open **Actions**, select the action, and confirm the run.
4. Check the log and result in the task window. If you close it, find the task by guest ID in Task History.

Commands run as `root` **inside the guest**. The guest needs Linux, `/bin/bash`, GNU `timeout`, `flock` from util-linux, and a writable `/run`. For VMs, enable **Options → QEMU Guest Agent** and start the `qemu-guest-agent` service inside the guest. The add-on uses `pct exec` for containers. Only `root@pam` can configure and run actions.

- Verify command execution, task results, and whether later steps are skipped after a failure with [Smoke Pass and Smoke Fail](examples/smoke-actions.json).
- The Go deployment example fetches the latest commit from `main`, tests and builds the candidate, stops the service, runs migrations, replaces the binary, starts the service, and checks `/healthz`. [Go deployment action](examples/go-deploy.json) · [Customization and import guide](examples/README.md)

## Updating and uninstalling

- To update, install the newer `.deb` with `apt install ./NEW_PACKAGE.deb` and refresh the web interface. The update preserves action configurations.
- To uninstall, run `apt remove proxmox-easy-actions`. Uninstalling removes the web interface integration and preserves guest configurations.
- Installation, updates, and removal reload `pvedaemon` and `pveproxy`. Perform these operations between deployment tasks. The package reapplies the integration when `pve-manager` files change and validates the integration points before patching them. If an update is interrupted, resume package configuration with `dpkg --configure -a`. If a Proxmox update changes the integration points, uninstall the add-on until a compatible package is available.

## Storage and execution behavior

The add-on stores configurations on the node in `/var/lib/proxmox-easy-actions`. Back up this directory with the host configuration. After a VM or LXC migration, action settings remain on the source node. On the destination node, recreate the actions or import them through the API. If the guest identity changes, you can load the previous configuration in **Config**, review it, and save it for the current guest. [Import guide](examples/README.md)

A node can run one action task per guest at a time. Stopping the task in the web interface cancels later steps after the current step finishes or times out. A failed action may leave migrations applied or a service stopped. Deployment scripts and rollback procedures are part of each application's configuration. Store secrets inside the guest and keep them out of stdout and stderr, which go to the Proxmox VE task log.

The add-on registers its own API routes and loads its script through the desktop web interface template. These integration points come from the Proxmox VE source and may change in future releases. When reporting an issue, include the output of `pveversion -v`, the package version, and the task message.

## Source layout and testing

| Directory | Contents |
| --- | --- |
| `src/PVE/EasyActions/` | Proxmox VE API, configuration storage, and action execution |
| `src/ui/` | Menu, editor, and task viewer integration |
| `scripts/`, `packaging/` | Debian package build and lifecycle scripts |
| `examples/` | Smoke tests and a deployment example |
| `tests/` | Add-on tests |

Run these checks locally on Linux.

```bash
prove -I src tests/backend.t
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

