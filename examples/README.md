# Example actions

- [`smoke-actions.json`](smoke-actions.json) runs on a Linux test guest. Run `Smoke Pass` and check the guest name in the log. The first step of `Smoke Fail` intentionally exits with code 7.
- [`go-deploy.json`](go-deploy.json) is a template for a Go application managed by systemd. Adapt the paths and migrations to your service before running it.

## Set up the Go application

Set up a checkout at `/srv/myapp/source` inside the guest. The action deploys the commit fetched from `origin/main`, so use a dedicated checkout with access to a trusted repository. Install `git`, the Go version required by the application, and `curl`. The example assumes the following setup.

- The application entry point is the `./cmd/myapp` package.
- The `myapp.service` unit uses `ExecStart=/srv/myapp/bin/myapp`.
- The repository contains `deploy/migrate.sh`, and the script can access the database from inside the guest.
- The endpoint at `http://127.0.0.1:8080/healthz` returns a `2xx` response when the application is ready.

The action fetches the code, runs the tests, and builds the candidate binary at `/srv/myapp/bin/myapp.next`. It then stops the service and runs the migrations. If a step fails after the service stops, use the task log and your application's recovery procedure.

## Configure the actions

Enter the steps in **Actions → Config**, or save the full list of actions with `pvesh` as `root` on the node. The following command uses `jq` and saves the actions only if the guest has an empty configuration. Substitute your node name, guest type (`qemu` or `lxc`), and VMID.

```bash
guest='/nodes/pve1/easy-actions/lxc/101'
current=$(pvesh get "$guest" --output-format json) &&
revision=$(jq -er 'select(.actions | length == 0).revision' <<<"$current") &&
pvesh set "$guest" --revision "$revision" --actions "$(cat examples/go-deploy.json)"
```

Use `examples/smoke-actions.json` to test the setup. The `pvesh set` command replaces the full list of actions. To add an example to an existing configuration, enter the steps in the editor.
