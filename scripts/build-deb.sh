#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if (( $# > 1 )); then
    echo "Usage: $0 [VERSION]" >&2
    exit 2
fi

version=${1:-$(cat "$repository/packaging/VERSION")}
if [[ ! $version =~ ^[0-9][A-Za-z0-9.+~-]*$ ]] || ! dpkg --validate-version "$version"; then
    echo "Invalid Debian package version: $version" >&2
    exit 2
fi

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
package="$staging/package"
perl_modules="$package/usr/share/perl5/PVE/EasyActions"
docdir="$package/usr/share/doc/proxmox-easy-actions"

install -d "$package/DEBIAN" "$package/usr/lib/proxmox-easy-actions" \
    "$package/usr/share/pve-manager/js" "$perl_modules" "$docdir"
{
    printf 'Version: %s\n' "$version"
    cat "$repository/packaging/debian/control"
} > "$package/DEBIAN/control"
install -m 0644 "$repository/packaging/debian/triggers" "$package/DEBIAN/triggers"
install -m 0755 "$repository/packaging/debian/postinst" "$repository/packaging/debian/prerm" \
    "$package/DEBIAN/"
install -m 0755 "$repository/packaging/patch-pve" "$package/usr/lib/proxmox-easy-actions/patch-pve"
install -m 0755 "$repository/packaging/receive-copy" "$package/usr/lib/proxmox-easy-actions/receive-copy"
install -m 0644 "$repository/src/PVE/EasyActions/"*.pm "$perl_modules/"
install -m 0644 "$repository/src/ui/easy-actions.js" \
    "$package/usr/share/pve-manager/js/proxmox-easy-actions.js"
install -m 0644 "$repository/packaging/debian/copyright" "$docdir/copyright"
install -m 0644 "$repository/LICENSE" "$docdir/AGPL-3.0.txt"

install -d "$repository/dist"
dpkg-deb --root-owner-group --build "$package" \
    "$repository/dist/proxmox-easy-actions_${version}_all.deb"
