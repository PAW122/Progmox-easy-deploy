#!/usr/bin/env perl
# SPDX-License-Identifier: AGPL-3.0-or-later
use strict;
use warnings;

use FindBin qw($Bin);
use Test::More;

require "$Bin/../packaging/patch-pve";

my $nodes_fixture = <<'PERL';
package PVE::API2::Nodes::Nodeinfo;
sub original_node_route { }

package PVE::API2::Nodes;
sub original_cluster_route { }

1;
PERL
my $index_fixture = <<'HTML';
<head>
    <script type="text/javascript" src="/pve2/js/pvemanagerlib.js?ver=[% version %]"></script>
    <script type="text/javascript">Ext.onReady(function() {});</script>
</head>
HTML
my $first_hash = 'a' x 64;
my $second_hash = 'b' x 64;

sub check_install_cycle {
    my ($nodes, $index) = @_;
    my $patched_nodes = rewrite_nodes($nodes, 1);
    my $patched_index = rewrite_index($index, 1, $first_hash);
    like($patched_nodes, qr/PVE::API2::Nodes::Nodeinfo->register_method\(\{/,
        'mounts the plugin as a node subresource');
    like($patched_index, qr/pvemanagerlib\.js[^\n]*\n[^\n]*\n[^\n]*proxmox-easy-actions\.js\?v=$first_hash/,
        'loads the separately versioned script immediately after the PVE bundle');

    is(rewrite_nodes($patched_nodes, 1), $patched_nodes, 'Perl patch is idempotent');
    is(rewrite_index($patched_index, 1, $first_hash), $patched_index, 'HTML patch is idempotent');
    my $upgraded_index = rewrite_index($patched_index, 1, $second_hash);
    unlike($upgraded_index, qr/\Q$first_hash\E/, 'upgrade removes the old UI version');
    like($upgraded_index, qr/proxmox-easy-actions\.js\?v=$second_hash/, 'upgrade replaces the UI version');

    my $local_edit = "<!-- Local template customisation -->\n";
    is(rewrite_index($local_edit . $upgraded_index, 0, ''), $local_edit . $index,
        'uninstall preserves unrelated changes to the patched HTML template');
    is(rewrite_nodes($patched_nodes, 0), $nodes, 'uninstall restores the exact vendor Perl source');
    is(rewrite_index($upgraded_index, 0, ''), $index, 'uninstall restores the exact vendor template');
}

subtest 'built-in fixtures' => sub { check_install_cycle($nodes_fixture, $index_fixture); };

subtest 'unexpected or damaged layout' => sub {
    my $unexpected_index = $index_fixture;
    $unexpected_index =~ s/pvemanagerlib\.js/renamed.js/;
    eval { rewrite_index($unexpected_index, 1, $first_hash); };
    like($@, qr/Unsupported Proxmox VE layout/, 'rejects a missing desktop bundle anchor');
    eval { rewrite_index($index_fixture x 2, 1, $first_hash); };
    like($@, qr/Unsupported Proxmox VE layout/, 'rejects an ambiguous desktop bundle anchor');
    eval { rewrite_nodes("package PVE::API2::Nodes;\n1;\n", 1); };
    like($@, qr/Unsupported Proxmox VE layout/, 'rejects an unknown node route layout');
    my $broken = rewrite_nodes($nodes_fixture, 1);
    $broken =~ s/^# END Proxmox Easy Actions\n//m;
    eval { rewrite_nodes($broken, 0); };
    like($@, qr/Malformed Proxmox Easy Actions markers/, 'declines to strip a partially marked Perl block');
};

die "Pass optional pairs of Nodes.pm and index.html.tpl fixture paths\n" if @ARGV % 2;
while (@ARGV) {
    my ($nodes, $index) = splice(@ARGV, 0, 2);
    subtest "vendor assets $nodes, $index" => sub {
        check_install_cycle(read_file($nodes), read_file($index));
    };
}

done_testing();
