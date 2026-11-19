# SPDX-License-Identifier: AGPL-3.0-or-later
package PVE::EasyActions::Runner;

use strict;
use warnings;

use Encode qw(decode_utf8 encode_utf8);
use Errno qw(EINTR EPIPE EWOULDBLOCK);
use IO::Select;
use IPC::Open3;
use JSON ();
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX qw(WIFEXITED WEXITSTATUS WIFSIGNALED WTERMSIG WNOHANG);
use Symbol qw(gensym);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC sleep);

use PVE::QemuServer::Agent qw(check_agent_error);
use PVE::QemuServer::Monitor qw(mon_cmd);

use constant LOG_LIMIT => 128 * 1024;
use constant TRANSPORT_GRACE => 30;

# Pass the user script via stdin, so host process arguments stay fixed and only
# the guest shell evaluates the saved text. Give the script an empty stdin.
my $read_script = <<'BASH';
IFS= read -r -d '' script || [[ -n $script ]] || exit 2
exec /bin/bash -e -o pipefail -c "$script" </dev/null
BASH

sub guest_command {
    my ($timeout) = @_;
    return (
        '/usr/bin/flock', '--nonblock', '--conflict-exit-code=75', '--close',
        '/run/proxmox-easy-actions.lock',
        '/usr/bin/timeout', '--kill-after=5s', "${timeout}s",
        '/bin/bash', '-c', $read_script,
    );
}

sub log_output {
    my ($bytes, $truncated) = @_;
    $bytes //= '';
    $truncated ||= length($bytes) > LOG_LIMIT;
    my $output = decode_utf8(substr($bytes, 0, LOG_LIMIT));
    $output =~ s/\r\n?/\n/g;
    $output =~ s/[^\P{Cc}\n\t]//g;
    # Prefix guest-controlled lines so they cannot be mistaken for PVE task status.
    print encode_utf8("[guest] $_\n") for split(/\n/, $output);
    print "[guest output truncated]\n" if $truncated;
}

sub run_container_step {
    my ($vmid, $command, $script, $seconds) = @_;
    my $stdout = gensym();
    my $pid = open3(my $stdin, $stdout, $stdout, '/usr/sbin/pct', 'exec', $vmid,
        '--keep-env', '0', '--', @$command);

    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds + TRANSPORT_GRACE;
    my ($captured, $truncated, $status, $offset) = ('', 0, undef, 0);
    my $readers = IO::Select->new($stdout);
    my $writers = IO::Select->new($stdin);
    local $SIG{PIPE} = 'IGNORE';

    my $ok = eval {
        while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
            if (!defined($status) && waitpid($pid, WNOHANG) == $pid) {
                $status = $?;
            }
            last if defined($status) && !$readers->count;
            if (!$readers->count && !$writers->count) {
                sleep(0.1);
                next;
            }

            my ($ready_read, $ready_write) = IO::Select->select($readers, $writers, undef, 0.25);
            if ($ready_write && @$ready_write) {
                my $length = length($script) - $offset;
                # A write no larger than Linux PIPE_BUF cannot block on this ready pipe.
                $length = 4096 if $length > 4096;
                my $written = syswrite($stdin, $script, $length, $offset);
                die "Unable to send script to the container: $!\n"
                    if !defined($written) && $! != EPIPE && $! != EINTR && $! != EWOULDBLOCK;
                if (defined($written)) {
                    $offset += $written;
                }
                if ($offset == length($script) || (!defined($written) && $! == EPIPE)) {
                    $writers->remove($stdin);
                    close($stdin);
                }
            }
            if ($ready_read && @$ready_read) {
                my $read = sysread($stdout, my $chunk, 8192);
                next if !defined($read) && ($! == EINTR || $! == EWOULDBLOCK);
                die "Unable to read container output: $!\n" if !defined($read);
                $readers->remove($stdout) if !$read;
                my $room = LOG_LIMIT - length($captured);
                $captured .= substr($chunk, 0, $room);
                $truncated ||= $read > $room;
            }
        }
        die "Container transport timed out.\n" if !defined($status) || $readers->count;
        1;
    };
    my $error = $@;
    close($stdin) if defined(fileno($stdin));
    close($stdout);
    if (!defined($status)) {
        kill('KILL', $pid);
        waitpid($pid, 0);
    }
    log_output($captured, $truncated);
    die $error if !$ok;
    return WEXITSTATUS($status) if WIFEXITED($status);
    die "Container transport received signal " . WTERMSIG($status) . ".\n" if WIFSIGNALED($status);
    die "Container transport ended without an exit status.\n";
}

sub run_vm_step {
    my ($vmid, $configuration, $command, $script, $seconds) = @_;
    die "QEMU Guest Agent is not configured. Enable it in the VM options.\n"
        if !defined($configuration->{agent});
    my $ping = eval { mon_cmd($vmid, 'guest-ping', timeout => 3) };
    die "QEMU Guest Agent is unavailable. Check that the VM and the guest agent service are running.\n"
        if $@ || (ref($ping) eq 'HASH' && $ping->{error});

    # The monitor command signature is shared by PVE 8 and 9. Their higher-level
    # Perl guest-exec wrappers take different arguments.
    my ($program, @arguments) = @$command;
    my $job = mon_cmd($vmid, 'guest-exec',
        path => $program,
        arg => \@arguments,
        'capture-output' => JSON::true,
        'input-data' => encode_base64($script, ''),
        timeout => 5,
    );
    check_agent_error($job, 'Unable to start guest command.');
    my $pid = $job->{pid};
    die "QEMU Guest Agent did not return a process ID.\n" if !defined($pid);

    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds + TRANSPORT_GRACE;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $status = mon_cmd($vmid, 'guest-exec-status', pid => $pid, timeout => 5);
        check_agent_error($status, 'Unable to read guest command status.');
        if ($status->{exited}) {
            log_output(decode_base64($status->{'out-data'} // ''), $status->{'out-truncated'});
            log_output(decode_base64($status->{'err-data'} // ''), $status->{'err-truncated'});
            return $status->{exitcode} if defined($status->{exitcode});
            die "Guest command received signal $status->{signal}.\n" if defined($status->{signal});
            die "Guest command ended without an exit status.\n";
        }
        sleep(0.5);
    }
    die "QEMU Guest Agent did not report command completion before the transport deadline.\n";
}

sub run_action {
    my ($type, $vmid, $action, $verify_guest) = @_;
    my $cancelled = 0;
    # PVE can stop this task. Finish the active in-guest step (or its timeout)
    # before handing the per-guest lock to a subsequent action.
    local $SIG{TERM} = local $SIG{INT} = local $SIG{QUIT} = sub { $cancelled = 1 };

    print encode_utf8("Action $action->{name} on $type guest $vmid\n");
    my $step_number = 0;
    my $step_count = scalar(@{ $action->{steps} });
    for my $step (@{ $action->{steps} }) {
        die "Action cancelled.\n" if $cancelled;
        my $guest_configuration = $verify_guest->();
        die "Action cancelled.\n" if $cancelled;
        my $label = '[' . ++$step_number . "/$step_count] $step->{name}";
        print encode_utf8("$label (timeout $step->{timeout}s)\n");
        my @command = guest_command($step->{timeout});
        my $script = encode_utf8($step->{command});
        my $status = $type eq 'qemu'
            ? run_vm_step($vmid, $guest_configuration, \@command, $script, $step->{timeout})
            : run_container_step($vmid, \@command, $script, $step->{timeout});
        die "Action cancelled after the current step.\n" if $cancelled;
        die "Step $step_number failed with exit code $status.\n" if $status;
        print "Step $step_number PASS\n";
    }

    print "Action PASS\n";
}

1;
