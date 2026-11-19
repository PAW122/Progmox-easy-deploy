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

use PVE::QemuServer::Monitor qw(mon_cmd);

use constant LOG_LIMIT => 128 * 1024;
use constant TRANSPORT_GRACE => 30;
use constant MAX_SECRET_BINDINGS => 8;
use constant MAX_SECRET_BYTES => 32 * 1024;
use constant MAX_ACTION_SECRET_BYTES => 64 * 1024;

# The outer guest shell holds the file lifetime across timeout. The inner shell
# loads the variables after startup, so neither flock nor timeout inherits them.
my $launch_step = <<'BASH';
read_field() { IFS= read -r -d '' "$1" || exit 2; }
read_field script
read_field count
for ((i = 0; i < count; ++i)); do
    read_field name
    read_field value
    export "$name=$value"
done
unset -f read_field
unset count i name value
exec </dev/null
eval -- 'unset script; '"$script"
BASH

my $read_step = <<'BASH';
fail() { printf '%s\n' 'Invalid or incomplete Easy Actions step input.' >&2; exit 2; }
input_deadline=$((SECONDS + 20))
read_field() {
    local remaining=$((input_deadline - SECONDS))
    (( remaining > 0 )) && IFS= read -t "$remaining" -r -d '' "$1" || fail
}
read_field protocol
[[ $protocol == 'PEA1' ]] || fail
read_field script
read_field count
[[ $count =~ ^[0-8]$ ]] || fail
names=() modes=() values=()
for ((i = 0; i < count; ++i)); do
    read_field name
    read_field mode
    read_field value
    [[ $name =~ ^[A-Z_][A-Z0-9_]{0,63}$ && ( $mode == file || $mode == env ) ]] || fail
    names+=("$name") modes+=("$mode") values+=("$value")
done
read_field end
[[ $end == 'END' ]] || fail
remaining=$((input_deadline - SECONDS))
(( remaining > 0 )) || fail
if IFS= read -t "$remaining" -r -d '' extra; then
    fail
else
    [[ $? == 1 && -z $extra ]] || fail
fi

runtime=''
cleanup() {
    local status=$?
    if [[ -n $runtime ]] && ! /usr/bin/rm -rf -- "$runtime"; then
        printf '%s\n' 'Unable to remove the Easy Actions temporary secret directory.' >&2
        exit 2
    fi
    return "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for ((i = 0; i < count; ++i)); do
    if [[ ${modes[i]} == file ]]; then
        if [[ -z $runtime ]]; then
            runtime=$(umask 077; /usr/bin/mktemp -d -- "$2/proxmox-easy-actions.XXXXXXXXXX") || exit 2
        fi
        file=$runtime/${names[i]}
        ( umask 077; printf '%s' "${values[i]}" > "$file" ) || exit 2
        values[i]=$file
    fi
done

emit_step() {
    printf '%s\0' "$script" "$count"
    for ((i = 0; i < count; ++i)); do
        printf '%s\0' "${names[i]}" "${values[i]}"
    done
}
set -o pipefail
emit_step | /usr/bin/timeout --kill-after=5s "${1}s" /bin/bash -e -o pipefail -c "$3"
BASH

sub guest_command {
    my ($timeout) = @_;
    return (
        '/usr/bin/flock', '--nonblock', '--conflict-exit-code=75', '--close',
        '/run/proxmox-easy-actions.lock',
        '/bin/bash', '-c', $read_step, 'easy-actions', $timeout, '/run', $launch_step,
    );
}

sub encode_bindings {
    my ($bindings) = @_;
    $bindings //= [];
    die "Invalid Easy Actions secret bindings.\n"
        if ref($bindings) ne 'ARRAY' || @$bindings > MAX_SECRET_BINDINGS;

    my (@encoded, %used_names);
    my $size = 0;
    for my $binding (@$bindings) {
        die "Invalid Easy Actions secret binding.\n" if ref($binding) ne 'HASH';
        my ($alias, $mode, $value) = @{$binding}{qw(env mode value)};
        die "Invalid Easy Actions secret binding.\n"
            if !defined($alias) || ref($alias) || $alias !~ /\A[A-Z_][A-Z0-9_]{0,63}\z/ || $used_names{$alias}++
            || !defined($mode) || ($mode ne 'env' && $mode ne 'file')
            || !defined($value) || ref($value) || !length($value) || $value =~ /\0/;
        my $bytes = encode_utf8($value);
        $size += length($bytes);
        die "Easy Actions secrets exceed the permitted input size.\n"
            if length($bytes) > MAX_SECRET_BYTES || $size > MAX_ACTION_SECRET_BYTES;
        push @encoded, [$alias, $mode, $bytes];
    }
    return \@encoded;
}

sub step_payload {
    my ($command, $bindings) = @_;
    die "An Easy Actions script cannot contain NUL bytes.\n" if $command =~ /\0/;
    return join("\0", 'PEA1', encode_utf8($command), scalar(@$bindings), (map { @$_ } @$bindings), 'END', '');
}

sub build_log_redactor {
    my ($bindings) = @_;
    my %secrets = map { $_->[2] => 1 } @$bindings;
    return undef if !%secrets;

    # Prefix tables identify exact and overlapping matches in linear time, and
    # identify a partial secret when a stream ends at the output limit.
    my @prefix_tables;
    for my $secret (keys %secrets) {
        my @bytes = unpack('C*', $secret);
        my @prefix = (0);
        my $matched = 0;
        for my $i (1 .. $#bytes) {
            $matched = $prefix[$matched - 1] while $matched && $bytes[$i] != $bytes[$matched];
            ++$matched if $bytes[$i] == $bytes[$matched];
            push @prefix, $matched;
        }
        push @prefix_tables, [\@bytes, \@prefix];
    }
    return \@prefix_tables;
}

sub redact_output {
    my ($bytes, $truncated, $redactor) = @_;
    return $bytes if !$redactor || !length($bytes);

    my @source = unpack('C*', $bytes);
    my @ends;
    for my $entry (@$redactor) {
        my ($secret, $prefix) = @$entry;
        my $length = scalar(@$secret);
        my $matched = 0;
        for my $i (0 .. $#source) {
            my $byte = $source[$i];
            $matched = $prefix->[$matched - 1] while $matched && $byte != $secret->[$matched];
            next if $byte != $secret->[$matched];
            if (++$matched == $length) {
                my $start = $i + 1 - $length;
                $ends[$start] = $i + 1 if ($ends[$start] // 0) < $i + 1;
                $matched = $prefix->[$matched - 1];
            }
        }
        $ends[@source - $matched] = scalar(@source) if $truncated && $matched;
    }
    return $bytes if !@ends;

    my $output = '';
    my ($copied, $i) = (0, 0);
    while ($i <= $#ends) {
        my $end = $ends[$i];
        if (!defined($end)) {
            ++$i;
            next;
        }
        $output .= substr($bytes, $copied, $i - $copied) . '[secret redacted]';
        for (my $next = $i + 1; $next <= $end; ++$next) {
            $end = $ends[$next] if ($ends[$next] // 0) > $end;
        }
        $copied = $i = $end;
    }
    return $output . substr($bytes, $copied);
}

sub log_output {
    my ($bytes, $truncated, $redactor) = @_;
    $bytes //= '';
    $truncated ||= length($bytes) > LOG_LIMIT;
    my $output = decode_utf8(redact_output(substr($bytes, 0, LOG_LIMIT), $truncated, $redactor));
    $output =~ s/\r\n?/\n/g;
    $output =~ s/[^\P{Cc}\n\t]//g;
    # Prefix guest-controlled lines so they cannot be mistaken for PVE task status.
    print encode_utf8("[guest] $_\n") for split(/\n/, $output);
    print "[guest output truncated]\n" if $truncated;
}

sub run_container_step {
    my ($vmid, $command, $input, $seconds, $redactor) = @_;
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
                my $length = length($input) - $offset;
                # A write no larger than Linux PIPE_BUF cannot block on this ready pipe.
                $length = 4096 if $length > 4096;
                my $written = syswrite($stdin, $input, $length, $offset);
                die "Unable to send script to the container: $!\n"
                    if !defined($written) && $! != EPIPE && $! != EINTR && $! != EWOULDBLOCK;
                if (defined($written)) {
                    $offset += $written;
                }
                if ($offset == length($input) || (!defined($written) && $! == EPIPE)) {
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
    log_output($captured, $truncated || !$ok, $redactor);
    die $error if !$ok;
    return WEXITSTATUS($status) if WIFEXITED($status);
    die "Container transport received signal " . WTERMSIG($status) . ".\n" if WIFSIGNALED($status);
    die "Container transport ended without an exit status.\n";
}

sub run_vm_step {
    my ($vmid, $configuration, $command, $input, $seconds, $redactor) = @_;
    die "QEMU Guest Agent is not configured. Enable it in the VM options.\n"
        if !defined($configuration->{agent});
    my $ping = eval { mon_cmd($vmid, 'guest-ping', timeout => 3) };
    die "QEMU Guest Agent is unavailable. Check that the VM and the guest agent service are running.\n"
        if $@ || (ref($ping) eq 'HASH' && $ping->{error});

    # The monitor command signature is shared by PVE 8 and 9. Their higher-level
    # Perl guest-exec wrappers take different arguments.
    my ($program, @arguments) = @$command;
    my $job = eval {
        mon_cmd($vmid, 'guest-exec',
            path => $program,
            arg => \@arguments,
            'capture-output' => JSON::true,
            'input-data' => encode_base64($input, ''),
            timeout => 5,
        );
    };
    die "QEMU Guest Agent could not start the guest step.\n"
        if $@ || ref($job) ne 'HASH' || $job->{error};
    my $pid = $job->{pid};
    die "QEMU Guest Agent did not return a process ID.\n" if !defined($pid);

    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds + TRANSPORT_GRACE;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $status = eval { mon_cmd($vmid, 'guest-exec-status', pid => $pid, timeout => 5) };
        die "QEMU Guest Agent could not read the guest step status.\n"
            if $@ || ref($status) ne 'HASH' || $status->{error};
        if ($status->{exited}) {
            log_output(decode_base64($status->{'out-data'} // ''), $status->{'out-truncated'}, $redactor);
            log_output(decode_base64($status->{'err-data'} // ''), $status->{'err-truncated'}, $redactor);
            return $status->{exitcode} if ($status->{exitcode} // '') =~ /\A[0-9]{1,3}\z/;
            die "Guest command received signal $status->{signal}.\n"
                if ($status->{signal} // '') =~ /\A[0-9]{1,3}\z/;
            die "Guest command ended without an exit status.\n";
        }
        sleep(0.5);
    }
    die "QEMU Guest Agent did not report command completion before the transport deadline.\n";
}

sub run_action {
    my ($type, $vmid, $action, $verify_guest, $resolved_bindings) = @_;
    my $bindings = encode_bindings($resolved_bindings);
    my $redactor = build_log_redactor($bindings);
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
        my $input = step_payload($step->{command}, $bindings);
        my $status = $type eq 'qemu'
            ? run_vm_step($vmid, $guest_configuration, \@command, $input, $step->{timeout}, $redactor)
            : run_container_step($vmid, \@command, $input, $step->{timeout}, $redactor);
        die "Action cancelled after the current step.\n" if $cancelled;
        die "Step $step_number failed with exit code $status.\n" if $status;
        print "Step $step_number PASS\n";
    }

    print "Action PASS\n";
}

1;
