# Reproducing the unhandled system analysis request

arm64 integration tests sporadically fail tracer startup with:

```
system analysis request was not handled for tid N at 0x...
```

`TestSystemAnalysisStress` repeats the failing step thousands of times. That
step is attaching `read_task_struct` and issuing a request right away.
`stress-system-analysis.sh` runs the test in a QEMU guest.

## Requirements

- An arm64 Linux host without `/dev/kvm`. `run-tests.sh` switches to KVM
  whenever `/dev/kvm` exists, and the issue does not show up there. It needs
  multi-threaded TCG with several vCPUs, the QEMU default without KVM.
- `qemu-system-aarch64` 9.2 or newer.
- Root, or `sudo`, which `run-tests.sh` uses to run QEMU when `/dev/kvm` is
  not accessible.
- `bluebox`, or Go to run it.
- arm64 kernel images in `ci-kernels/arm64/<version>/vmlinuz`, or in
  `KERN_DIR` (an absolute path) with the same layout. Missing ones are
  downloaded with Docker.

The image built from the repository `Dockerfile` runs as root but has neither
QEMU nor Docker. Inside it, run `apt-get install -y qemu-system-arm` and
provide the kernel images, for example through a bind mount.

## Steps

Build the static test binary from the repository root. The eBPF objects must
be up to date, see the top level `Makefile`.

```bash
go test -ldflags='-extldflags=-static' -trimpath -c \
  -tags osusergo,netgo,static_build,integration \
  -o ./support/tracer.test ./tracer
```

Run 4000 requests against a 6.16 kernel:

```bash
./support/stress-system-analysis.sh 6.16 4000
```

This takes about 1.5 minutes. The failure rate is about 1 in 1750 requests,
so a run without failures is possible. Rerun or raise the count.

## Reading the output

A failure looks like:

```
request 1470 unhandled: read_task_struct: system analysis request was not handled for tid 85 at 0x0 (retries=48 waited=256ms requester_cpus=map[0:7 1:13 2:21 3:7] migrated_cpu=-1 armed_runs=0 requester_process_runs=0 last_tid=0 last_cpu=none recursion_misses=0 thread_flags=0x400(TIF_SYSCALL_TRACEPOINT=true))
4000 requests in 1m38s: 0 retried (max wait 0s), 0 needed migration, 2 unhandled
```

| Field | Meaning |
|---|---|
| `requester_cpus` | Retries per CPU the requester polled from |
| `migrated_cpu` | CPU that serviced the request after pinning the requester to each CPU in turn, `-1` if none |
| `armed_runs` | Program invocations by any task while the request was armed |
| `requester_process_runs` | Invocations by threads of the requester process |
| `last_tid`, `last_cpu` | Last such thread and its CPU |
| `recursion_misses` | Invocations the kernel skipped because a BPF program was already running on that CPU |
| `thread_flags` | Requester `thread_info` flags, read through a test run that does not depend on syscall tracepoints |

`armed_runs=0` with `TIF_SYSCALL_TRACEPOINT` set means the program never runs
on any CPU, although the attach succeeded and syscalls should reach it.

## Control runs

```bash
# One vCPU.
QEMU_SMP=1 ./support/stress-system-analysis.sh 6.16 4000
# Four vCPUs, single-threaded TCG.
QEMU_SMP=4 QEMU_EXTRA_ARGS="-accel tcg,thread=single" \
  ./support/stress-system-analysis.sh 6.16 4000
```

Observed with QEMU 10.0 on 6.16 (CI runs 10.2):

| Configuration | Unhandled |
|---|---|
| `-smp 4`, multi-threaded TCG | 4 / 7000 |
| `-smp 1` | 0 / 4000 |
| `-smp 4`, single-threaded TCG | 0 / 16000 |
