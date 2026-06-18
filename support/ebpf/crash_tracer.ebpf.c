#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

#define MAX_THREADS_PER_VICTIM 32

typedef struct {
  u64 ktime;
  u32 threads_captured;
} oom_victim_t;

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u32);
  __type(value, oom_victim_t);
  __uint(max_entries, 64);
} oom_victims SEC(".maps");

typedef struct {
  unsigned char _pad[8];
  int pid;
} mark_victim_ctx;

SEC("tracepoint/oom/mark_victim")
int tracepoint__oom_mark_victim(mark_victim_ctx *ctx)
{
  u32 pid = (u32)ctx->pid;
  if (pid == 0) {
    return 0;
  }
  oom_victim_t victim = {};
  victim.ktime = bpf_ktime_get_ns();
  bpf_map_update_elem(&oom_victims, &pid, &victim, BPF_ANY);
  return 0;
}

// kprobe__do_coredump fires when a fatal signal with default disposition
// causes a core dump. The first argument is a pointer to kernel_siginfo_t;
// si_signo is always its first field.
SEC("kprobe/do_coredump")
int kprobe__do_coredump(struct pt_regs *ctx)
{
  int signo = 0;
  void *siginfo = (void *)ctx->di;
  if (bpf_probe_read_kernel(&signo, sizeof(signo), siginfo)) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = (u32)pid_tgid;
  u64 ts       = bpf_ktime_get_ns();

  return collect_trace(ctx, TRACE_CRASH, pid, tid, ts, (u64)(u32)signo);
}

SEC("kprobe/do_exit")
int kprobe__do_exit(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = (u32)pid_tgid;

  oom_victim_t *victim = bpf_map_lookup_elem(&oom_victims, &pid);
  if (!victim) {
    return 0;
  }

  if (victim->threads_captured >= MAX_THREADS_PER_VICTIM) {
    bpf_map_delete_elem(&oom_victims, &pid);
    return 0;
  }
  victim->threads_captured++;

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_CRASH, pid, tid, ts, 9); // SIGKILL
}
