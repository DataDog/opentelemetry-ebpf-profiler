#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// oom_victim_t holds the ktime when the victim was marked by the OOM killer.
typedef struct {
  u64 ktime;
} oom_victim_t;

// oom_victims maps victim pid -> context for the window between mark_victim
// and get_signal. LRU handles stale entries if get_signal never fires.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u32);
  __type(value, oom_victim_t);
  __uint(max_entries, 64);
} oom_victims SEC(".maps");

// mark_victim_ctx mirrors the tracepoint/oom/mark_victim format.
typedef struct {
  unsigned char _pad[8]; // common tracepoint header fields
  int pid;
} mark_victim_ctx;

// tracepoint__oom_mark_victim fires when the OOM killer selects a victim.
// Records the victim PID so kprobe__get_signal can filter for it.
SEC("tracepoint/oom/mark_victim")
int tracepoint__oom_mark_victim(mark_victim_ctx *ctx)
{
  u32 pid = (u32)ctx->pid;
  if (pid == 0) {
    return 0;
  }
  oom_victim_t victim = { .ktime = bpf_ktime_get_ns() };
  bpf_map_update_elem(&oom_victims, &pid, &victim, BPF_ANY);
  return 0;
}

// kprobe__get_signal fires when a process dequeues a pending signal, in the
// victim's own execution context. If the PID is in oom_victims it's receiving
// its OOM SIGKILL — collect the stack trace.
SEC("kprobe/get_signal")
int kprobe__get_signal(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = (u32)pid_tgid;

  if (!bpf_map_lookup_elem(&oom_victims, &pid)) {
    return 0;
  }

  // Only capture on the main thread (TID == PID). In Go+Python mixed
  // processes the Go runtime creates extra OS threads; the main Python
  // thread is the one executing user code and has TID == PID.
  if (tid != pid) {
    return 0;
  }

  bpf_map_delete_elem(&oom_victims, &pid);

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_OOM, pid, tid, ts, 0);
}
