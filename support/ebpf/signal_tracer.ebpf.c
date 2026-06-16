#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

#define SIGABRT 6
#define SIGBUS  7
#define SIGSEGV 11

// signal_generate_ctx mirrors tracepoint/signal/signal_generate.
// Field offsets verified from /sys/kernel/tracing/events/signal/signal_generate/format.
typedef struct {
  unsigned char _pad[8]; // common tracepoint header
  int sig;               // offset 8
  int errno;             // offset 12
  int code;              // offset 16
  char comm[16];         // offset 20
  int pid;               // offset 36  (task_pid_vnr of target task)
  int group;             // offset 40
  int result;            // offset 44  (0 = TRACE_SIGNAL_DELIVERED)
} signal_generate_ctx;

// signal_pending maps the sending/victim TGID to the packed signal info.
// For fault-induced and self-sent signals the tracepoint fires in the victim's
// own context, so bpf_get_current_pid_tgid()>>32 equals the victim's global TGID
// and matches the lookup key used in kprobe__signal_deliver below.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u32);      // global (initial-ns) TGID of victim
  __type(value, u64);    // packed: (si_code << 32) | signo
  __uint(max_entries, 64);
} signal_pending SEC(".maps");

// tracepoint__signal_generate fires when a crash-inducing signal is queued.
// It only writes to the map — no pt_regs access needed — and is safe to use
// from a tracepoint context.
//
// For SIGSEGV/SIGBUS (CPU faults) and SIGABRT (via abort()/raise()), this
// tracepoint fires in the victim process's own context, so the current TGID
// IS the victim's TGID.
SEC("tracepoint/signal/signal_generate")
int tracepoint__signal_generate(signal_generate_ctx *ctx)
{
  int sig = ctx->sig;
  if (sig != SIGABRT && sig != SIGBUS && sig != SIGSEGV) {
    return 0;
  }
  if (ctx->result != 0) { // 0 = TRACE_SIGNAL_DELIVERED
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  if (pid == 0) {
    return 0;
  }

  u64 value = ((u64)(u32)ctx->code << 32) | (u32)sig;
  bpf_map_update_elem(&signal_pending, &pid, &value, BPF_ANY);
  return 0;
}

// kprobe__signal_deliver fires in the victim's execution context when it
// dequeues a pending signal — the same hook used by OOM tracing. Because
// this is a kprobe, ctx IS struct pt_regs * and collect_trace() works
// without any workaround.
SEC("kprobe/get_signal")
int kprobe__signal_deliver(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = (u32)pid_tgid;

  if (!bpf_map_lookup_elem(&signal_pending, &pid)) {
    return 0;
  }

  // Read and remove the pending entry atomically-ish. The value carries
  // both the signal number and si_code packed by tracepoint__signal_generate.
  u64 *valp = bpf_map_lookup_elem(&signal_pending, &pid);
  if (!valp) {
    return 0;
  }
  u64 value = *valp;
  bpf_map_delete_elem(&signal_pending, &pid);

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_SIGNAL, pid, tid, ts, value);
}
