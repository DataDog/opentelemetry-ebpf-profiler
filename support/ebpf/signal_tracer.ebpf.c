#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

#define SIGABRT 6
#define SIGBUS  7
#define SIGSEGV 11

// signal_deliver_ctx mirrors the tracepoint/signal/signal_deliver format.
typedef struct {
  unsigned char _pad[8]; // common tracepoint header fields
  int sig;
  int err;
  int code;
  unsigned long sa_handler;
  unsigned long sa_flags;
} signal_deliver_ctx;

// tracepoint__signal_deliver fires in the receiving process's context just
// before a signal is delivered. For crash-inducing signals (SIGABRT, SIGBUS,
// SIGSEGV) we capture the full stack trace. Unlike OOM tracing no intermediate
// map is needed: the tracepoint already runs in the victim's context with the
// signal number and si_code available.
SEC("tracepoint/signal/signal_deliver")
int tracepoint__signal_deliver(signal_deliver_ctx *ctx)
{
  int sig = ctx->sig;
  if (sig != SIGABRT && sig != SIGBUS && sig != SIGSEGV) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = (u32)pid_tgid;

  if (pid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  // Pack si_code in the high 32 bits, signal number in the low 32 bits so the
  // Go side can recover both from the single Value field.
  u64 value = ((u64)(u32)ctx->code << 32) | (u32)sig;
  return collect_trace(ctx, TRACE_SIGNAL, pid, tid, ts, value);
}
