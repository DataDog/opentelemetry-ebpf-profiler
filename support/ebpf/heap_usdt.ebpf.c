// SPDX-License-Identifier: Apache-2.0
//
// USDT (uprobe) handlers for heap profiling.
//
// Provider:  see usdt.ProbeProvider on the Go side. The current upstream
//            sampler library (libdd-heap-sampler) emits these notes with
//            provider "ddheap"; this is expected to track the eventual
//            OTel-standard heap-profiling provider name once defined.
//
// Probes:    alloc(void *user, uint64_t size, uint64_t weight)
//            free(void *ptr)
//
// These programs are attached PID-scoped from userspace by the `usdt`
// package once per (process, probe site) discovered via .note.stapsdt
// scanning. See usdt/wiring.go for the attachment flow.
//
// v1 reads arguments directly out of pt_regs using the architecture-specific
// register layout defined in kernel.h, matching the fixed tracepoint signatures
// emitted by the sampler. Honouring per-arg location descriptors from the SDT
// note is follow-up work.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE u64 usdt_arg0(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->di;
#elif defined(__aarch64__)
  return ctx->regs[0];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 usdt_arg1(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->si;
#elif defined(__aarch64__)
  return ctx->regs[1];
#else
  #error "Unsupported architecture"
#endif
}

static EBPF_INLINE u64 usdt_arg2(struct pt_regs *ctx)
{
#if defined(__x86_64__)
  return ctx->dx;
#elif defined(__aarch64__)
  return ctx->regs[2];
#else
  #error "Unsupported architecture"
#endif
}

// ─────────────────────────────────────────────────────────────────────────
// heap:alloc(user, size, weight)
//
//   arg0 = user-visible allocation pointer
//   arg1 = allocation size in bytes
//   arg2 = weight (unbiased size estimator = nsamples * interval)
// ─────────────────────────────────────────────────────────────────────────
SEC("uprobe/heap_alloc")
int uprobe_heap_alloc(struct pt_regs *ctx)
{
  u64 user   = usdt_arg0(ctx);
  u64 size   = usdt_arg1(ctx);
  u64 weight = usdt_arg2(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid;

  DEBUG_PRINT("heap_usdt: alloc pid=%llu ptr=%llx", pid_tgid >> 32, user);
  DEBUG_PRINT("heap_usdt: alloc size=%llu weight=%llu", size, weight);

  return collect_trace(ctx, TRACE_HEAP_ALLOC, pid, tid, bpf_ktime_get_ns(), weight);
}

// ─────────────────────────────────────────────────────────────────────────
// heap:free(ptr)
//
//   arg0 = pointer being freed
//
// Fast path: if the pointer is not in our sampled-allocation map, return
// immediately without a stack walk. Hot path on every free, must stay cheap.
// ─────────────────────────────────────────────────────────────────────────
SEC("uprobe/heap_free")
int uprobe_heap_free(struct pt_regs *ctx)
{
  u64 ptr = usdt_arg0(ctx);

  DEBUG_PRINT("heap_usdt: free pid=%llu ptr=%llx", bpf_get_current_pid_tgid() >> 32, ptr);
  // TODO: lookup (pid, ptr) in alloc->free correlation map;
  //       bail out if not sampled.
  // TODO: emit free event (no stack walk needed for v1).
  return 0;
}
