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
// v1 reads arguments directly out of pt_regs assuming the SysV AMD64 ABI,
// matching Nicolas' allocation-profiling PoC. aarch64 and honouring the
// per-arg location descriptors from the SDT note are follow-up work.

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

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
    // TODO: pull args via SysV AMD64 regs (rdi, rsi, rdx).
    // TODO: walk user stack via existing native unwinder entry path
    //       (mirror the PoC's PROG_ARRAY-of-uprobe-copies, or reuse the
    //       perf-event entry path with a synthetic record).
    // TODO: emit sample event tagged as heap-alloc with weight + size.
    return 0;
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
    // TODO: pull arg0 (rdi).
    // TODO: lookup (pid, ptr) in alloc->free correlation map;
    //       bail out if not sampled.
    // TODO: emit free event (no stack walk needed for v1).
    return 0;
}

char _license[] SEC("license") = "GPL";
