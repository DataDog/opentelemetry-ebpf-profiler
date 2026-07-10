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

// ─────────────────────────────────────────────────────────────────────────
// heap_live_pids: set of PIDs that have the ddheap:free probe attached.
// Only these PIDs get entries in heap_alloc_live. Written by userspace
// during USDT reconcile; read by uprobe_heap_alloc.
// ─────────────────────────────────────────────────────────────────────────
struct heap_live_pids_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);  // pid
  __type(value, u8); // dummy
} heap_live_pids SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_pid_alloc_count: per-PID count of entries currently in
// heap_alloc_live. Used to enforce per-process caps.
// ─────────────────────────────────────────────────────────────────────────
struct heap_pid_alloc_count_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);  // same as heap_live_pids
  __type(key, u32);           // pid
  __type(value, u32);         // current count
} heap_pid_alloc_count SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_pid_alloc_limit: single-entry array holding the per-PID cap.
// Written by userspace at startup. If 0, per-PID limiting is disabled.
// ─────────────────────────────────────────────────────────────────────────
struct heap_pid_alloc_limit_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);    // always 0
  __type(value, u32);  // the limit
} heap_pid_alloc_limit SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// heap_alloc_live: correlation map for live-heap tracking.
//
// Key:   (pid, ptr) — uniquely identifies a sampled allocation.
// Value: weight     — the unbiased weight passed by the sampler.
//
// Written by uprobe_heap_alloc (only for PIDs in heap_live_pids),
// read+deleted by uprobe_heap_free.
// Entries for dead PIDs are batch-deleted from userspace on process exit.
// ─────────────────────────────────────────────────────────────────────────
typedef struct {
  u32 pid;
  u32 _pad;
  u64 ptr;
} HeapAllocKey;

typedef struct {
  u64 weight;
} HeapAllocVal;

struct heap_alloc_live_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, HeapAllocKey);
  __type(value, HeapAllocVal);
} heap_alloc_live SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────
// USDT argument helpers
// ─────────────────────────────────────────────────────────────────────────

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

  // Only record in the live-heap correlation map if this PID has the
  // free probe attached (i.e., is in heap_live_pids). Without the free
  // probe, entries would accumulate forever and starve the map.
  //
  // live_tracked gates whether we set trace->ptr below. If the eBPF map
  // insert fails (map full or per-PID cap), we zero ptr so userspace won't
  // add this allocation to the live-heap Tracker — since the free probe
  // won't be able to find it either, it would never be removed.
  bool live_tracked = false;
  if (bpf_map_lookup_elem(&heap_live_pids, &pid)) {
    // Check per-PID limit before attempting the insert.
    u32 zero_key = 0;
    u32 *limit = bpf_map_lookup_elem(&heap_pid_alloc_limit, &zero_key);
    u32 *count = bpf_map_lookup_elem(&heap_pid_alloc_count, &pid);

    if (limit && *limit > 0 && count && *count >= *limit) {
      increment_metric(metricID_HeapPerPIDLimitHit);
    } else {
      HeapAllocKey key = {.pid = pid, .ptr = user};
      HeapAllocVal val = {.weight = weight};
      if (bpf_map_update_elem(&heap_alloc_live, &key, &val, BPF_NOEXIST) < 0) {
        // Could be map full or duplicate ptr (realloc without free — unusual).
        // Try overwrite for the duplicate case.
        if (bpf_map_update_elem(&heap_alloc_live, &key, &val, BPF_ANY) < 0) {
          increment_metric(metricID_HeapLiveMapFull);
        } else {
          live_tracked = true;
        }
      } else {
        live_tracked = true;
      }

      // Update the per-PID count on successful insert.
      if (live_tracked) {
        u32 new_count = count ? (*count + 1) : 1;
        bpf_map_update_elem(&heap_pid_alloc_count, &pid, &new_count, BPF_ANY);
      }
    }
  }

  // We can't use collect_trace() directly because it calls
  // get_pristine_per_cpu_record() which would zero our ptr field, and then
  // tail-calls without returning. Instead we call collect_trace first (which
  // sets up the trace and triggers unwinding) — but we need ptr to be set
  // on the trace BEFORE send_trace fires at the end of the unwind chain.
  //
  // Since get_pristine_per_cpu_record zeros the whole record and collect_trace
  // only sets specific fields, we set trace->ptr right after collect_trace
  // initializes the trace. We achieve this by inlining the setup:
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace  = &record->trace;
  trace->origin = TRACE_HEAP_ALLOC;
  trace->pid    = pid;
  trace->tid    = tid;
  trace->ktime  = bpf_ktime_get_ns();
  trace->value  = weight;
  trace->ptr    = live_tracked ? user : 0;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  push_kernel_frames(ctx, trace);

  if (!pid_information_exists(pid)) {
    u64 pid_tgid_val = (u64)pid << 32 | tid;
    if (report_pid(ctx, pid_tgid_val, RATELIMIT_ACTION_DEFAULT)) {
      increment_metric(metricID_NumProcNew);
    }
    return 0;
  }

  int unwinder           = PROG_UNWIND_STOP;
  bool has_usermode_regs = false;
  ErrorCode error        = get_usermode_regs(ctx, &record->state, &has_usermode_regs);
  if (error || !has_usermode_regs) {
    goto exit;
  }

  error = get_next_unwinder_after_native_frame(record, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in uprobe_heap_alloc", unwinder);
  return -1;
}

// ─────────────────────────────────────────────────────────────────────────
// heap:free(ptr)
//
//   arg0 = pointer being freed
//
// Fast path: if the pointer is not in our sampled-allocation map, return
// immediately without any work. Hot path on every free, must stay cheap.
// ─────────────────────────────────────────────────────────────────────────
SEC("uprobe/heap_free")
int uprobe_heap_free(struct pt_regs *ctx)
{
  u64 ptr = usdt_arg0(ctx);

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid;

  // Fast-path: was this pointer sampled?
  HeapAllocKey key  = {.pid = pid, .ptr = ptr};
  HeapAllocVal *val = bpf_map_lookup_elem(&heap_alloc_live, &key);
  if (!val) {
    // Not a sampled allocation — nothing to do.
    return 0;
  }

  u64 weight = val->weight;

  // Remove from the live map before emitting the event.
  bpf_map_delete_elem(&heap_alloc_live, &key);

  // Decrement the per-PID count.
  u32 *count = bpf_map_lookup_elem(&heap_pid_alloc_count, &pid);
  if (count && *count > 0) {
    u32 new_count = *count - 1;
    bpf_map_update_elem(&heap_pid_alloc_count, &pid, &new_count, BPF_ANY);
  }

  DEBUG_PRINT("heap_usdt: free pid=%u ptr=%llx weight=%llu", pid, ptr, weight);

  // Emit a minimal free event to userspace via the trace_events ringbuf.
  // No stack walk — we only need to identify which allocation was freed.
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace             = &record->trace;
  trace->origin            = TRACE_HEAP_FREE;
  trace->pid               = pid;
  trace->tid               = tid;
  trace->ktime             = bpf_ktime_get_ns();
  trace->value             = weight;
  trace->ptr               = ptr;
  trace->num_frames        = 0;
  trace->num_kernel_frames = 0;
  trace->frame_data_len    = 0;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  send_trace(ctx, trace);
  return 0;
}
