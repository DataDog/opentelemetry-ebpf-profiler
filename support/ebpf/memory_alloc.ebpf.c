// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// eBPF program for memory allocation profiling - two-tier design:
//   Tier 1: aggregate counters on every alloc/free (bytes, call counts)
//   Tier 2: sampled stack traces (100% >=1MB, 50% 4KB-1MB, configurable for small)

#include "bpfdefs.h"
#include "types.h"
#include "tracemgmt.h"

// Sampling threshold for small allocations (<4KB), 0-100 percent. 0 = disabled.
volatile const u32 memory_alloc_threshold = 0;

struct memory_counters {
  u64 total_allocated_bytes;
  u64 total_freed_bytes;
  u64 malloc_count;
  u64 free_count;
  u64 realloc_count;
  u64 realloc_moved_count;
};

// Correlates realloc entry/return to detect in-place vs moved reallocations.
struct realloc_info {
  u64 old_ptr;
  u64 old_size;
  u64 new_size;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct memory_counters);
} memory_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, struct realloc_info);
} pending_reallocs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u8);
} memory_profiling_pids SEC(".maps");

static inline __attribute__((always_inline)) bool is_pid_tracked() {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u8 *tracked = bpf_map_lookup_elem(&memory_profiling_pids, &pid);
  return tracked != NULL;
}

// Weighted sampling: 100% for >=1MB, 50% for 4KB-1MB, threshold% for <4KB.
static inline EBPF_INLINE bool should_sample_allocation(u64 size) {
  if (size >= (1024 * 1024)) {
    increment_metric(metricID_MemProfLargeAllocsTracked);
    return true;
  }

  if (size >= 4096) {
    u32 random = bpf_get_prandom_u32();
    if ((random & 1) == 0) {
      increment_metric(metricID_MemProfLargeAllocsTracked);
      return true;
    }
    return false;
  }

  if (memory_alloc_threshold == 0) {
    return false;
  }

  u32 random = bpf_get_prandom_u32();
  u32 threshold_scaled = (u32)(((u64)memory_alloc_threshold * 0xFFFFFFFF) / 100);
  return random < threshold_scaled;
}

// Read allocation size from glibc chunk header at ptr-8.
// Used by free and realloc to get the size of an existing allocation.
// The size field has 3 flag bits in the low bits; mask them off.
static inline EBPF_INLINE u64 read_glibc_alloc_size(u64 ptr) {
  if (ptr == 0 || (ptr & 0xF) != 0) {
    increment_metric(metricID_MemProfInvalidSize);
    return 0;
  }

  u64 size_field = 0;
  if (bpf_probe_read_user(&size_field, sizeof(size_field), (void*)(ptr - 8)) < 0) {
    increment_metric(metricID_MemProfMetadataReadFailed);
    return 0;
  }

  u64 size = size_field & ~0x7ULL;
  if (size == 0 || size > (1ULL << 40)) {
    increment_metric(metricID_MemProfInvalidSize);
    return 0;
  }

  return size;
}

// malloc entry: read requested size from rdi (no memory read needed).
SEC("kprobe/uprobe__malloc_entry")
int uprobe__malloc_entry(struct pt_regs *ctx) {
  if (!is_pid_tracked()) {
    return 0;
  }

  u64 size = (u64)PT_REGS_PARM1(ctx);
  if (size == 0) {
    return 0;
  }

  u32 zero = 0;
  struct memory_counters *stats = bpf_map_lookup_elem(&memory_stats, &zero);
  if (stats) {
    stats->total_allocated_bytes += size;
    stats->malloc_count++;
  }

  if (!should_sample_allocation(size)) {
    increment_metric(metricID_MemProfSamplesDropped);
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;
  u64 ts = bpf_ktime_get_ns();
  int ret = collect_trace(ctx, TRACE_ALLOCATION, pid, tid, ts, size);

  if (ret < 0) {
    increment_metric(metricID_MemProfRingBufferFull);
  } else {
    increment_metric(metricID_MemProfSamplesGenerated);
  }

  return 0;
}

// free entry: read freed size from glibc chunk header for Tier 1 accounting.
SEC("kprobe/uprobe__free_entry")
int uprobe__free_entry(struct pt_regs *ctx) {
  if (!is_pid_tracked()) {
    return 0;
  }

  u64 ptr = (u64)PT_REGS_PARM1(ctx);
  if (ptr == 0) {
    return 0;
  }

  u64 size = read_glibc_alloc_size(ptr);
  if (size == 0) {
    return 0;
  }

  u32 zero = 0;
  struct memory_counters *stats = bpf_map_lookup_elem(&memory_stats, &zero);
  if (stats) {
    stats->total_freed_bytes += size;
    stats->free_count++;
  }

  increment_metric(metricID_MemProfFreeTracked);
  return 0;
}

// realloc entry: save old size for return probe to detect in-place vs moved.
SEC("kprobe/uprobe__realloc_entry")
int uprobe__realloc_entry(struct pt_regs *ctx) {
  if (!is_pid_tracked()) {
    return 0;
  }

  u64 old_ptr = (u64)PT_REGS_PARM1(ctx);
  u64 new_size = (u64)PT_REGS_PARM2(ctx);
  u32 tid = (u32)bpf_get_current_pid_tgid();

  if (old_ptr == 0) {
    return 0;
  }

  u64 old_size = read_glibc_alloc_size(old_ptr);
  if (old_size == 0) {
    return 0;
  }

  struct realloc_info info = {
    .old_ptr = old_ptr,
    .old_size = old_size,
    .new_size = new_size,
  };

  bpf_map_update_elem(&pending_reallocs, &tid, &info, BPF_ANY);
  return 0;
}

// realloc return: if new_ptr == old_ptr the allocation is in-place (malloc/free
// hooks did NOT fire); update counters here to avoid double-counting.
SEC("kprobe/uretprobe__realloc_return")
int uretprobe__realloc_return(struct pt_regs *ctx) {
  if (!is_pid_tracked()) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tid = (u32)pid_tgid;

  struct realloc_info *info = bpf_map_lookup_elem(&pending_reallocs, &tid);
  if (!info) {
    increment_metric(metricID_MemProfCorrelationMisses);
    return 0;
  }

  u64 old_ptr = info->old_ptr;
  u64 old_size = info->old_size;
  u64 new_size = info->new_size;
  bpf_map_delete_elem(&pending_reallocs, &tid);

  u64 new_ptr = (u64)PT_REGS_RC(ctx);
  if (new_ptr == 0) {
    return 0;
  }

  u32 zero = 0;
  struct memory_counters *stats = bpf_map_lookup_elem(&memory_stats, &zero);
  if (!stats) {
    return 0;
  }

  stats->realloc_count++;
  increment_metric(metricID_MemProfReallocTotal);

  if (new_ptr == old_ptr) {
    stats->total_allocated_bytes += new_size;
    stats->total_freed_bytes += old_size;
    stats->malloc_count++;
    stats->free_count++;
  } else {
    stats->realloc_moved_count++;
    increment_metric(metricID_MemProfReallocMoved);
  }

  u64 max_size = (new_size > old_size) ? new_size : old_size;
  if (!should_sample_allocation(max_size)) {
    increment_metric(metricID_MemProfSamplesDropped);
    return 0;
  }

  u32 pid = pid_tgid >> 32;
  u64 ts = bpf_ktime_get_ns();
  int ret = collect_trace(ctx, TRACE_ALLOCATION, pid, tid, ts, new_size);

  if (ret < 0) {
    increment_metric(metricID_MemProfRingBufferFull);
  } else {
    increment_metric(metricID_MemProfSamplesGenerated);
  }

  return 0;
}
