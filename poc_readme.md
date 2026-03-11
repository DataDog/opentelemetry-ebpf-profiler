# Memory Allocation Profiling

Uprobes on `malloc`/`free`/`realloc` in glibc. Two-tier design:

- **Tier 1** — aggregate counters on every alloc/free (bytes allocated, freed, call counts). Per-CPU array map, no contention.
- **Tier 2** — sampled stack traces for hotspot identification. Weighted: 100% for ≥1MB, 50% for 4KB–1MB, configurable % for small allocs.

Traces are emitted as `TRACE_ALLOCATION` origin and reported as an `alloc_space / bytes` OTLP profile with `profile.type = memory`.

---

## Two Approaches for malloc Size

### Approach A: uprobe on entry (current)

Read `rdi` / `PT_REGS_PARM1(ctx)` at the call site.

```
uprobe__malloc_entry(ctx):
    size = PT_REGS_PARM1(ctx)   // rdi = first arg, free
```

**Pros:** exact requested size, zero memory reads, cheapest possible probe.
**Cons:** counts failed allocations (malloc returned NULL) in Tier 1.

---

### Approach B: uretprobe + glibc chunk header

After malloc returns, read the chunk header at `ret_ptr - 8`. The glibc chunk layout:

```
[prev_size: 8B][size_field: 8B][user data ...]
                                ^ ret_ptr
               ^ ret_ptr - 8 (what we read)
```

The size field has 3 flag bits in the low bits (PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA). Mask them off: `size = size_field & ~0x7`.

```
uretprobe__malloc_return(ctx):
    ret_ptr = PT_REGS_RC(ctx)
    size_field = *(u64 *)(ret_ptr - 8)   // bpf_probe_read_user
    size = size_field & ~0x7
```

**Pros:** only successful allocations counted, size available on return.
**Cons:** `bpf_probe_read_user` is expensive (page fault risk, cache miss). Size is the **chunk** size, not the requested size — glibc rounds up and adds header overhead, so small allocs are inflated:

| malloc(n)  | chunk size | inflation |
|------------|-----------|-----------|
| 1–24 bytes | 32 bytes  | up to 32× |
| 25–40      | 48 bytes  | ~2×       |
| 1 MB       | ~1 MB     | ~0%       |

---

## realloc / free

Both still use the glibc header read (`read_glibc_alloc_size`) to get the old allocation size:

- `free`: needs freed bytes for Tier 1 accounting.
- `realloc_entry`: needs old size to detect in-place vs moved (if `new_ptr == old_ptr`, malloc/free hooks did not fire — must update counters here to avoid double-counting).

---

## PID Filtering

Only tracked PIDs are profiled. Attach via `AttachMemoryProfilingForPID(pid)`, which inserts the PID into the `memory_profiling_pids` BPF hash map. `SetPIDNewCallback` hooks new process discovery to attach probes automatically.

---

## Enabling

```go
collector.WithMemoryProfiling(true, thresholdPercent)
collector.WithTracerAccess(func(t *tracer.Tracer) {
    for _, pid := range t.GetTrackedPIDs() {
        t.AttachMemoryProfilingForPID(pid)
    }
    t.SetPIDNewCallback(func(pid int) {
        t.AttachMemoryProfilingForPID(pid)
    })
})
```
