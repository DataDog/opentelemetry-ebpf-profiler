# Heap Profiling

## Decisions

- Use `github.com/parca-dev/usdt` for USDT discovery/parsing, but attach with this repo's existing `cilium/ebpf` stack. This avoids adding another eBPF runtime while not hand-rolling `.note.stapsdt` parsing.
- Attach USDTs per process (`UprobeOptions.PID`) rather than globally per binary. Heap profiling is a per-process decision, and PID-scoped links fit the existing process-manager lifecycle and cleanup model.
- Reconcile USDT attachments on every `SynchronizeProcess`, not just on first sight, so probes inside libraries `dlopen`'d after process start are picked up. Diff by file id against the per-PID attached set; cache `.note.stapsdt` parse results per file id.
- Export allocation events as an OTLP profile with `sample_type = alloc_space/bytes`. Each sample's value is the allocation weight in bytes and the stack is the allocation call stack.
- Live (in-use) heap profiling is a separate opt-in on top of heap profiling: `-live-heap-profiling` (collector: `live_heap_profiling`), requiring `-heap-profiling`. Free events are only consumed by live-heap tracking — plain allocation profiling never needs them — so the `uprobe_heap_free` program is not even loaded (and the `free` USDT never attached) unless live heap is enabled. This keeps the default heap-profiling overhead to the alloc probe only (cf. ddprof, where deallocation tracking is likewise gated behind `kTrackDeallocations`).
- 
