# Heap Profiling

## Decisions

- Use `github.com/parca-dev/usdt` for USDT discovery/parsing, but attach with this repo's existing `cilium/ebpf` stack. This avoids adding another eBPF runtime while not hand-rolling `.note.stapsdt` parsing.
- Attach USDTs per process (`UprobeOptions.PID`) rather than globally per binary. Heap profiling is a per-process decision, and PID-scoped links fit the existing process-manager lifecycle and cleanup model.
- Reconcile USDT attachments on every `SynchronizeProcess`, not just on first sight, so probes inside libraries `dlopen`'d after process start are picked up. Diff by file id against the per-PID attached set; cache `.note.stapsdt` parse results per file id.
