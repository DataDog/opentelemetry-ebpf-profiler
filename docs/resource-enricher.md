# Per-process metadata collection: three phases, two extension points

Two features want to contribute OTel attributes per profiled process:

1. **OTel process context** (OTEP 4719): an application publishes a memory region (`OTEL_CTX`) with
  resource attributes it wants on its telemetry. It may publish at any point in its life, and
   republish.
2. **Runtime name/version** (`process.runtime.name` / `process.runtime.version`): derived from the
  interpreter the profiler detects in the process.

Neither fits `process.MetaEnricher`, the existing extension point for per-process metadata. This
document says why, and what the second one is.

## Three phases


|        | **1. Identity**                          | **2. Initial enrichment**                                        | **3. Late enrichment**                                                           |
| ------ | ---------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| What   | PID, executable path, container ID       | env vars, anything an embedder needs from procfs                 | process context, runtime info                                                    |
| When   | process first observed, or exec detected | same, right after phase 1                                        | end of every `SynchronizeProcess`, after the mapping pass and interpreter attach |
| Writes | fills `Meta`                             | mutates `*Meta` freely, as it is privately owned until published | none, returns a freshly built value                                              |
| Output | `ResourceKey` fields                     | `Meta` fields, incl. `ExtraMeta`                                 | immutable `*pcommon.Resource` -> resource attributes                             |
| API    | none                                     | `process.MetaEnricher` (unchanged)                               | `procmeta.ResourceEnricher` (new)                                                |
| Home   | head of `Process.GetProcessMeta`         | enricher loop in `Process.GetProcessMeta`                        | `processmanager`                                                                 |




### Identity keys, enrichment decorates

The phase-1 fields are exactly `samples.ResourceKey`, the key samples are aggregated under:

```go
type ResourceKey struct {
	ContainerID    libpf.String // phase 1
	ExecutablePath libpf.String // phase 1
	APMServiceName string       // from eBPF, outside all three phases
	PID            int64        // phase 1
}
```

Phase 1 identifies the bucket; phases 2 and 3 decorate a bucket it already picked. Hence:

- Phase 1 is neither an extension point nor configurable. A hook able to change it would re-bucket
samples.
- Phase 3 can be applied retroactively only because the key is stable within a reporting
interval for a process that does not exec.



## Why phase 3 cannot be MetaEnricher

```go
type MetaEnricher interface { EnrichMeta(procBase string, meta *Meta) }
```

- **It runs too early.** `EnrichMeta` is called before the mapping pass and before interpreters
attach, so a region published 200 ms after startup does not exist yet and the interpreter
identifying the runtime is not attached yet.
- **There is no "again" in the contract.** `Meta` is published once, then read by the
trace-processing goroutine. Writing to it later needs copy-on-write discipline, ownership rules,
and a subscription mechanism to declare when an enricher wants re-running, all enforced by
documentation only.
- **The output is different.** Both features produce typed resource attributes, not the
`map[string]string` sample attributes `ExtraMeta` carries. Process context holds arbitrary
`AnyValue`s, which `ExtraMeta` would flatten to strings for a consumer to re-inflate.
- **Different inputs are needed.** Phase 3 needs the process's mappings, its attached
`interpreter.Instance`s, remote memory reads, and per-PID state (last `PublishedAtNs`, a fill-once
marker).



## The phase-3 interface

```go
type ResourceEnricher interface {
	// Called once at registration: declares which mappings the enricher wants.
	ResourceConfig() ResourceConfig

	// Called every synchronization. changed=false keeps the stored contribution,
	// (nil, true) withdraws it.
	EnrichResource(req *ResourceRequest) (res *pcommon.Resource, changed bool)
}
```

`ResourceRequest` carries the process, the mappings it asked for, the attached interpreter
instances, and a per-PID state slot the manager owns and drops when the process exits. It never
sees the published `Meta`, so immutability is by construction rather than by convention. What
follows:

- No copy-on-write helpers, no ownership flags, no "must not mutate a published Meta" contract.
- The merged resource lives in `processInfo`.
- `MetaEnricher` keeps its shape and its built-ins.

The manager keeps one contribution slot per enricher and publishes their merge, so an enricher
builds only its own resource and never sees, or has to merge with, another's. On key collisions the
later enricher wins. A slot holds what the enricher last returned until it reports a change, so what
is reported for a process is the merge of every enricher's latest version, and a contribution that
arrives mid-interval is merged, republished, and applied to the samples already buffered for that
PID in the current reporting interval.

The manager, not the enrichers, handles exec: it clears the stored contribution and state, making a
first call and a post-exec call indistinguishable, which is exactly what an enricher should do about
an exec.

Two interfaces are more surface than one, and an extension wanting both procfs access at phase 2 and
resource attributes implements both. The rejected alternative, one interface over a shared mutable
`Meta`, buys the single interface at the price of a mutation contract that only documentation
enforces, on a struct the reporting path reads concurrently.

## Known gaps

Neither is introduced here; both are clearer in the three-phase framing.

- **A phase-1 field is written from phase 2.** `NewSelfContainerIDEnricher` is a registered
`MetaEnricher` filling `Meta.ContainerID` when cgroup parsing yields nothing, so a `ResourceKey`
component is set by a configurable, order-dependent hook. It belongs in phase 1. Nothing stops a
user `MetaEnricher` from overwriting identity fields either; preventing that means splitting
`Meta` into an immutable identity part and a writable enrichment part.
- **Not every exec is detected, and phase 2 is the only phase with no recovery.** The trigger is
`exe != info.meta.Executable`, so a re-exec of the same path is invisible, and detecting it needs
a `sched_process_exec` tracepoint. Phase 1 self-corrects (a same-path re-exec has unchanged
identity by definition) and phase 3 re-asks every sync, but phase 2 runs once and keeps stale data
for the life of the process.



## Where it lives

- `procmeta/procmeta.go`: `ResourceEnricher`, `ResourceRequest`, `ResourceConfig`, `MergeResources`,
and the base resource read from `OTEL_SERVICE_NAME` / `OTEL_RESOURCE_ATTRIBUTES`.
- `processmanager/`: drives phase 3 and publishes the merged resource per PID.
- `procmeta/processcontext/`, `procmeta/runtimeinfo/`: the two built-in phase-3 enrichers.
- `reporter/`: `TraceEventMeta.Resource` → `setResourceAttributes`, with a late-resolved resource
backfilled onto samples already buffered for that PID in the current interval.

Merge precedence is registration order, later wins: environment base, runtime info, process context,
user enrichers. So what an application publishes beats what the profiler inferred, and both beat
what its environment declared.
