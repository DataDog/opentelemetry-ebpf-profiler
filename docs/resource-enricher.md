# Adapt process context (and runtime info) to the MetaEnricher API

**Status: implemented** in `cb68bcd9..5a4f360f`. This document describes the design as built;
where the implementation departed from the original plan, the deviation is called out inline.

`file.go:NNN` references throughout point at the **pre-change** tree (`8a28e6cd`), since they were
written to say where the work had to go. Use them to read the diffs, not the current code.

## Context

Upstream landed `process.MetaEnricher` (PR #1500, commit `f44eb782`, already at HEAD) as *the*
extension point for per-process metadata:

```go
type MetaEnricher interface { EnrichMeta(procBase string, meta *Meta) }
```

An enricher gets a `/proc/<pid>/` path, runs when the process is first observed (and again if the
executable changes), and writes into `Meta` — typed fields (`EnvVariables`, `ContainerID`) or the
generic `ExtraMeta map[libpf.String]string`, which reaches the wire as *sample* attributes via
`SampleAttrProducer`.

Two features do not fit and are therefore hard-wired into `processmanager.SynchronizeProcess`:

1. **OTel process context** (`process/processcontext`, OTEP 4719). Needs the `OTEL_CTX` mapping
   address found during the mapping pass, remote memory access, `OTEL_SERVICE_NAME` /
   `OTEL_RESOURCE_ATTRIBUTES`, per-PID state (`PublishedAtNs`), re-evaluation on every resync (the
   mapping can appear late — that is what the prctl tracepoint exists for), and it produces a typed
   OTel **resource**, not string sample attributes.
2. **Runtime name/version** (upstream PR
   [#1716](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/1716), not on this
   branch). Needs the attached `interpreter.Instance`s plus the executable's on-disk identity,
   resolves late (interpreters attach after the first samples), is fill-once, and also produces
   resource attributes.

Each currently carves its own path through `SynchronizeProcess` → `processInfo` → `metaForPID` →
`TraceEventMeta` → `ResourceToProfiles` → `setResourceAttributes`, duplicating the same
"resolve late, publish a snapshot, backfill onto already-buffered samples" pattern — PR 1716 and this
branch collide textually on five of the same files.

**Outcome wanted:** one extension mechanism for both, with the bespoke code out of the process
manager, and the same capabilities available to out-of-tree embedders (the Datadog agent) through
`collector`.

### The organising idea: two enrichment phases

What blocks both features is that they are *late* and *additive*, while `MetaEnricher` is defined
around metadata read once, up front. Rather than stretching one interface to cover both — a shared
mutable `Meta` written repeatedly, needing copy-on-write discipline, ownership flags and a trigger
subscription mechanism — the plan splits enrichment by its actual mutation semantics:

| | **Initial enrichment** | **Late enrichment** |
|---|---|---|
| When | process first observed, or exec detected | end of every `SynchronizeProcess`, after the mapping pass and interpreter attach |
| Subject | a `Meta` being built from scratch, privately owned by the caller | a `Meta` already published and read concurrently by `HandleTrace` |
| Writes | free — mutate `*Meta` directly | none; returns a freshly built value |
| Output | `Meta` fields, incl. `ExtraMeta` → sample attributes | an immutable `*pcommon.Resource` → resource attributes |
| Interface | `process.MetaEnricher` (upstream's, kept) | `procmeta.ResourceEnricher` (new) |

Because the phases never share a mutable object, immutability is by construction rather than by
convention. Consequences that fall out:

- No copy-on-write helpers, no ownership flags, no "must not mutate a published Meta" contract.
- No trigger-subscription mechanism — implementing an interface *is* the declaration.
- `process.Meta` needs no `Resource` field, so package `process` gains **no new dependency** (no
  `pcommon`); the merged resource lives in `processInfo`, exactly where `processcontext.Info` lives
  today, so the reporter side is untouched.
- Resource enrichment has a single call site with mappings and interpreters already available, so
  nothing is called twice per observation.
- Upstream's `MetaEnricher` keeps its shape and its built-in implementations stay in `process`; only
  the new capability needs a new package.

Also decided: the late-phase request hands over the process's attached interpreter instances **as the
live map the manager already holds** (no copy, no conversion), which is why that interface cannot
live in `process` — it must import `interpreter`, and `interpreter` → `process` is the existing
direction. Runtime info is implemented and emitted at resource level (upstream has agreed resource
level is acceptable), with all runtime-specific policy inside the enricher.

## Design

### 1. Initial enrichment — `process.MetaEnricher`, essentially unchanged

Only the argument list changes, from a bare `procBase` to a request struct:

```go
package process

// Reason says why metadata is being collected.
type Reason uint8

const (
    ReasonFirstSeen Reason = iota // process observed for the first time
    ReasonExec                    // the process's executable changed
)

// MetaRequest describes the process whose metadata is being collected.
type MetaRequest struct {
    // Process gives access to remote memory, mappings and the executable.
    Process Process
    // ProcBase is "/proc/<pid>/" (with trailing slash); empty for coredumps.
    ProcBase string
    // Reason is why metadata is being collected.
    Reason Reason
}

// MetaEnricher is called when a process's metadata is collected: once when the
// process is first observed, and again if its executable changes. The Meta is
// freshly built and owned by the caller, so implementations may write it freely.
// The call happens while the process is still alive, so short-lived process data
// is reliably captured.
type MetaEnricher interface {
    EnrichMeta(req *MetaRequest, meta *Meta)
}

type MetaEnricherFunc func(*MetaRequest, *Meta)
```

`Meta` itself is unchanged: `Executable`, `EnvVariables`, `ContainerID`, `ExtraMeta`. The two
built-ins (`NewEnvVarsEnricher`, `NewSelfContainerIDEnricher`) stay in `process/process.go` and only
have their signature updated — no cycle, no helpers to export, no moves. Direct `ExtraMeta` writes
stay legal, because the `Meta` is private until published.

### 2. Late enrichment — `procmeta.ResourceEnricher` (new)

New package `procmeta` (`go.opentelemetry.io/ebpf-profiler/procmeta`), which may import
`interpreter` and `pcommon`:

```go
package procmeta

// ResourceConfig declares what a ResourceEnricher needs. The zero value asks for
// nothing. New requirements are added as new fields, so existing implementations
// keep compiling.
type ResourceConfig struct {
    // EnvVars names the environment variables to make available in
    // ResourceRequest.EnvVars. They are captured even when the user did not ask
    // for them to be reported, and are not reported unless the user did.
    EnvVars []string
    // WantMapping selects the mappings delivered in ResourceRequest.Mappings.
    // nil means the enricher gets none. Called for every mapping of every
    // synchronized process, so it must be cheap: no allocation, no syscalls.
    WantMapping func(m *process.RawMapping) bool
}

// ResourceRequest describes a process and what the manager observed for it this
// round. Valid only for the duration of the EnrichResource call: enrichers must
// not retain it or anything reachable from it.
type ResourceRequest struct {
    // Process gives access to remote memory, mappings and the executable.
    Process process.Process
    // ProcBase is "/proc/<pid>/" (with trailing slash); empty for coredumps.
    ProcBase string
    // Meta is the process metadata collected by process.MetaEnricher. Read-only:
    // it is a snapshot of already-published metadata whose maps are shared with
    // the code reporting profiles for this process.
    Meta *process.Meta
    // NewProcessOrExec is true on the first round for a process and on the round
    // that follows an exec: previously derived state should be discarded.
    NewProcessOrExec bool
    // EnvVars holds the values of the variables named in ResourceConfig.EnvVars,
    // as captured during the initial phase.
    EnvVars map[libpf.String]libpf.String
    // Mappings holds the mappings selected by ResourceConfig.WantMapping, in
    // /proc/<pid>/maps order.
    Mappings []process.RawMapping
    // Interpreters are the interpreter instances attached to the process, keyed
    // by the on-disk identity of the DSO each was detected in. Nil until one has
    // attached. Read-only: enrichers must not insert, delete, or drive the
    // instances (Attach/Detach/Synchronize* belong to the process manager).
    Interpreters map[util.OnDiskFileIdentifier]interpreter.Instance
    // MainExecutableID is the on-disk identity of the process's own executable,
    // or the zero value when it was not observed this round.
    MainExecutableID util.OnDiskFileIdentifier
    // State points at the manager's per-process storage slot for this enricher:
    // *State is what the enricher stored on its previous call for this PID, nil
    // on the first. Keep per-process state here rather than in enricher-owned
    // maps: the slot is dropped when the process exits, and Close() is called on
    // it if it implements io.Closer.
    State *any
}

// ResourceEnricher contributes OTel resource attributes for a process. Unlike
// MetaEnricher it is called on every mapping resynchronization, so it can supply
// attributes that only become available after the process is first observed — a
// memory region published later, an interpreter attaching.
type ResourceEnricher interface {
    // ResourceConfig is called once, when the enricher is registered.
    ResourceConfig() ResourceConfig

    // EnrichResource returns a freshly built resource, which the caller treats
    // as immutable, or changed=false to keep the enricher's previous
    // contribution. Returning (nil, true) withdraws it.
    EnrichResource(req *ResourceRequest) (res *pcommon.Resource, changed bool)
}

// MergeResources combines per-enricher contributions into a single resource.
// Contributions are applied in order, so later ones win on key collisions.
// Returns nil if every contribution is nil, and shares the single non-nil
// contribution as-is: contributions are immutable, so copying is unnecessary.
func MergeResources(contributions []*pcommon.Resource) *pcommon.Resource
```

`MergeResources` was not in the original plan, which left merging as unspecified process-manager
logic. It lives here because it defines what "later enrichers win" means, and because it is worth
testing on its own — in particular that it never mutates the contributions, which the manager
retains and re-merges across synchronizations.

`(value, changed)` is deliberately the shape `processcontext.Resolve` already returns, so the
existing state machine maps onto it directly.

### 3. Who drives what

Driving moves out of `Process.GetProcessMeta` into `processmanager`, the only component that knows
the mapping pass, the interpreter map, and the per-PID state:

- `Process.GetProcessMeta()` drops its `[]MetaEnricher` argument and returns only procfs basics
  (`Executable`, `ContainerID`). `process/coredump.go:206` keeps returning `Meta{}`.
- `Process` gains `ProcBase() string` (`systemProcess` returns `sp.procBase`, `CoredumpProcess`
  returns `""`), so the manager can fill the requests without re-deriving it.

Call sites, both **without `pm.mu` held** (arbitrary callback code plus /proc reads):

| Phase | Site | Notes |
|---|---|---|
| Initial | `getOrCreateProcessInfo` (`processinfo.go:126`) and the `updateProcessMeta` branch of `SynchronizeProcess` (`:820-824`) | exactly today's two `readProcessMeta` calls; `Reason` distinguishes them |
| Late | end of `SynchronizeProcess`, replacing the `processcontext.Resolve` block (`:826-828`) | mappings, interpreters and `MainExecutableID` are all known by then |

Per-process late-phase storage lives in `processInfo`, so it is covered by `pm.mu` and freed with the
`processInfo`:

```go
type processInfo struct {
    meta            process.Meta
    resource        *pcommon.Resource   // merged contributions, replaces processContext
    contributions   []*pcommon.Resource // one slot per resource enricher
    enricherState   []any               // one slot per resource enricher
    internalEnvVars map[libpf.String]libpf.String // values named by ResourceConfig.EnvVars
    mappings        []Mapping
    libcInfo        *libc.LibcInfo
}
```

The env-var field keeps its existing name rather than being renamed to `envVars`: the mechanism is
unchanged, only its input is — the names now come from what the enrichers declared instead of a
hardcoded list. `ProcessManager.internalEnvVars` survives for the same reason.

Each round: run every resource enricher; replace the slots that reported `changed`; if any changed,
merge all slots in registration order into one fresh `*pcommon.Resource` and publish `meta` +
`resource` together under `pm.mu.Lock` — the same discipline `info.meta` / `info.processContext` use
today at `processinfo.go:834-844`. `metaForPID` returns `(process.Meta, *pcommon.Resource)`, mirroring
today's `(process.Meta, processcontext.Info)`, and `HandleTrace` sets `TraceEventMeta.Resource` from
it. `ProcessedUntil` (`processinfo.go:958`, a *different* goroutine) calls `Close()` on any state
implementing `io.Closer` before `delete(pm.pidToProcessInfo, pid)`, next to the existing
`instance.Detach` loop.

### 4. Inputs to the late phase

- **Mappings**: `processmanager.New` collects the non-nil `WantMapping` funcs once. Inside the
  existing `IterateMappings` callback (`processinfo.go:690`), each filter that returns true gets the
  mapping interned and appended to its per-round slice; the block is guarded by a hoisted
  `len(pm.mappingFilters) > 0`, so a build with no filtering enricher pays nothing.

  Cost check: this replaces today's inline `processcontext.IsContextMapping` with one indirect call
  per registered filter — a few ns against a loop that already runs `isInterpreterMapping`
  (`IsExecutable` + `IsAnonymous`, several prefix/equality checks), `IsContextMapping`,
  `libpf.Intern` for kept mappings, and potentially an ELF open plus file-ID computation. Even at
  1000 mappings that is single-digit µs on a pass measured in hundreds. `maxProcParseUsec` /
  `totalProcParseUsec` already instrument exactly this loop — check them rather than guessing. A
  declarative exact-name set, and keeping the check specialized in the manager, were both considered
  and rejected on those numbers.

- **Interpreters**: `pm.interpreters[pid]` is passed straight through — no copy, no conversion. It is
  grabbed under `pm.mu` exactly like the existing `interpreters := pm.interpreters[pid]` at
  `processinfo.go:845` and iterated unlocked by the enricher, the same pattern (and the same
  pre-existing caveat about `processRemovedInterpreters` deleting from the inner map under the lock)
  as today's `SynchronizeMappings` loop. Enrichers run on the sync goroutine, before that loop.
  `MainExecutableID` is captured during the pass by comparing `m.Path` against the exe — PR 1716's
  `exeOID` capture, ~3 lines.

  The manager never calls `RuntimeInfo()`, so PR 1716's `selectProcessRuntime` does **not** move into
  `processmanager`. All runtime-specific policy lives in the enricher: calling `RuntimeInfo()`,
  preferring the main-executable instance, the lexicographic tie-break, fill-once, and the semconv
  attribute keys. The manager can be read without knowing runtimes are a concept.

- **Env vars**: `processmanager.New` unions every resource enricher's `ResourceConfig().EnvVars` into
  `includeEnvVars`, replacing the hardcoded `processcontext.EnvVars()` block, and keeps
  `reportEnvVars` (the user-requested set) separate as today. During the initial phase the manager
  extracts the declared names into `processInfo.envVars` and strips everything not in
  `reportEnvVars` from `meta.EnvVariables` — today's `internalEnvVars` mechanism, generalized from a
  hardcoded list to declared requirements, and now available to any enricher.

### 5. Ordering and merging

Registration order defines both call order and merge precedence (later wins on key conflicts):
env vars → self container ID for the initial phase; runtime info → process context → user enrichers
for the late phase, so an application's explicitly published attributes win over profiler-derived
ones. The manager re-merges and republishes only when some enricher reported a change, so
`base_reporter.go`'s `meta.Resource != rtp.Resource` refresh sees a new pointer exactly when there is
something new to see. (With a single contributing enricher the merge hands back that contribution
itself rather than allocating a copy, which is safe precisely because contributions are immutable.)

## Files to change

**Initial-phase API (`process`, no new dependencies)**
- `process/types.go` — add `Reason`, `MetaRequest`; `MetaEnricher`/`MetaEnricherFunc` take the
  request; `Process.GetProcessMeta()` loses its argument; add `Process.ProcBase()`. `Meta` unchanged.
- `process/process.go` — `GetProcessMeta` no longer loops enrichers; add `ProcBase()`; update the two
  built-in enricher signatures; trim `" (deleted)"` in `GetExe()` via a shared `deletedSuffix` const
  with `trimMappingPath` (needed for the exe↔mapping comparison, per PR 1716).
- `process/coredump.go` — `GetProcessMeta()` / `ProcBase()`.

**Late-phase API (new package)**
- `procmeta/procmeta.go` (new) — `ResourceConfig`, `ResourceRequest`, `ResourceEnricher`,
  `MergeResources`.

**Process context**
- `procmeta/processcontext/` — the whole `process/processcontext` package **moves here** (engine,
  tests, `proto/`, `v1development/`, `integrationtests/`), since it now imports `procmeta`. Nothing
  outside the package referenced the engine.
- `procmeta/processcontext/enricher.go` (new) — `func NewEnricher() procmeta.ResourceEnricher`,
  reporting `ResourceConfig{EnvVars: EnvVars(), WantMapping: <wraps IsContextMapping>}`. Its
  `EnrichResource` finds the context mapping in `req.Mappings`, reads `PublishedAtNs` from
  `req.State`, and calls the existing `Resolve(addr, pid, rm, oldPublishedAtNs, req.EnvVars,
  req.NewProcessOrExec)` — whose `(Info, bool)` return maps straight onto
  `(*pcommon.Resource, changed)`. `Read`, `WithMergedEnvVars` and the package's own internal
  `mergeResources` are reused as-is; no `MergeInto` helper is needed, since merging *across*
  enrichers is the manager's job, via `procmeta.MergeResources`.
- `Makefile` — three path references to update: `clean` (line 56), `processctx-execs` (line 150),
  `host-integration-tests` (line 155).

**Runtime info**
- `interpreter/types.go`, `interpreter/instancestubs.go`, `interpreter/multi.go` and nine
  implementations (`beam`, `dotnet`, `go`, `hotspot`, `nodev8`, `perl`, `php`, `python`, `ruby`) — add
  `RuntimeInfo() (name, version string, ok bool)`. `nodev8` is not in PR 1716, which predates this
  fork's V8 support; without it Node processes would silently report no runtime. It reports `v8` with
  V8's own version, since that is what is read from the binary — not the Node.js release embedding it.
  Port the rest from
  `origin/cherelii/add_runtime_version_resource_attributes` (`git diff` against its merge-base with
  HEAD), including CPython's `decodePyVersionHex` / `pythonData.fullVersion` and the unconditional
  `readPyVersionHex` in `loader()`.
- `procmeta/runtimeinfo/runtimeinfo.go` (new) — `func NewEnricher() procmeta.ResourceEnricher` with
  the zero `ResourceConfig`. Ranges over `req.Interpreters`, applies PR 1716's selection (prefer
  `oid == req.MainExecutableID`, else lexicographically smallest `(name, version)` for determinism),
  is fill-once via `req.State`, and returns a resource carrying
  `semconv.ProcessRuntimeNameKey` / `ProcessRuntimeVersionKey`. Unit-testable with
  `interpreter.InstanceStubs` plus a `RuntimeInfo` override — no process manager involved.

**Process manager**
- `processmanager/manager.go` — assemble both enricher lists (adding the two new resource enrichers);
  call `ResourceConfig()` once per resource enricher and precompute the `WantMapping` filter list
  (as `[]mappingFilter`, each pairing a predicate with the index of the enricher that declared it) and
  the `EnvVars` union, replacing the hardcoded `processcontext.EnvVars()` block;
  `HandleTrace` takes the resource from `metaForPID`.
- `processmanager/processinfo.go` — thread `MetaRequest` through the two `readProcessMeta` sites; new
  `enrichResources` helper plus the publication step; filter dispatch and `exeOID` capture in the
  `IterateMappings` callback; delete the inline `IsContextMapping` / `Resolve` blocks (`:691`,
  `:826-828`, `:841-843`) and replace the hardcoded internal-env-var split in `readProcessMeta` with
  the declared-names one; `metaForPID` returns `(process.Meta, *pcommon.Resource)`; state `Close()`
  in `ProcessedUntil`.
- `processmanager/types.go` — `processInfo` as in §3 (`resource`, `contributions` and `enricherState`
  replacing `processContext`); the `mappingFilter` type; on `ProcessManager`, the resource-enricher
  list plus the resolved filters.

**Reporter — nothing changes.** Resource attributes already flow `TraceEventMeta.Resource` →
`ResourceToProfiles.Resource` → `setResourceAttributes`, with the late-detection backfill at
`base_reporter.go:79-84`. Runtime attributes ride that same path, so PR 1716's
`RuntimeName`/`RuntimeVersion` fields and its `setResourceAttributes` signature change are **not
needed**. Only comments naming `processcontext` need a touch-up.

**Plumbing** — `collector/controller_options.go`, `internal/controller/config.go`,
`internal/controller/controller.go`, `tracer/tracer.go`, `processmanager/manager.go`: carry a second
slice, `[]procmeta.ResourceEnricher`, alongside the existing `[]process.MetaEnricher`, with a new
`collector.WithResourceEnricher` option next to `WithProcessMetaEnricher`. Existing out-of-tree
`MetaEnricher`s need only the mechanical signature update; `ExtraMeta` semantics are unchanged.

**Tests**
- `procmeta/procmeta_test.go` (new) — `MergeResources`: precedence, nil handling, that contributions
  are not mutated, and that a lone contribution is shared rather than copied.
- `processmanager/processinfo_test.go` — update `testProcess.GetProcessMeta`/`ProcBase` (note it
  passed a procBase *without* the trailing slash, unlike production; now fixed); extend
  `TestSynchronizeProcessRunEnrichers` with the `Reason` sequence while keeping its initial-phase
  expectations (one call on discovery, none on unchanged exe, one more on exe change); add
  `TestSynchronizeProcessRunsResourceEnrichers` (called on every sync, `changed=false` carry-forward,
  `(nil, true)` withdrawal), `…ResourceEnricherNewProcessOrExec`, `…MergesResourceContributions`,
  `…ResourceEnricherState` (survives syncs, `Close()`d on exit) and `…ResourceEnricherMappings`.
- `procmeta/processcontext/processcontext_test.go` (moved) + new `enricher_test.go` — the config's
  filter, plus enricher-level equivalents of the `Resolve` state-machine cases: late mapping,
  mapping disappearing, `ErrNoUpdate` keeping the previous contribution, exec forcing a rebuild.
- `procmeta/runtimeinfo/runtimeinfo_test.go` — port `TestSelectProcessRuntime`'s cases (including
  determinism and the exe-reports-nothing case) onto an `interpreter.Instance` map, plus
  resolve-once-until-exec and attribute emission.
- `collector/controller_options_test.go` and `interpreter/python` (`TestDecodePyVersionHex`) —
  signature update and ported case.
- `procmeta/processcontext/integrationtests/processcontext_integration_test.go` — moves, assertions
  unchanged; it checks `TraceEventMeta.Resource`, the contract being preserved.

Two files the plan expected to touch needed no changes: `process/process_test.go` (it does not
exercise the enricher API) and `reporter/base_reporter_test.go` — `TestProcessMetaEnricherPipeline`
covers the `ExtraMeta` path, which this work leaves alone. That the reporter tests compile and pass
untouched is the useful signal that the reporter contract really is unchanged.

## Commits

| | | |
|---|---|---|
| `cb68bcd9` | `process`: pass a request to MetaEnricher and let the process manager drive it | Behaviour-neutral; `MetaRequest`, `Reason`, `Process.ProcBase()`. Upstreamable on its own. |
| `1db414af` | `processcontext`: move the package under procmeta | Pure move: import paths + the three Makefile targets. |
| `57edf956` | `procmeta`: add the ResourceEnricher interface | Types and `MergeResources` only, no callers. Also upstreamable on its own. |
| `2d0490d2` | `processmanager`: drive resource enrichers and make process context one | Wiring plus the first implementation. |
| `29de10de` | `interpreter`: let instances report their language runtime | `RuntimeInfo()` across nine runtimes. |
| `f5111c65` | `process`: identify the process's own executable among its mappings | `MainExecutableID` + the `GetExe()` trim. |
| `5a4f360f` | `runtimeinfo`: emit process.runtime.name and process.runtime.version | Selection policy and emission. |

Two deviations from the planned staging, both to avoid commits that exist only to be undone:

- The move was pulled ahead of the API work (planned #3 → actual #2). Landing it before anything
  references `procmeta` keeps it a pure rename with no import churn to redo later.
- Planned #2 (the plumbing, with process context still inline) and #4 (the port) were merged into
  `2d0490d2`. Keeping them apart would have meant a commit that adds the resource path *and* retains
  the inline `processcontext.Resolve` call, plus a temporary shim in `HandleTrace` to merge the two
  resource sources — code written purely to be deleted one commit later. The API types still land on
  their own in `57edf956`, which is what made the separate commit worth having.

The `f5111c65` boundary is also slightly wider than planned: it carries the `GetExe()` `" (deleted)"`
trim, which reads as an unrelated fix but is what makes the `MainExecutableID` comparison work at all.

Every commit builds and its tests pass in isolation; verified by checking each one out in turn.

**Deferred:** emitting `processcontext.Info.ExtraAttributes` (parsed but dropped today; needs a
sample- vs resource-scope decision); making the two new resource enrichers configurable rather than
always-on; any frame-level runtime attribute.

## Verification

All of the below runs in the container, per `CLAUDE.md`. No eBPF changes, so a single arch suffices.

```bash
# Build. Note that plain `go build ./...` does NOT work in this repo: linking
# rust-crates/symblib-capi needs a prebuilt libsymblib_capi.a that is absent
# unless the Rust side was built. Excluding it also makes this the import-cycle
# check for procmeta -> {process, interpreter} and processmanager -> procmeta.
go build $(go list ./... | grep -v rust-crates)

go test $(go list ./... | grep -v rust-crates | grep -v tools/coredump)
go test -race ./procmeta/... ./processmanager/ ./process/...
make lint

# Process-context host-integration test — assertions must pass unchanged
sudo mountpoint -q /sys/kernel/tracing || sudo mount -t tracefs tracefs /sys/kernel/tracing
make processctx-execs
go test -exec sudo -v -tags host_integration -run Test_ProcessContext \
  ./procmeta/processcontext/integrationtests

# Per-commit check. -buildvcs=false is required on a detached HEAD, otherwise the
# build fails on "error obtaining VCS status" rather than on anything real.
go build -buildvcs=false $(go list ./... | grep -v rust-crates)
```

Results: build, tests, `-race` and `make lint` (0 issues) all clean. `Test_ProcessContext` passes
with its assertions untouched, including the `glibc_exe_delayed_publish` subtest — that one exercises
a context region published ~200 ms after startup, so it covers the whole late path (prctl tracepoint
→ resynchronization → mapping filter → enricher → merged resource → reporter) and is the strongest
evidence the refactor is behaviour-preserving.

End-to-end check that runtime info lands: run the profiler against a CPython and a Go target and
confirm `process.runtime.name` / `process.runtime.version` appear on the exported `ResourceProfiles`,
alongside process-context attributes when `OTEL_CTX` is published.

Mapping-pass regression check: compare `maxProcParseUsec` / `totalProcParseUsec` before and after,
ideally against a process with many mappings (a JVM or a browser), to confirm the `WantMapping`
dispatch is in the noise as expected.

## Open risks

- Two enricher interfaces instead of one is more API surface, and the split is a judgement call: an
  extension that wants both early procfs access *and* resource attributes has to implement both. The
  alternative — one interface over a shared mutable `Meta` — was rejected because it needs
  copy-on-write discipline enforced only by documentation.
- A resource enricher's first call is at the end of the first mapping pass rather than at first
  observation, so it is marginally later than `MetaEnricher` for very short-lived processes. Today's
  `processcontext.Resolve` already runs at that point, so this is not a regression.
- `ResourceRequest.Interpreters` hands enrichers the live `interpreter.Instance` map; nothing stops a
  badly behaved enricher from calling `Detach` or mutating it, and the contract is a doc comment
  only. Accepted for zero-copy pass-through — an `iter.Seq2` over a narrow `RuntimeInfo`-only
  interface, and a copied snapshot slice, were both considered and rejected.
- `pm.interpreters[pid]` is fetched under `pm.mu` then iterated unlocked, mirroring
  `processinfo.go:845` — and inheriting that code's latent hazard, since `processRemovedInterpreters`
  deletes from the inner map under the lock. Checked during implementation: the enrichment round runs
  on the PID-event goroutine, which is also the only one that calls `processRemovedInterpreters`, so
  the two cannot overlap within a synchronization and no new exposure is added. The hazard is still
  there in principle for a concurrent `ProcessedUntil`, exactly as it already was for the existing
  `SynchronizeMappings` loop; fixing it is out of scope for this change.
- Reporting the V8 version as the runtime for Node processes is a guess at what is most useful:
  `RuntimeInfo` can only see what is in the binary, and Node's own release version is not it. If
  consumers want `nodejs` and a Node version instead, that is a change to the `nodev8` interpreter,
  not to this design.
- PR 1716 is still open with CHANGES_REQUESTED on record (florianl: a process can host several
  runtimes, so runtime is not a resource property; use a frame-level attribute). Proceeding on the
  stated agreement that resource level is acceptable; if that reverses, only commits 5–7 are
  affected — 1–4 stand.
