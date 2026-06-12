# Implement me: eBPF heap allocation counts for profiling-backend

## Context

`profiling-backend` now accepts eBPF heap allocation OTLP profiles and maps them as:

```text
alloc_space   bytes -> alloc-size    bytes -> heap.pprof
alloc_objects count -> alloc-samples count -> heap.pprof
```

The current otel eBPF profiler heap allocation path appears to emit only:

```text
sample_type = alloc_space / bytes
sample.values = allocation size bytes
```

That is enough for allocation byte flamegraphs, but not enough for allocation sample indexing/analytics in profiling-backend.

## Needed change

Emit allocation object/count data as well as allocation byte data.

Preferred shape: emit a heap allocation OTLP profile that includes both pprof-compatible allocation value columns downstream can preserve/index:

```text
alloc_space   / bytes
alloc_objects / count
```

For each allocation event/sample:

```text
alloc_space value   = allocation size in bytes
alloc_objects value = allocation count represented by the sample
```

For one allocation event, `alloc_objects` should normally be `1`. If samples are aggregated by identical stack/labels, `alloc_objects` should be the number of allocation events aggregated into that row, while `alloc_space` should be the sum of their allocated bytes.

## Why

`profiling-backend` sample indexing for allocation size expects:

```text
value column = alloc-size
count column = alloc-samples
```

Without `alloc_objects/count`, backend can still build allocation byte flamegraphs, but cannot correctly disaggregate allocation samples for sample indexing.

## Names to use

Use pprof-native names:

```text
alloc_space
alloc_objects
```

Do not use:

```text
allocated_space
allocated_objects
space
objects
```

`space`/`objects` are ambiguous and have legacy Node-specific behavior elsewhere.

## Current known code location

Current allocation profile type is set in:

```text
reporter/internal/pdata/generate.go
```

Currently:

```go
case support.TraceOriginHeapAlloc:
    st.SetTypeStrindex(stringSet.Add("alloc_space"))
    st.SetUnitStrindex(stringSet.Add("bytes"))
```

The profiler should additionally produce `alloc_objects/count` values for heap allocation events, ideally in a form that backend can turn into `alloc-samples`.

## Future live heap names

When live heap is implemented, use:

```text
inuse_space   bytes -> heap-live-size
inuse_objects count -> heap-live-samples
```
