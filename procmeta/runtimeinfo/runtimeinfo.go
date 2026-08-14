// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtimeinfo contributes the process.runtime.name and
// process.runtime.version resource attributes, recording which language runtime
// a profiled process ran and which version of it. Knowing that a sample came
// from CPython 3.11.4 rather than just "CPython" is what allows the standard
// library sources for that exact version to be resolved.
package runtimeinfo // import "go.opentelemetry.io/ebpf-profiler/procmeta/runtimeinfo"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/procmeta"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// enricher reports the runtime of a process. It is stateless: whether a process's
// runtime has already been resolved is recorded in that process's enricher state
// slot.
type enricher struct{}

// NewEnricher returns a ResourceEnricher contributing the language runtime of a
// process, resolved from the interpreters the profiler attached to it.
func NewEnricher() procmeta.ResourceEnricher {
	return enricher{}
}

func (enricher) ResourceConfig() procmeta.ResourceConfig {
	return procmeta.ResourceConfig{}
}

// state is an enricher's per-process state.
type state struct {
	// resolved is set once a runtime has been reported for the process. The
	// runtime is then left alone until the executable changes: a process does not
	// swap runtimes under us, and re-resolving on every synchronization would let
	// the reported runtime flip as further interpreters attach.
	resolved bool
}

func (enricher) EnrichResource(req *procmeta.ResourceRequest) (*pcommon.Resource, bool) {
	if s, ok := (*req.State).(*state); ok && s.resolved && !req.NewProcessOrExec {
		return nil, false
	}

	name, version := selectRuntime(req)
	if name == "" {
		// No interpreter has attached yet, or none can report a runtime. Interpreters
		// are detected as their mappings appear, so a later synchronization may still
		// resolve one.
		return nil, false
	}

	res := pcommon.NewResource()
	res.Attributes().PutStr(string(semconv.ProcessRuntimeNameKey), name)
	if version != "" {
		res.Attributes().PutStr(string(semconv.ProcessRuntimeVersionKey), version)
	}

	*req.State = &state{resolved: true}
	return &res, true
}

// selectRuntime picks the runtime to report for a process that may host several,
// for instance a Go binary embedding CPython, or a Python application calling
// into a JIT-compiled library through its FFI.
func selectRuntime(req *procmeta.ResourceRequest) (name, version string) {
	// Prefer the top-level runtime: the one whose DSO is the process's own
	// executable. That is what makes a Go binary embedding CPython report "go".
	if inst, ok := req.Interpreters[req.MainExecutableID]; ok &&
		req.MainExecutableID != (util.OnDiskFileIdentifier{}) {
		if n, v, ok := inst.RuntimeInfo(); ok {
			return n, v
		}
	}

	// Otherwise pick the smallest (name, version), so that a process hosting
	// several non-executable runtimes keeps reporting the same one instead of
	// flipping with Go's randomized map iteration order, which would split its
	// samples across resources.
	for _, inst := range req.Interpreters {
		n, v, ok := inst.RuntimeInfo()
		if !ok {
			continue
		}
		if name == "" || n < name || (n == name && v < version) {
			name, version = n, v
		}
	}
	return name, version
}
