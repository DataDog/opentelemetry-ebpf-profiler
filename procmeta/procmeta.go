// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package procmeta provides the extension point for contributing OTel resource
// attributes to a profiled process.
//
// It complements process.MetaEnricher, which collects process metadata once when
// a process is first observed. Some attributes are not available that early: a
// memory region the process publishes after startup, or a language runtime whose
// interpreter is only detected once the profiler sees a matching mapping. A
// ResourceEnricher is therefore called on every mapping resynchronization, and
// contributes an immutable resource rather than writing to shared metadata.
package procmeta // import "go.opentelemetry.io/ebpf-profiler/procmeta"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// ResourceConfig declares what a ResourceEnricher needs in order to run. The
// zero value asks for nothing. Requirements are added as new fields, so existing
// implementations keep working.
type ResourceConfig struct {
	// EnvVars names the environment variables to make available in
	// ResourceRequest.EnvVars. They are captured even if the user did not ask for
	// them to be reported, and are not reported unless the user did.
	EnvVars []string

	// WantMapping selects the mappings delivered in ResourceRequest.Mappings.
	// nil means the enricher receives none. It is called for every mapping of
	// every synchronized process, so it must be cheap: no allocation, no
	// syscalls.
	WantMapping func(m *process.RawMapping) bool
}

// ResourceRequest describes a process and what the process manager observed for
// it during the current synchronization. It is valid only for the duration of
// the EnrichResource call: enrichers must not retain it, or anything reachable
// from it, afterwards.
type ResourceRequest struct {
	// Process gives access to the target process: remote memory, mappings and
	// the executable.
	Process process.Process

	// ProcBase is the process's /proc/<pid>/ base path (including trailing
	// slash), or empty for processes without a procfs entry.
	ProcBase string

	// Meta is the process metadata collected by process.MetaEnricher. Read-only:
	// it is a snapshot of already-published metadata whose maps are shared with
	// the code reporting profiles for this process.
	Meta *process.Meta

	// NewProcessOrExec is true on the first synchronization of a process and on
	// the one following an exec, meaning previously derived state should be
	// discarded.
	NewProcessOrExec bool

	// EnvVars holds the values of the variables named in ResourceConfig.EnvVars,
	// as captured when the process metadata was collected.
	EnvVars map[libpf.String]libpf.String

	// Mappings holds the mappings selected by ResourceConfig.WantMapping, in
	// /proc/<pid>/maps order.
	Mappings []process.RawMapping

	// Interpreters holds the interpreter instances attached to the process, keyed
	// by the on-disk identity of the DSO each was detected in. It is nil until an
	// interpreter has attached. Read-only: enrichers must not insert into or
	// delete from the map, nor drive the instances, as attaching, detaching and
	// synchronizing them belongs to the process manager.
	Interpreters map[util.OnDiskFileIdentifier]interpreter.Instance

	// MainExecutableID is the on-disk identity of the process's own executable,
	// or the zero value if it was not observed during this synchronization.
	MainExecutableID util.OnDiskFileIdentifier

	// State points at the process manager's per-process storage slot for this
	// enricher: *State is whatever the enricher stored on its previous call for
	// this process, and nil on the first call. Enrichers with per-process state
	// must keep it here rather than in their own maps, so that it is dropped when
	// the process exits. If the stored value implements io.Closer, Close is
	// called at that point.
	State *any
}

// ResourceEnricher contributes OTel resource attributes for a process.
type ResourceEnricher interface {
	// ResourceConfig returns the enricher's requirements. It is called once, when
	// the enricher is registered.
	ResourceConfig() ResourceConfig

	// EnrichResource returns the enricher's contribution for the process
	// described by req. The returned resource must be freshly built and is
	// treated as immutable by the caller, which may retain it across
	// synchronizations.
	//
	// changed reports whether the contribution differs from the one returned by
	// the previous call for this process: false keeps the stored contribution and
	// res is ignored, while (nil, true) withdraws it.
	EnrichResource(req *ResourceRequest) (res *pcommon.Resource, changed bool)
}

// MergeResources combines per-enricher contributions into a single resource.
// Contributions are applied in order, so later ones win on key collisions.
// Returns nil if every contribution is nil, and shares the single non-nil
// contribution as-is: contributions are immutable, so copying is unnecessary.
func MergeResources(contributions []*pcommon.Resource) *pcommon.Resource {
	var count int
	var single *pcommon.Resource
	for _, c := range contributions {
		if c != nil {
			count++
			single = c
		}
	}
	if count <= 1 {
		return single
	}

	merged := pcommon.NewResource()
	attrs := merged.Attributes()
	for _, c := range contributions {
		if c == nil {
			continue
		}
		c.Attributes().Range(func(k string, v pcommon.Value) bool {
			v.CopyTo(attrs.PutEmpty(k))
			return true
		})
	}
	return &merged
}
