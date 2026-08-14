// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext // import "go.opentelemetry.io/ebpf-profiler/procmeta/processcontext"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/procmeta"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// enricher reads the OTel process context a process shares through its OTEL_CTX
// memory region. It is stateless: the timestamp of the last context it published
// for a process is kept in that process's enricher state slot.
type enricher struct{}

// NewEnricher returns a ResourceEnricher contributing the resource attributes a
// process publishes in its OTEL_CTX memory region, merged with those derived from
// OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
func NewEnricher() procmeta.ResourceEnricher {
	return enricher{}
}

func (enricher) ResourceConfig() procmeta.ResourceConfig {
	return procmeta.ResourceConfig{
		EnvVars: EnvVars(),
		WantMapping: func(m *process.RawMapping) bool {
			return IsContextMapping(m.IsExecutable(), m.Path)
		},
	}
}

// state is an enricher's per-process state.
type state struct {
	// publishedAtNs is the timestamp of the context last published for the
	// process, used to skip re-reading a payload that has not changed.
	publishedAtNs uint64
}

func (enricher) EnrichResource(req *procmeta.ResourceRequest) (*pcommon.Resource, bool) {
	// The context mapping is absent until the process publishes it, which it may do
	// well after startup. The eBPF hook on prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)
	// triggers a resynchronization when that happens, bringing us back here.
	var mappingAddr uint64
	if len(req.Mappings) > 0 {
		mappingAddr = req.Mappings[0].Vaddr
	}

	var oldPublishedAtNs uint64
	if s, ok := (*req.State).(*state); ok {
		oldPublishedAtNs = s.publishedAtNs
	}

	info, publish := Resolve(mappingAddr, req.Process.PID(), req.Process.GetRemoteMemory(),
		oldPublishedAtNs, req.EnvVars, req.NewProcessOrExec)
	if !publish {
		return nil, false
	}

	*req.State = &state{publishedAtNs: info.PublishedAtNs}
	return info.Resource, true
}
