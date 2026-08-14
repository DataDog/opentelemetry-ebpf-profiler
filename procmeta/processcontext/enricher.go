// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext // import "go.opentelemetry.io/ebpf-profiler/procmeta/processcontext"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
)

// enricher reads the OTel process context a process shares through its OTEL_CTX
// memory region. The last snapshot lives in the process's state slot.
type enricher struct{}

// NewEnricher returns a ResourceEnricher contributing only the resource a process
// publishes through OTEL_CTX. The process manager merges it with other sources.
func NewEnricher() procmeta.ResourceEnricher {
	return enricher{}
}

func (enricher) ResourceConfig() procmeta.ResourceConfig {
	return procmeta.ResourceConfig{
		WantMapping: func(m *process.RawMapping) bool {
			return IsContextMapping(m.IsExecutable(), m.Path)
		},
	}
}

func (enricher) EnrichResource(req *procmeta.ResourceRequest) (*pcommon.Resource, bool) {
	// The prctl monitor triggers resynchronization when a context mapping appears,
	// including one published after the process was first observed.
	var mappingAddr uint64
	if len(req.Mappings) > 0 {
		mappingAddr = req.Mappings[len(req.Mappings)-1].Vaddr
	}

	old, _ := (*req.State).(Info)
	info, changed := Resolve(mappingAddr, req.Process.PID(), req.Process.GetRemoteMemory(), old)
	if !changed {
		return nil, false
	}
	*req.State = info
	if !info.valid {
		return nil, true
	}

	resource := pcommon.NewResource()
	attrs := resource.Attributes()
	attrs.EnsureCapacity(info.ResourceAttrs.Len())
	for iter := info.ResourceAttrs.Iter(); iter.Next(); {
		kv := iter.Attribute()
		setAttributeValue(attrs.PutEmpty(string(kv.Key)), kv.Value)
	}
	return &resource, true
}

// setAttributeValue writes src into dst. dst is already inserted in its
// container, so a case that writes nothing yields an empty pcommon value.
func setAttributeValue(dst pcommon.Value, src attribute.Value) {
	switch src.Type() {
	case attribute.BOOL:
		dst.SetBool(src.AsBool())
	case attribute.INT64:
		dst.SetInt(src.AsInt64())
	case attribute.FLOAT64:
		dst.SetDouble(src.AsFloat64())
	case attribute.STRING:
		dst.SetStr(src.AsString())
	case attribute.BYTESLICE:
		dst.SetEmptyBytes().FromRaw(src.AsByteSlice())
	case attribute.BOOLSLICE:
		setSliceValue(dst, src.AsBoolSlice(), pcommon.Value.SetBool)
	case attribute.INT64SLICE:
		setSliceValue(dst, src.AsInt64Slice(), pcommon.Value.SetInt)
	case attribute.FLOAT64SLICE:
		setSliceValue(dst, src.AsFloat64Slice(), pcommon.Value.SetDouble)
	case attribute.STRINGSLICE:
		setSliceValue(dst, src.AsStringSlice(), pcommon.Value.SetStr)
	case attribute.SLICE:
		setSliceValue(dst, src.AsSlice(), setAttributeValue)
	case attribute.MAP:
		kvs := src.AsMap()
		m := dst.SetEmptyMap()
		m.EnsureCapacity(len(kvs))
		for _, kv := range kvs {
			setAttributeValue(m.PutEmpty(string(kv.Key)), kv.Value)
		}
	case attribute.EMPTY:
		// A published empty value, and dst already is one.
	default:
		// Reachable only if otel adds an attribute.Type.
		log.Warnf("setAttributeValue: no pcommon representation for %s, "+
			"emitting empty", src.Type())
	}
}

func setSliceValue[T any](dst pcommon.Value, values []T, set func(pcommon.Value, T)) {
	sl := dst.SetEmptySlice()
	sl.EnsureCapacity(len(values))
	for _, v := range values {
		set(sl.AppendEmpty(), v)
	}
}
