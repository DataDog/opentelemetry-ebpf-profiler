// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[samples.TraceEventsTree]

	// collectionStartTime tracks when the current collection window started.
	// Initialized when Start() is called. The duration of the first profile may be
	// slightly overestimated as it includes tracer setup time before samples arrive.
	collectionStartTime time.Time
}

var errUnknownProfileType = errors.New("unknown trace profile type")

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	if meta.ProfileType == nil {
		return fmt.Errorf("skip reporting trace: %w", errUnknownProfileType)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	key := samples.ResourceKey{
		APMServiceName: meta.APMServiceName,
		ContainerID:    meta.ContainerID,
		PID:            int64(meta.PID),
		ExecutablePath: meta.ExecutablePath,
		ContextKey:     resourceToContextKey(meta.Resource),
	}
	traceHash := traceutil.HashTrace(trace)

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[key]; !exists {
		(*eventsTree)[key] = samples.ResourceToProfiles{
			EnvVars:  meta.EnvVars,
			Resource: meta.Resource,
			Events:   make(map[*samples.TypeMetadata]samples.SampleToEvents),
		}
	}

	rtp := (*eventsTree)[key]
	if _, exists := rtp.Events[meta.ProfileType]; !exists {
		rtp.Events[meta.ProfileType] = make(samples.SampleToEvents)
	}

	sampleKey := samples.SampleKey{
		Hash:      traceHash,
		Comm:      meta.Comm,
		TID:       int64(meta.TID),
		CPU:       int64(meta.CPU),
		SpanID:    meta.SpanID,
		TraceID:   meta.TraceID,
		ExtraMeta: extraMeta,
	}
	if events, exists := rtp.Events[meta.ProfileType][sampleKey]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.Values = append(events.Values, meta.Value)
		return nil
	}

	rtp.Events[meta.ProfileType][sampleKey] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		Values:     []int64{meta.Value},
		Labels:     trace.CustomLabels,
	}
	return nil
}

// resourceToContextKey returns a stable key derived from the
// (service.namespace, service.name, service.instance.id) triplet which the
// OTel semantic conventions describe as globally unique for a service instance.
// See: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/service.md
//
// Returns libpf.NullString only when resource is nil or none of the three
// attributes is present. When at least one is present, the result joins all
// three with ':' (missing components render as empty strings); callers should
// treat the null sentinel as "unidentifiable" and may choose to group such
// samples by other fields.
func resourceToContextKey(resource *pcommon.Resource) libpf.String {
	if resource == nil {
		return libpf.NullString
	}
	serviceNamespace, namespaceOk := resource.Attributes().Get(string(semconv.ServiceNamespaceKey))
	serviceName, nameOk := resource.Attributes().Get(string(semconv.ServiceNameKey))
	serviceInstanceID, instanceIdOk := resource.Attributes().Get(string(semconv.ServiceInstanceIDKey))
	// If all three attributes are missing, return an empty string instead of ":::"
	// to ensure that nil resource and empty resource are treated as the same.
	if !namespaceOk && !nameOk && !instanceIdOk {
		return libpf.NullString
	}
	return libpf.Intern(fmt.Sprintf("%s:%s:%s",
		serviceNamespace.Str(), serviceName.Str(), serviceInstanceID.Str()))
}
