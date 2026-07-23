// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/processcontext"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
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

var errUnknownOrigin = errors.New("unknown trace origin")

const (
	serviceNameKey               = "service.name"
	serviceVersionKey            = "service.version"
	deploymentEnvironmentNameKey = "deployment.environment.name"
)

var promotedThreadResourceAttributes = map[string]struct{}{
	serviceNameKey:               {},
	serviceVersionKey:            {},
	deploymentEnvironmentNameKey: {},
}

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

// effectiveResource returns a per-sample resource in precedence order:
// Process Context, SDK-published Thread Context, then the legacy APM service
// name as a fallback when service.name is absent or empty.
//
// Process Context resources are shared and immutable, so this function copies
// before applying overrides. A Thread Context attribute replaces a same-named
// Process Context attribute. The resource-semantic attributes consumed by the
// profiler are also promoted when absent from Process Context; all other Thread
// Context attributes remain attached to the sample.
func effectiveResource(
	resource *pcommon.Resource,
	apmServiceName string,
	trace *libpf.Trace,
) (*pcommon.Resource, libpf.String) {
	hasThreadResourceAttribute := false
	if trace.CustomLabelsFromThreadContext {
		for key := range trace.CustomLabels {
			name := key.String()
			_, isPromoted := promotedThreadResourceAttributes[name]
			existsInProcessResource := false
			if resource != nil {
				_, existsInProcessResource = resource.Attributes().Get(name)
			}
			if isPromoted || existsInProcessResource {
				hasThreadResourceAttribute = true
				break
			}
		}
	}

	if !hasThreadResourceAttribute {
		if resourceString(resource, serviceNameKey) != "" || apmServiceName == "" {
			return resource, libpf.NullString
		}

		effective := pcommon.NewResource()
		if resource != nil {
			resource.Attributes().CopyTo(effective.Attributes())
		}
		effective.Attributes().PutStr(serviceNameKey, apmServiceName)
		return &effective, libpf.NullString
	}

	effective := pcommon.NewResource()
	if resource != nil {
		resource.Attributes().CopyTo(effective.Attributes())
	}

	var threadResourceParts []string
	if trace.CustomLabelsFromThreadContext {
		for key, value := range trace.CustomLabels {
			name := key.String()
			_, isPromoted := promotedThreadResourceAttributes[name]
			_, existsInEffectiveResource := effective.Attributes().Get(name)
			if isPromoted || existsInEffectiveResource {
				valueString := value.String()
				effective.Attributes().PutStr(name, valueString)
				threadResourceParts = append(threadResourceParts,
					fmt.Sprintf("%d:%s%d:%s", len(name), name, len(valueString), valueString))
			}
		}
	}
	if resourceString(&effective, serviceNameKey) == "" && apmServiceName != "" {
		effective.Attributes().PutStr(serviceNameKey, apmServiceName)
	}
	if len(threadResourceParts) == 0 {
		return &effective, libpf.NullString
	}
	sort.Strings(threadResourceParts)
	return &effective, libpf.Intern(strings.Join(threadResourceParts, ""))
}

func resourceString(resource *pcommon.Resource, key string) string {
	if resource == nil {
		return ""
	}
	value, ok := resource.Attributes().Get(key)
	if !ok || value.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return value.Str()
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	switch meta.Origin {
	case support.TraceOriginSampling:
	case support.TraceOriginOffCPU:
	case support.TraceOriginProbe:
	default:
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin,
			errUnknownOrigin)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	resource, threadResourceKey := effectiveResource(meta.Resource, meta.APMServiceName, trace)
	key := samples.ResourceKey{
		ServiceName:           resourceString(resource, serviceNameKey),
		ServiceVersion:        resourceString(resource, serviceVersionKey),
		DeploymentEnvironment: resourceString(resource, deploymentEnvironmentNameKey),
		ContainerID:           meta.ContainerID,
		PID:                   int64(meta.PID),
		ExecutablePath:        meta.ExecutablePath,
		ContextKey:            processcontext.ResourceToContextKey(resource),
		ThreadResourceKey:     threadResourceKey,
	}

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[key]; !exists {
		(*eventsTree)[key] = samples.ResourceToProfiles{
			EnvVars:  meta.EnvVars,
			Resource: resource,
			Events:   make(map[libpf.Origin]samples.SampleToEvents),
		}
	}

	rtp := (*eventsTree)[key]
	if _, exists := rtp.Events[meta.Origin]; !exists {
		rtp.Events[meta.Origin] = make(samples.SampleToEvents)
	}

	sampleKey := samples.SampleKey{
		Hash:       trace.Hash,
		LabelsHash: libpf.HashLabels(trace.CustomLabels),
		Comm:       meta.Comm,
		TID:        int64(meta.TID),
		CPU:        int64(meta.CPU),
		SpanID:     meta.SpanID,
		TraceID:    meta.TraceID,
		ExtraMeta:  extraMeta,
	}
	if events, exists := rtp.Events[meta.Origin][sampleKey]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.Values = append(events.Values, meta.Value)
		return nil
	}

	rtp.Events[meta.Origin][sampleKey] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		Values:     []int64{meta.Value},
		Labels:     trace.CustomLabels,
	}
	return nil
}
