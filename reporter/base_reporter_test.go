// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// createTestBaseReporter creates a minimal baseReporter for testing purposes
func createTestBaseReporter(t *testing.T, cfg *Config) *baseReporter {
	t.Helper()

	if cfg == nil {
		cfg = &Config{
			Name:             "test-agent",
			Version:          "v1.0.0",
			SamplesPerSecond: 100,
		}
	}

	pdataInstance, err := pdata.New(cfg.SamplesPerSecond, cfg.ExtraSampleAttrProd)
	require.NoError(t, err)

	return &baseReporter{
		cfg:                 cfg,
		name:                cfg.Name,
		version:             cfg.Version,
		pdata:               pdataInstance,
		traceEvents:         xsync.NewRWMutex(make(samples.TraceEventsTree)),
		collectionStartTime: time.Now(),
	}
}

// TestBaseReporterGenerate tests the Generate method and validates the output
func TestBaseReporterGenerate(t *testing.T) {
	reporter := createTestBaseReporter(t, nil)

	trace1 := &libpf.Trace{
		Hash: libpf.NewTraceHash(0x0102030400000000, 0x0000000000000000),
		Frames: func() libpf.Frames {
			frames := make(libpf.Frames, 0, 3)
			frames.Append(&libpf.Frame{
				Type:            libpf.KernelFrame,
				AddressOrLineno: 0x1000,
				FunctionName:    libpf.Intern("kernel_entry"),
			})
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x2000,
				FunctionName:    libpf.Intern("native_handler"),
			})
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x3000,
				FunctionName:    libpf.Intern("app_function"),
			})
			return frames
		}(),
	}

	trace2 := &libpf.Trace{
		Hash: libpf.NewTraceHash(0x0506070800000000, 0x0000000000000000),
		Frames: func() libpf.Frames {
			frames := make(libpf.Frames, 0, 2)
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x4000,
				FunctionName:    libpf.Intern("another_function"),
			})
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x5000,
				FunctionName:    libpf.Intern("leaf_function"),
			})
			return frames
		}(),
	}

	now := time.Now()
	meta1 := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(now.UnixNano()),
		Comm:           libpf.Intern("app1"),
		ProcessName:    libpf.Intern("app1"),
		ExecutablePath: libpf.Intern("/usr/bin/app1"),
		APMServiceName: "service1",
		ContainerID:    libpf.Intern("container-1"),
		PID:            1000,
		TID:            1001,
		CPU:            0,
		Origin:         support.TraceOriginSampling,
	}

	meta2 := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(now.Add(time.Second).UnixNano()),
		Comm:           libpf.Intern("app2"),
		ProcessName:    libpf.Intern("app2"),
		ExecutablePath: libpf.Intern("/usr/bin/app2"),
		APMServiceName: "service2",
		ContainerID:    libpf.Intern("container-2"),
		PID:            2000,
		TID:            2001,
		CPU:            1,
		Origin:         support.TraceOriginOffCPU,
		Value:          5000000, // 5ms
	}

	err := reporter.ReportTraceEvent(trace1, meta1)
	require.NoError(t, err)

	err = reporter.ReportTraceEvent(trace2, meta2)
	require.NoError(t, err)

	// Get the trace events tree for generation
	eventsTreePtr := reporter.traceEvents.RLock()
	eventsTree := *eventsTreePtr
	reporter.traceEvents.RUnlock(&eventsTreePtr)

	// Generate profiles
	collectionStart := reporter.collectionStartTime
	collectionEnd := time.Now()
	profiles, err := reporter.pdata.Generate(
		eventsTree,
		reporter.name,
		reporter.version,
		collectionStart,
		collectionEnd,
	)

	// Validate the generation succeeded
	require.NoError(t, err)
	require.NotNil(t, profiles)

	// Validate profile structure
	assert.Greater(t, profiles.SampleCount(), 0,
		"Should have at least one sample")
	assert.Equal(t, 2, profiles.ResourceProfiles().Len(),
		"Should have exactly two resource profile")

	// Check that we have scope profiles
	resourceProfile := profiles.ResourceProfiles().At(0)
	assert.Equal(t, 1, resourceProfile.ScopeProfiles().Len(), 0,
		"Should have exactly one scope profile")

	// Verify scope profile metadata
	scopeProfile := resourceProfile.ScopeProfiles().At(0)
	assert.Equal(t, reporter.name, scopeProfile.Scope().Name())
	assert.Equal(t, reporter.version, scopeProfile.Scope().Version())

	// Verify profiles exist
	assert.Greater(t, scopeProfile.Profiles().Len(), 0,
		"Should have at least one profile")
}

// TestReportTraceEventResourceKeyContextKey verifies that the ContextKey
// derived from meta.Resource controls bucketing in the events tree:
//   - Same (namespace,name,instance.id) triplet collapses to one bucket.
//   - A different service.instance.id splits into a second bucket.
//   - A partial triplet (e.g. only service.name) produces a non-null key
//     like ":svc:" — distinct from the populated triplets and from nil.
//   - A nil Resource yields a NullString ContextKey, also distinct.
func TestReportTraceEventResourceKeyContextKey(t *testing.T) {
	reporter := createTestBaseReporter(t, nil)

	makeResource := func(namespace, name, instanceID string) *pcommon.Resource {
		r := pcommon.NewResource()
		if namespace != "" {
			r.Attributes().PutStr("service.namespace", namespace)
		}
		if name != "" {
			r.Attributes().PutStr("service.name", name)
		}
		if instanceID != "" {
			r.Attributes().PutStr("service.instance.id", instanceID)
		}
		return &r
	}

	trace := &libpf.Trace{
		Hash: libpf.NewTraceHash(0x1, 0x0),
		Frames: func() libpf.Frames {
			frames := make(libpf.Frames, 0, 1)
			frames.Append(&libpf.Frame{
				Type:            libpf.NativeFrame,
				AddressOrLineno: 0x100,
				FunctionName:    libpf.Intern("f"),
			})
			return frames
		}(),
	}

	now := libpf.UnixTime64(time.Now().UnixNano())
	baseMeta := func(resource *pcommon.Resource) *samples.TraceEventMeta {
		return &samples.TraceEventMeta{
			Timestamp:      now,
			Comm:           libpf.Intern("svc"),
			ProcessName:    libpf.Intern("svc"),
			ExecutablePath: libpf.Intern("/usr/bin/svc"),
			ContainerID:    libpf.Intern("c1"),
			PID:            1234,
			TID:            1235,
			Origin:         support.TraceOriginSampling,
			Resource:       resource,
		}
	}

	// Two events with the same triplet -> one bucket.
	resA := makeResource("ns", "svc", "instance-1")
	require.NoError(t, reporter.ReportTraceEvent(trace, baseMeta(resA)))
	resADup := makeResource("ns", "svc", "instance-1")
	require.NoError(t, reporter.ReportTraceEvent(trace, baseMeta(resADup)))

	// Different service.instance.id -> second bucket.
	resB := makeResource("ns", "svc", "instance-2")
	require.NoError(t, reporter.ReportTraceEvent(trace, baseMeta(resB)))

	// Partial triplet (only service.name) -> non-null key ":svc:" -> third bucket.
	resPartial := makeResource("", "svc", "")
	require.NoError(t, reporter.ReportTraceEvent(trace, baseMeta(resPartial)))

	// Nil Resource -> ContextKey is NullString -> fourth bucket.
	require.NoError(t, reporter.ReportTraceEvent(trace, baseMeta(nil)))

	treePtr := reporter.traceEvents.RLock()
	defer reporter.traceEvents.RUnlock(&treePtr)
	tree := *treePtr

	keys := make(map[libpf.String]bool)
	for k := range tree {
		keys[k.ContextKey] = true
	}
	assert.Equal(t, 4, len(tree), "expected four buckets")
	assert.True(t, keys[libpf.Intern("ns:svc:instance-1")], "missing bucket for instance-1")
	assert.True(t, keys[libpf.Intern("ns:svc:instance-2")], "missing bucket for instance-2")
	assert.True(t, keys[libpf.Intern(":svc:")], "missing bucket for partial-triplet key")
	assert.True(t, keys[libpf.NullString], "missing NullString bucket for nil resource")
}

func TestReportTraceEventThreadContextOverlaysProcessResource(t *testing.T) {
	reporter := createTestBaseReporter(t, nil)

	processResource := pcommon.NewResource()
	processResource.Attributes().PutStr("service.name", "process-service")
	processResource.Attributes().PutStr("service.version", "process-version")
	processResource.Attributes().PutStr("deployment.environment.name", "process-env")
	processResource.Attributes().PutStr("service.instance.id", "process-instance")
	processResource.Attributes().PutStr("host.name", "process-host")
	processResource.Attributes().PutStr("process-only", "unchanged")

	trace := &libpf.Trace{
		Hash:                          libpf.NewTraceHash(0x1, 0x0),
		CustomLabelsFromThreadContext: true,
		CustomLabels: map[libpf.String]libpf.String{
			libpf.Intern("service.name"):                libpf.Intern("thread-service"),
			libpf.Intern("service.version"):             libpf.Intern("thread-version"),
			libpf.Intern("deployment.environment.name"): libpf.Intern("thread-env"),
			libpf.Intern("service.instance.id"):         libpf.Intern("thread-instance"),
			libpf.Intern("host.name"):                   libpf.Intern("thread-host"),
			libpf.Intern("http.route"):                  libpf.Intern("/not-a-resource"),
		},
	}
	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(time.Now().UnixNano()),
		ExecutablePath: libpf.Intern("/usr/bin/php"),
		APMServiceName: "legacy-apm-service",
		PID:            1234,
		TID:            1235,
		Origin:         support.TraceOriginSampling,
		Resource:       &processResource,
	}

	require.NoError(t, reporter.ReportTraceEvent(trace, meta))

	treePtr := reporter.traceEvents.RLock()
	defer reporter.traceEvents.RUnlock(&treePtr)
	tree := *treePtr
	require.Len(t, tree, 1)

	for key, profiles := range tree {
		assert.Equal(t, "thread-service", key.ServiceName)
		assert.Equal(t, "thread-version", key.ServiceVersion)
		assert.Equal(t, "thread-env", key.DeploymentEnvironment)
		assert.Equal(t, ":thread-service:thread-instance", key.ContextKey.String())

		require.NotNil(t, profiles.Resource)
		assert.Equal(t, map[string]any{
			"service.name":                "thread-service",
			"service.version":             "thread-version",
			"deployment.environment.name": "thread-env",
			"service.instance.id":         "thread-instance",
			"host.name":                   "thread-host",
			"process-only":                "unchanged",
		}, profiles.Resource.Attributes().AsRaw())
		_, promoted := profiles.Resource.Attributes().Get("http.route")
		assert.False(t, promoted, "sample-only attributes must not be promoted")
	}

	// The shared Process Context resource remains immutable.
	assert.Equal(t, "process-service",
		processResource.Attributes().AsRaw()["service.name"])
	assert.Equal(t, "process-host",
		processResource.Attributes().AsRaw()["host.name"])
}

func TestReportTraceEventThreadResourceOverridesCreateDistinctBuckets(t *testing.T) {
	reporter := createTestBaseReporter(t, nil)
	processResource := pcommon.NewResource()
	processResource.Attributes().PutStr("service.name", "process-service")

	meta := &samples.TraceEventMeta{
		Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID:       1234,
		TID:       1235,
		Origin:    support.TraceOriginSampling,
		Resource:  &processResource,
	}
	makeTrace := func(version string) *libpf.Trace {
		return &libpf.Trace{
			Hash:                          libpf.NewTraceHash(0x1, 0x0),
			CustomLabelsFromThreadContext: true,
			CustomLabels: map[libpf.String]libpf.String{
				libpf.Intern("service.version"): libpf.Intern(version),
			},
		}
	}

	require.NoError(t, reporter.ReportTraceEvent(makeTrace("v1"), meta))
	require.NoError(t, reporter.ReportTraceEvent(makeTrace("v2"), meta))

	treePtr := reporter.traceEvents.RLock()
	defer reporter.traceEvents.RUnlock(&treePtr)
	assert.Len(t, *treePtr, 2)
}

func TestReportTraceEventAPMServiceNameIsFallback(t *testing.T) {
	stringPtr := func(value string) *string {
		return &value
	}
	tests := []struct {
		name           string
		processService string
		threadService  *string
		expected       string
	}{
		{
			name:           "process context wins",
			processService: "process-service",
			expected:       "process-service",
		},
		{
			name:     "APM fills missing service",
			expected: "legacy-apm-service",
		},
		{
			name:           "thread context wins",
			processService: "process-service",
			threadService:  stringPtr("thread-service"),
			expected:       "thread-service",
		},
		{
			name:           "APM fills service cleared by thread context",
			processService: "process-service",
			threadService:  stringPtr(""),
			expected:       "legacy-apm-service",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reporter := createTestBaseReporter(t, nil)
			processResource := pcommon.NewResource()
			if test.processService != "" {
				processResource.Attributes().PutStr("service.name", test.processService)
			}

			trace := &libpf.Trace{Hash: libpf.NewTraceHash(0x1, 0x0)}
			if test.threadService != nil {
				trace.CustomLabelsFromThreadContext = true
				trace.CustomLabels = map[libpf.String]libpf.String{
					libpf.Intern("service.name"): libpf.Intern(*test.threadService),
				}
			}
			meta := &samples.TraceEventMeta{
				Timestamp:      libpf.UnixTime64(time.Now().UnixNano()),
				APMServiceName: "legacy-apm-service",
				PID:            1234,
				TID:            1235,
				Origin:         support.TraceOriginSampling,
				Resource:       &processResource,
			}

			require.NoError(t, reporter.ReportTraceEvent(trace, meta))

			treePtr := reporter.traceEvents.RLock()
			defer reporter.traceEvents.RUnlock(&treePtr)
			require.Len(t, *treePtr, 1)
			for key, profiles := range *treePtr {
				assert.Equal(t, test.expected, key.ServiceName)
				require.NotNil(t, profiles.Resource)
				assert.Equal(t, test.expected,
					profiles.Resource.Attributes().AsRaw()["service.name"])
			}
		})
	}
}

func TestReportTraceEventGoLabelsDoNotOverrideResource(t *testing.T) {
	reporter := createTestBaseReporter(t, nil)
	processResource := pcommon.NewResource()
	processResource.Attributes().PutStr("service.name", "process-service")

	trace := &libpf.Trace{
		Hash: libpf.NewTraceHash(0x1, 0x0),
		CustomLabels: map[libpf.String]libpf.String{
			libpf.Intern("service.name"): libpf.Intern("go-label-service"),
		},
	}
	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(time.Now().UnixNano()),
		APMServiceName: "legacy-apm-service",
		PID:            1234,
		TID:            1235,
		Origin:         support.TraceOriginSampling,
		Resource:       &processResource,
	}

	require.NoError(t, reporter.ReportTraceEvent(trace, meta))

	treePtr := reporter.traceEvents.RLock()
	defer reporter.traceEvents.RUnlock(&treePtr)
	require.Len(t, *treePtr, 1)
	for key, profiles := range *treePtr {
		assert.Equal(t, "process-service", key.ServiceName)
		assert.Equal(t, "process-service",
			profiles.Resource.Attributes().AsRaw()["service.name"])
	}
}
