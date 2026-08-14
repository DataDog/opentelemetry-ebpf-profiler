// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimeinfo_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
	"go.opentelemetry.io/ebpf-profiler/procmeta/runtimeinfo"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// fakeInstance is an interpreter.Instance reporting a fixed runtime.
type fakeInstance struct {
	interpreter.InstanceStubs
	name, version string
	// reports is false for an interpreter that cannot tell its runtime, as an
	// instance whose version data has not been read yet does.
	reports bool
}

func (i *fakeInstance) RuntimeInfo() (string, string, bool) {
	return i.name, i.version, i.reports
}

func (i *fakeInstance) Detach(interpreter.EbpfHandler, libpf.PID) error { return nil }

func runtime(name, version string) *fakeInstance {
	return &fakeInstance{name: name, version: version, reports: true}
}

func oid(inode uint64) util.OnDiskFileIdentifier {
	return util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: inode}
}

// enrich runs the enricher once and returns the attributes it contributed.
func enrich(t *testing.T, req *procmeta.ResourceRequest) (map[string]string, bool) {
	t.Helper()
	res, changed := runtimeinfo.NewEnricher().EnrichResource(req)
	if res == nil {
		return nil, changed
	}
	attrs := make(map[string]string, res.Attributes().Len())
	res.Attributes().Range(func(k string, v pcommon.Value) bool {
		attrs[k] = v.Str()
		return true
	})
	return attrs, changed
}

func TestEnricher_SelectRuntime(t *testing.T) {
	exeOID := oid(1)
	libOID := oid(2)

	tests := map[string]struct {
		interpreters     map[util.OnDiskFileIdentifier]interpreter.Instance
		mainExecutableID util.OnDiskFileIdentifier
		expected         map[string]string
	}{
		"no interpreter attached": {
			mainExecutableID: exeOID,
		},
		"single runtime in the executable": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("cpython", "3.11.4"),
			},
			mainExecutableID: exeOID,
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"single runtime in a library": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				libOID: runtime("cpython", "3.11.4"),
			},
			mainExecutableID: exeOID,
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"executable wins over embedded runtime": {
			// A Go binary embedding CPython must report Go.
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("go", "1.24.6"),
				libOID: runtime("cpython", "3.11.4"),
			},
			mainExecutableID: exeOID,
			expected: map[string]string{
				"process.runtime.name":    "go",
				"process.runtime.version": "1.24.6",
			},
		},
		"executable reports nothing, fall back to a library": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &fakeInstance{},
				libOID: runtime("ruby", "3.3.0"),
			},
			mainExecutableID: exeOID,
			expected: map[string]string{
				"process.runtime.name":    "ruby",
				"process.runtime.version": "3.3.0",
			},
		},
		"executable not observed, several libraries": {
			// Deterministic despite Go's randomized map iteration: smallest
			// (name, version) wins, so samples do not split across resources.
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				oid(2): runtime("ruby", "3.3.0"),
				oid(3): runtime("cpython", "3.12.7"),
				oid(4): runtime("cpython", "3.11.4"),
				oid(5): runtime("php", "8.3.1"),
			},
			expected: map[string]string{
				"process.runtime.name":    "cpython",
				"process.runtime.version": "3.11.4",
			},
		},
		"no interpreter reports a runtime": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: &fakeInstance{},
				libOID: &fakeInstance{},
			},
			mainExecutableID: exeOID,
		},
		"version omitted when unknown": {
			interpreters: map[util.OnDiskFileIdentifier]interpreter.Instance{
				exeOID: runtime("erlang", ""),
			},
			mainExecutableID: exeOID,
			expected: map[string]string{
				"process.runtime.name": "erlang",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var state any
			attrs, changed := enrich(t, &procmeta.ResourceRequest{
				Interpreters:     test.interpreters,
				MainExecutableID: test.mainExecutableID,
				State:            &state,
			})
			require.Equal(t, test.expected, attrs)
			require.Equal(t, test.expected != nil, changed)
		})
	}
}

// TestEnricher_ResolvesOnceUntilExec verifies that the runtime is resolved as soon
// as an interpreter attaches, then left alone: re-resolving on every
// synchronization would let the reported runtime flip as more interpreters attach.
// An exec replaces the program, so it starts over.
func TestEnricher_ResolvesOnceUntilExec(t *testing.T) {
	e := runtimeinfo.NewEnricher()
	exeOID := oid(1)
	var state any

	// No interpreter attached yet: nothing to report, but keep looking.
	req := &procmeta.ResourceRequest{MainExecutableID: exeOID, State: &state}
	_, changed := e.EnrichResource(req)
	require.False(t, changed)
	require.Nil(t, state)

	// An interpreter attaches.
	req.Interpreters = map[util.OnDiskFileIdentifier]interpreter.Instance{
		exeOID: runtime("cpython", "3.11.4"),
	}
	res, changed := e.EnrichResource(req)
	require.True(t, changed)
	v, ok := res.Attributes().Get("process.runtime.version")
	require.True(t, ok)
	require.Equal(t, "3.11.4", v.Str())

	// Already resolved: a second interpreter does not change what is reported.
	req.Interpreters[oid(2)] = runtime("cpython", "3.9.1")
	_, changed = e.EnrichResource(req)
	require.False(t, changed)

	// An exec replaces the program, so the runtime is resolved again.
	req.NewProcessOrExec = true
	req.Interpreters = map[util.OnDiskFileIdentifier]interpreter.Instance{
		exeOID: runtime("ruby", "3.3.0"),
	}
	res, changed = e.EnrichResource(req)
	require.True(t, changed)
	v, ok = res.Attributes().Get("process.runtime.name")
	require.True(t, ok)
	require.Equal(t, "ruby", v.Str())
}

func TestEnricher_ResourceConfig(t *testing.T) {
	// The runtime is derived from the interpreters the process manager passes in,
	// so this enricher needs no env vars and no mappings of its own.
	cfg := runtimeinfo.NewEnricher().ResourceConfig()
	require.Empty(t, cfg.EnvVars)
	require.Nil(t, cfg.WantMapping)
}
