// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package processcontext_test

import (
	"debug/elf"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
	"go.opentelemetry.io/ebpf-profiler/procmeta/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	headerAddr  = 0x1000
	payloadAddr = 0x2000
)

var errNotImplemented = errors.New("not implemented")

// fakeProcess is a process.Process exposing nothing but a PID and a remote memory
// reader, which is all a resource enricher needs from it.
type fakeProcess struct {
	pid libpf.PID
	rm  remotememory.RemoteMemory
}

func (p *fakeProcess) PID() libpf.PID                             { return p.pid }
func (p *fakeProcess) GetRemoteMemory() remotememory.RemoteMemory { return p.rm }
func (p *fakeProcess) GetMachineData() process.MachineData        { return process.MachineData{} }
func (p *fakeProcess) GetProcessMeta() process.Meta               { return process.Meta{} }
func (p *fakeProcess) ProcBase() string                           { return "" }
func (p *fakeProcess) GetExe() (libpf.String, error)              { return libpf.NullString, nil }
func (p *fakeProcess) GetThreads() ([]process.ThreadInfo, error)  { return nil, nil }
func (p *fakeProcess) Close() error                               { return nil }

func (p *fakeProcess) IterateMappings(func(process.RawMapping) bool) (uint32, error) {
	return 0, nil
}

func (p *fakeProcess) OpenMappingFile(*process.RawMapping) (process.ReadAtCloser, error) {
	return nil, errNotImplemented
}

func (p *fakeProcess) GetMappingFileLastModified(*process.RawMapping) int64 { return 0 }

func (p *fakeProcess) CalculateMappingFileID(*process.RawMapping) (libpf.FileID, error) {
	return libpf.FileID{}, errNotImplemented
}

func (p *fakeProcess) OpenELF(string) (*pfelf.File, error) { return nil, errNotImplemented }

// contextMapping is the mapping the enricher's filter selects.
var contextMapping = process.RawMapping{Vaddr: headerAddr, Path: "[anon:OTEL_CTX]"}

// attrStr returns a resource's string attribute, requiring it to be present.
func attrStr(t *testing.T, res *pcommon.Resource, key string) string {
	t.Helper()
	require.NotNil(t, res)
	v, ok := res.Attributes().Get(key)
	require.True(t, ok, "attribute %q missing", key)
	return v.Str()
}

// publishedContext returns a process whose memory holds a valid context published
// at the given timestamp.
func publishedContext(t *testing.T, publishedAtNs uint64) *fakeProcess {
	t.Helper()
	payload, err := proto.Marshal(&testContext)
	require.NoError(t, err)

	mock := newMockReader()
	mock.writeAt(headerAddr, createValidHeader(uint32(len(payload)), payloadAddr, publishedAtNs))
	mock.writeAt(payloadAddr, payload)
	return &fakeProcess{pid: 1, rm: remotememory.RemoteMemory{ReaderAt: mock}}
}

func TestEnricher_ResourceConfig(t *testing.T) {
	cfg := processcontext.NewEnricher().ResourceConfig()

	require.Equal(t, processcontext.EnvVars(), cfg.EnvVars)
	require.NotNil(t, cfg.WantMapping)
	require.True(t, cfg.WantMapping(&process.RawMapping{Path: "[anon:OTEL_CTX]"}))
	require.True(t, cfg.WantMapping(&process.RawMapping{Path: "/memfd:OTEL_CTX"}))
	require.False(t, cfg.WantMapping(&process.RawMapping{Path: "/usr/lib/libc.so.6"}))
	// An executable mapping is never a context mapping.
	require.False(t, cfg.WantMapping(&process.RawMapping{
		Path: "[anon:OTEL_CTX]", Flags: elf.PF_R | elf.PF_X,
	}))
}

// TestEnricher_NoMapping covers a process that never publishes a context region:
// the attributes derived from the environment are contributed on first sight, and
// nothing changes afterwards.
func TestEnricher_NoMapping(t *testing.T) {
	e := processcontext.NewEnricher()
	var state any
	req := &procmeta.ResourceRequest{
		Process:          &fakeProcess{pid: 1},
		NewProcessOrExec: true,
		EnvVars: map[libpf.String]libpf.String{
			libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("from-env"),
		},
		State: &state,
	}

	res, changed := e.EnrichResource(req)
	require.True(t, changed)
	require.Equal(t, "from-env", attrStr(t, res, "service.name"))

	// Steady state: no context region, nothing published before, nothing to say.
	req.NewProcessOrExec = false
	_, changed = e.EnrichResource(req)
	require.False(t, changed)
}

// TestEnricher_PublishedContext covers the lifecycle of a context region that
// appears after the process was first seen, is then republished, and finally goes
// away.
func TestEnricher_PublishedContext(t *testing.T) {
	e := processcontext.NewEnricher()
	var state any
	envVars := map[libpf.String]libpf.String{
		libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("from-env"),
	}

	// First synchronization, before the process published anything.
	req := &procmeta.ResourceRequest{
		Process:          &fakeProcess{pid: 1},
		NewProcessOrExec: true,
		EnvVars:          envVars,
		State:            &state,
	}
	res, changed := e.EnrichResource(req)
	require.True(t, changed)
	require.Equal(t, "from-env", attrStr(t, res, "service.name"))

	// The region shows up: the payload wins over the environment.
	req = &procmeta.ResourceRequest{
		Process:  publishedContext(t, 1000),
		EnvVars:  envVars,
		Mappings: []process.RawMapping{contextMapping},
		State:    &state,
	}
	res, changed = e.EnrichResource(req)
	require.True(t, changed)
	require.Equal(t, "test-service", attrStr(t, res, "service.name"))

	// Same payload on the next synchronization: keep the published contribution
	// rather than rebuilding an identical one.
	_, changed = e.EnrichResource(req)
	require.False(t, changed)

	// Republished with a newer timestamp: read it again.
	req.Process = publishedContext(t, 2000)
	res, changed = e.EnrichResource(req)
	require.True(t, changed)
	require.Equal(t, "test-service", attrStr(t, res, "service.name"))

	// The region disappears, as it does when the process tears it down. Attribution
	// falls back to the environment.
	req.Mappings = nil
	res, changed = e.EnrichResource(req)
	require.True(t, changed)
	require.Equal(t, "from-env", attrStr(t, res, "service.name"))
}

// TestEnricher_ExecRebuildsContext verifies that an exec discards the timestamp
// remembered for the previous program, so a context republished at a lower
// timestamp is not mistaken for one already seen.
func TestEnricher_ExecRebuildsContext(t *testing.T) {
	e := processcontext.NewEnricher()
	var state any

	req := &procmeta.ResourceRequest{
		Process:  publishedContext(t, 2000),
		Mappings: []process.RawMapping{contextMapping},
		State:    &state,
	}
	_, changed := e.EnrichResource(req)
	require.True(t, changed)

	// A context published earlier than the one already seen is ignored...
	req.Process = publishedContext(t, 1000)
	_, changed = e.EnrichResource(req)
	require.False(t, changed)

	// ...unless the process execed, which invalidates everything derived from the
	// previous program.
	req.NewProcessOrExec = true
	res, changed := e.EnrichResource(req)
	require.True(t, changed)
	require.Equal(t, "test-service", attrStr(t, res, "service.name"))
}
