package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"debug/elf"
	"errors"
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/procmeta"
	"go.opentelemetry.io/ebpf-profiler/process"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type TestInstance struct {
	interpreter.InstanceStubs
	info                  libc.LibcInfo
	syncMappings          []process.RawMapping
	usesAnonymousMappings bool
}

func (ti *TestInstance) UpdateLibcInfo(_ interpreter.EbpfHandler, _ libpf.PID, info libc.LibcInfo) error {
	ti.info = info
	return nil
}

func (ti *TestInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (ti *TestInstance) UsesAnonymousMappings() bool {
	return ti.usesAnonymousMappings
}

func (ti *TestInstance) SynchronizeMappings(_ interpreter.EbpfHandler,
	_ reporter.ExecutableReporter, _ process.Process, mappings []process.RawMapping,
) error {
	ti.syncMappings = append([]process.RawMapping(nil), mappings...)
	return nil
}

type testInterpreterData struct {
	attach func(interpreter.EbpfHandler, libpf.PID, libpf.Address, remotememory.RemoteMemory) (
		interpreter.Instance, error)
}

func (td *testInterpreterData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	return td.attach(ebpf, pid, bias, rm)
}

func (td *testInterpreterData) Unload(interpreter.EbpfHandler) {}

type testEbpfHandler struct {
	pidPageMappingInfoUpdates []struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}
}

func (h *testEbpfHandler) UpdateInterpreterOffsets(uint16, host.FileID, []util.Range) error {
	return nil
}

func (h *testEbpfHandler) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}

func (h *testEbpfHandler) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

func (h *testEbpfHandler) UpdatePidInterpreterMapping(
	libpf.PID, lpm.Prefix, uint8, host.FileID, uint64,
) error {
	return nil
}

func (h *testEbpfHandler) DeletePidInterpreterMapping(libpf.PID, lpm.Prefix) error {
	return nil
}

func (h *testEbpfHandler) RemoveReportedPID(libpf.PID) {}

func (h *testEbpfHandler) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error {
	return nil
}

func (h *testEbpfHandler) UpdateExeIDToStackDeltas(
	host.FileID, []pmebpf.StackDeltaEBPF,
) (uint16, error) {
	return 0, nil
}

func (h *testEbpfHandler) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	return nil
}

func (h *testEbpfHandler) UpdateStackDeltaPages(host.FileID, []uint16, uint16, uint64) error {
	return nil
}

func (h *testEbpfHandler) DeleteStackDeltaPage(host.FileID, uint64) error {
	return nil
}

func (h *testEbpfHandler) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix,
	fileID, bias uint64,
) error {
	h.pidPageMappingInfoUpdates = append(h.pidPageMappingInfoUpdates, struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}{pid: pid, prefix: prefix, fileID: fileID, bias: bias})
	return nil
}

func (h *testEbpfHandler) DeletePidPageMappingInfo(libpf.PID, []lpm.Prefix) (uint64, error) {
	return 0, nil
}

func (h *testEbpfHandler) CollectMetrics() []metrics.Metric {
	return nil
}

func (h *testEbpfHandler) SupportsLPMTrieBatchOperations() bool {
	return false
}

type testProcess struct {
	pid      libpf.PID
	exe      libpf.String
	mappings []process.RawMapping
}

func (tp *testProcess) PID() libpf.PID {
	return tp.pid
}

func (tp *testProcess) GetMachineData() process.MachineData {
	return process.MachineData{}
}

func (tp *testProcess) GetProcessMeta() process.Meta {
	return process.Meta{Executable: tp.exe}
}

func (tp *testProcess) ProcBase() string {
	return fmt.Sprintf("/proc/%d/", tp.pid)
}

func (tp *testProcess) GetExe() (libpf.String, error) {
	return tp.exe, nil
}

func (tp *testProcess) IterateMappings(callback func(process.RawMapping) bool) (uint32, error) {
	for _, m := range tp.mappings {
		if !callback(m) {
			return 0, process.ErrCallbackStopped
		}
	}
	return 0, nil
}

func (tp *testProcess) GetThreads() ([]process.ThreadInfo, error) {
	return nil, nil
}

func (tp *testProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{}
}

func (tp *testProcess) OpenMappingFile(*process.RawMapping) (process.ReadAtCloser, error) {
	return nil, errors.New("not implemented")
}

func (tp *testProcess) GetMappingFileLastModified(*process.RawMapping) int64 {
	return 0
}

func (tp *testProcess) CalculateMappingFileID(*process.RawMapping) (libpf.FileID, error) {
	return libpf.FileID{}, errors.New("not implemented")
}

func (tp *testProcess) Close() error {
	return nil
}

func (tp *testProcess) OpenELF(string) (*pfelf.File, error) {
	return nil, errors.New("not implemented")
}

func TestAssignLibcInfoMergesLibcInfo(t *testing.T) {
	assert := assert.New(t)

	pid := libpf.PID(1)
	odid := util.OnDiskFileIdentifier{
		DeviceID: 1,
		InodeNum: 1,
	}

	interp := TestInstance{}

	pm := ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				odid: &interp,
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {},
		},
	}

	libcInfoWithTSD := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{
			Offset:     8,
			Multiplier: 8,
			Indirect:   0,
		},
		DTVInfo: libc.DTVInfo{},
	}
	pm.assignLibcInfo(pid, &libcInfoWithTSD)

	assert.Equal(libcInfoWithTSD, interp.info)

	libcInfoWithDTV := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{},
		DTVInfo: libc.DTVInfo{
			Offset:     -8,
			Multiplier: 16,
		},
	}

	merged := libcInfoWithTSD
	merged.Merge(libcInfoWithDTV)

	pm.assignLibcInfo(pid, &libcInfoWithDTV)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)

	pm.assignLibcInfo(pid, &merged)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)
}

func TestHandleNewInterpreterRecordsAnonymousMappingInterestLocally(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return &TestInstance{usesAnonymousMappings: true}, nil
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, oid, data, false)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oid)
	require.True(anonymousMappingsWanted)
}

func TestHandleNewInterpreterDoesNotAssignOnAttachFailure(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	attachErr := errors.New("attach failed")
	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return nil, attachErr
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, oid, data, false)
	require.ErrorIs(err, attachErr)
	require.False(anonymousMappingsWanted)
	require.NotContains(pm.interpreters, pid)
}

func TestHandleNewInterpreterKeepsExistingInterpreter(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oldOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	newOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	pm := &ProcessManager{
		ebpf: &testEbpfHandler{},
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oldOID: &TestInstance{usesAnonymousMappings: true}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			return &TestInstance{usesAnonymousMappings: true}, nil
		},
	}

	anonymousMappingsWanted, err := pm.handleNewInterpreter(
		process.New(pid, pid), 0, newOID, data, true)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oldOID)
	require.Contains(pm.interpreters[pid], newOID)
	require.True(anonymousMappingsWanted)
}

func TestProcessRemovedInterpretersClearsAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{usesAnonymousMappings: true}},
		},
	}

	anonymousMappingsWanted := pm.processRemovedInterpreters(
		pid, libpf.Set[util.OnDiskFileIdentifier]{})

	require.NotContains(pm.interpreters, pid)
	require.False(anonymousMappingsWanted)
}

func TestProcessRemovedInterpretersKeepsAnonymousMappingInterestWhenInterpreterRemains(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	keptOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	removedOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				keptOID:    &TestInstance{usesAnonymousMappings: true},
				removedOID: &TestInstance{usesAnonymousMappings: true},
			},
		},
	}

	anonymousMappingsWanted := pm.processRemovedInterpreters(pid,
		libpf.Set[util.OnDiskFileIdentifier]{keptOID: libpf.Void{}})

	require.Contains(pm.interpreters[pid], keptOID)
	require.NotContains(pm.interpreters[pid], removedOID)
	require.True(anonymousMappingsWanted)
}

func TestProcessPIDExitRemovesInterpreters(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				{DeviceID: 1, InodeNum: 2}: &TestInstance{usesAnonymousMappings: true},
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.processPIDExit(pid)
	require.NotContains(pm.interpreters, pid)
}

func TestSynchronizeProcessUpdatesAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{usesAnonymousMappings: true}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.SynchronizeProcess(&testProcess{pid: pid})

	require.Equal([]struct {
		pid    libpf.PID
		prefix lpm.Prefix
		fileID uint64
		bias   uint64
	}{{pid: pid, prefix: dummyPrefix}}, ebpf.pidPageMappingInfoUpdates)
}

func TestSynchronizeProcessSkipsDllMappingsWithoutAnonymousMappingInterest(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	instance := &TestInstance{}
	interpreterMapping := process.RawMapping{
		Vaddr:  0x1000,
		Length: 0x1000,
		Flags:  elf.PF_R | elf.PF_X,
		Device: oid.DeviceID,
		Inode:  oid.InodeNum,
		Path:   "/tmp/interpreter",
	}
	pm := &ProcessManager{
		ebpf:                     &testEbpfHandler{},
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: instance},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {
				mappings: []Mapping{
					{
						Vaddr:  libpf.Address(interpreterMapping.Vaddr),
						Length: interpreterMapping.Length,
						Device: interpreterMapping.Device,
						Inode:  interpreterMapping.Inode,
						FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
							File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
								FileID:   libpf.NewFileID(1, 0),
								FileName: libpf.Intern("interpreter"),
							}),
							Start: 0,
							End:   libpf.Address(interpreterMapping.Length),
						}),
					},
				},
			},
		},
		exitEvents: make(map[libpf.PID]times.KTime),
	}

	pm.SynchronizeProcess(&testProcess{
		pid: pid,
		mappings: []process.RawMapping{
			interpreterMapping,
			{
				Vaddr:  0x3000,
				Length: 0x1000,
				Flags:  elf.PF_R,
				Device: 3,
				Inode:  4,
				Path:   "/tmp/assembly.dll",
			},
		},
	})

	require.Empty(instance.syncMappings)
}

func TestIsInterpreterMapping(t *testing.T) {
	tests := []struct {
		name string
		m    process.RawMapping
		want bool
	}{
		{
			name: "anonymous executable",
			m:    process.RawMapping{Flags: elf.PF_R | elf.PF_X},
			want: true,
		},
		{
			name: "anonymous non-executable",
			m:    process.RawMapping{Flags: elf.PF_R},
		},
		{
			name: "dll",
			m:    process.RawMapping{Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
			want: true,
		},
		{
			name: "file backed executable",
			m:    process.RawMapping{Flags: elf.PF_R | elf.PF_X, Path: "/tmp/interpreter"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, isInterpreterMapping(&test.m))
		})
	}
}

func TestInterpreterMappingCollectorFlushesFirstPassMappingsAfterEnable(t *testing.T) {
	collector := newInterpreterMappingCollector(8)
	pending := []process.RawMapping{
		{Vaddr: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x2000, Flags: elf.PF_R},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x4000, Flags: elf.PF_R | elf.PF_X, Path: "/tmp/interpreter"},
	}
	for _, m := range pending {
		collector.add(m, false)
	}
	require.Empty(t, collector.mappings())

	collector.enable()
	collector.add(process.RawMapping{
		Vaddr: 0x5000,
		Flags: elf.PF_R,
		Path:  "/tmp/assembly.dll",
	}, true)

	require.Equal(t, []process.RawMapping{
		{Vaddr: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x5000, Flags: elf.PF_R, Path: "/tmp/assembly.dll"},
	}, collector.mappings())
}

// TestSynchronizeProcessRunEnrichers verifies that meta enrichers run at process
// discovery and again when the executable changes, so that enricher-produced
// ExtraMeta is not lost when process metadata is refetched.
func TestSynchronizeProcessRunEnrichers(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	key := libpf.Intern("test.key")
	enricherCalls := 0
	reasons := []process.Reason{}
	enricher := process.MetaEnricherFunc(func(req *process.MetaRequest, meta *process.Meta) {
		enricherCalls++
		reasons = append(reasons, req.Reason)
		require.Equal(fmt.Sprintf("/proc/%d/", pid), req.ProcBase)
		require.Equal(pid, req.Process.PID())
		meta.ExtraMeta = map[libpf.String]string{key: meta.Executable.String()}
	})

	pm := &ProcessManager{
		ebpf:             &testEbpfHandler{},
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: make(map[libpf.PID]*processInfo),
		exitEvents:       make(map[libpf.PID]times.KTime),
		metaEnrichers:    []process.MetaEnricher{enricher},
	}

	// Process first seen: gather and enrich metadata.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(1, enricherCalls)
	meta, _ := pm.metaForPID(pid)
	require.Equal("foobar", meta.ExtraMeta[key])

	// Unchanged executable: don't refetch metadata, don't enrich.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(1, enricherCalls)

	// Executable changed: refetch metadata and enrich.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobarbaz")})
	require.Equal(2, enricherCalls)
	meta, _ = pm.metaForPID(pid)
	require.Equal("foobarbaz", meta.ExtraMeta[key])

	require.Equal([]process.Reason{process.ReasonFirstSeen, process.ReasonExec}, reasons)
}

// testResourceEnricher is a ResourceEnricher whose behaviour each test controls
// through enrich.
type testResourceEnricher struct {
	cfg    procmeta.ResourceConfig
	calls  int
	reqs   []procmeta.ResourceRequest
	enrich func(req *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool)
}

func (e *testResourceEnricher) ResourceConfig() procmeta.ResourceConfig {
	return e.cfg
}

func (e *testResourceEnricher) EnrichResource(req *procmeta.ResourceRequest) (
	*pcommon.Resource, bool,
) {
	e.calls++
	e.reqs = append(e.reqs, *req)
	if e.enrich == nil {
		return nil, false
	}
	return e.enrich(req, e.calls)
}

// resourceWithAttr builds a single-attribute resource.
func resourceWithAttr(key, value string) *pcommon.Resource {
	r := pcommon.NewResource()
	r.Attributes().PutStr(key, value)
	return &r
}

// resourceAttrs flattens a resource's string attributes, or returns nil.
func resourceAttrs(r *pcommon.Resource) map[string]string {
	if r == nil {
		return nil
	}
	attrs := make(map[string]string, r.Attributes().Len())
	r.Attributes().Range(func(k string, v pcommon.Value) bool {
		attrs[k] = v.Str()
		return true
	})
	return attrs
}

func newTestProcessManager(metaEnrichers []process.MetaEnricher,
	resourceEnrichers []procmeta.ResourceEnricher,
) *ProcessManager {
	var mappingFilters []mappingFilter
	for i, e := range resourceEnrichers {
		if want := e.ResourceConfig().WantMapping; want != nil {
			mappingFilters = append(mappingFilters, mappingFilter{enricher: i, want: want})
		}
	}
	return &ProcessManager{
		ebpf:              &testEbpfHandler{},
		interpreters:      make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo:  make(map[libpf.PID]*processInfo),
		exitEvents:        make(map[libpf.PID]times.KTime),
		metaEnrichers:     metaEnrichers,
		resourceEnrichers: resourceEnrichers,
		mappingFilters:    mappingFilters,
	}
}

// TestSynchronizeProcessRunsResourceEnrichers verifies that resource enrichers run
// on every synchronization, unlike meta enrichers, so that attributes which only
// resolve after the process is first observed are still picked up.
func TestSynchronizeProcessRunsResourceEnrichers(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	// Contributes nothing on the first call, then an attribute on the second, as a
	// late-resolving enricher would.
	enricher := &testResourceEnricher{
		enrich: func(_ *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			if call == 1 {
				return nil, false
			}
			return resourceWithAttr("late.attr", "resolved"), true
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(1, enricher.calls)
	_, resource := pm.metaForPID(pid)
	require.Nil(resource)
	require.True(enricher.reqs[0].NewProcessOrExec)
	require.Equal(fmt.Sprintf("/proc/%d/", pid), enricher.reqs[0].ProcBase)
	require.Equal(pid, enricher.reqs[0].Process.PID())

	// Same executable: the meta enrichers would not run, but this one does.
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(2, enricher.calls)
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"late.attr": "resolved"}, resourceAttrs(resource))

	// Reporting no change keeps the published contribution.
	enricher.enrich = func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
		return nil, false
	}
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	require.Equal(3, enricher.calls)
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"late.attr": "resolved"}, resourceAttrs(resource))

	// Reporting a change with a nil resource withdraws it.
	enricher.enrich = func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
		return nil, true
	}
	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	_, resource = pm.metaForPID(pid)
	require.Nil(resource)
}

// TestSynchronizeProcessResourceEnricherNewProcessOrExec verifies the flag that
// tells an enricher to discard previously derived state: set on the first
// synchronization of a process and on the one following an exec, clear otherwise.
func TestSynchronizeProcessResourceEnricherNewProcessOrExec(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	exe := libpf.Intern("/bin/foobar")

	enricher := &testResourceEnricher{}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	// A process is considered new until it has known mappings, so seed one that
	// the synchronization below can match and reuse. Reusing it also keeps the
	// mapping out of the ELF-parsing path, which needs a fuller ProcessManager.
	rawMapping := process.RawMapping{
		Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X,
		Device: 7, Inode: 8, Path: exe.String(),
	}
	pm.pidToProcessInfo[pid] = &processInfo{
		meta: process.Meta{Executable: exe},
		mappings: []Mapping{{
			Vaddr:  libpf.Address(rawMapping.Vaddr),
			Length: rawMapping.Length,
			Device: rawMapping.Device,
			Inode:  rawMapping.Inode,
			FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
				File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
					FileID:   libpf.NewFileID(1, 0),
					FileName: libpf.Intern("foobar"),
				}),
				Start: 0,
				End:   libpf.Address(rawMapping.Length),
			}),
		}},
		contributions: make([]*pcommon.Resource, 1),
		enricherState: make([]any, 1),
	}

	// Known process, unchanged executable.
	proc := &testProcess{pid: pid, exe: exe, mappings: []process.RawMapping{rawMapping}}
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	require.Len(enricher.reqs, 2)
	require.False(enricher.reqs[0].NewProcessOrExec)
	require.False(enricher.reqs[1].NewProcessOrExec)

	// Executable changed.
	pm.SynchronizeProcess(&testProcess{
		pid: pid, exe: libpf.Intern("/bin/other"),
		mappings: []process.RawMapping{rawMapping},
	})
	require.Len(enricher.reqs, 3)
	require.True(enricher.reqs[2].NewProcessOrExec)
}

// TestSynchronizeProcessMergesResourceContributions verifies that contributions
// from several enrichers are merged, with later enrichers winning on key
// collisions, and that each enricher's contribution is tracked independently.
func TestSynchronizeProcessMergesResourceContributions(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	first := &testResourceEnricher{
		enrich: func(_ *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
			r := pcommon.NewResource()
			r.Attributes().PutStr("shared", "first")
			r.Attributes().PutStr("only.first", "1")
			return &r, true
		},
	}
	second := &testResourceEnricher{
		enrich: func(_ *procmeta.ResourceRequest, call int) (*pcommon.Resource, bool) {
			// Contribute only on the first call, to check the stored contribution
			// still takes part in later merges.
			if call > 1 {
				return nil, false
			}
			return resourceWithAttr("shared", "second"), true
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{first, second})

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	_, resource := pm.metaForPID(pid)
	require.Equal(map[string]string{"shared": "second", "only.first": "1"},
		resourceAttrs(resource))

	pm.SynchronizeProcess(&testProcess{pid: pid, exe: libpf.Intern("foobar")})
	_, resource = pm.metaForPID(pid)
	require.Equal(map[string]string{"shared": "second", "only.first": "1"},
		resourceAttrs(resource))
}

// TestSynchronizeProcessResourceEnricherState verifies that per-process enricher
// state survives across synchronizations and is dropped, and closed, on exit.
func TestSynchronizeProcessResourceEnricherState(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	var seen []int
	enricher := &testResourceEnricher{
		enrich: func(req *procmeta.ResourceRequest, _ int) (*pcommon.Resource, bool) {
			state, _ := (*req.State).(*testEnricherState)
			if state == nil {
				state = &testEnricherState{}
				*req.State = state
			}
			state.counter++
			seen = append(seen, state.counter)
			return nil, false
		},
	}
	pm := newTestProcessManager(nil, []procmeta.ResourceEnricher{enricher})

	proc := &testProcess{pid: pid, exe: libpf.Intern("foobar")}
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	pm.SynchronizeProcess(proc)
	require.Equal([]int{1, 2, 3}, seen)

	pm.mu.RLock()
	state, _ := pm.pidToProcessInfo[pid].enricherState[0].(*testEnricherState)
	pm.mu.RUnlock()
	require.NotNil(state)
	require.False(state.closed)

	// Process exit drops the state, closing it on the way out.
	pm.processPIDExit(pid)
	pm.ProcessedUntil(times.GetKTime())
	require.True(state.closed)

	pm.mu.RLock()
	_, tracked := pm.pidToProcessInfo[pid]
	pm.mu.RUnlock()
	require.False(tracked)
}

type testEnricherState struct {
	counter int
	closed  bool
}

func (s *testEnricherState) Close() error {
	s.closed = true
	return nil
}

// TestSynchronizeProcessResourceEnricherMappings verifies that only the mappings
// an enricher's WantMapping filter selects are delivered to it, and that each
// enricher gets its own selection.
func TestSynchronizeProcessResourceEnricherMappings(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)

	wantsNamed := &testResourceEnricher{
		cfg: procmeta.ResourceConfig{
			WantMapping: func(m *process.RawMapping) bool { return m.Path == "[anon:MY_REGION]" },
		},
	}
	wantsNothing := &testResourceEnricher{}
	pm := newTestProcessManager(nil,
		[]procmeta.ResourceEnricher{wantsNamed, wantsNothing})

	pm.SynchronizeProcess(&testProcess{
		pid: pid,
		exe: libpf.Intern("foobar"),
		mappings: []process.RawMapping{
			{Vaddr: 0x1000, Flags: elf.PF_R, Path: "/bin/foobar"},
			{Vaddr: 0x2000, Flags: elf.PF_R | elf.PF_W, Path: "[anon:MY_REGION]"},
			{Vaddr: 0x3000, Flags: elf.PF_R | elf.PF_W},
		},
	})

	require.Len(wantsNamed.reqs, 1)
	require.Equal([]process.RawMapping{
		{Vaddr: 0x2000, Flags: elf.PF_R | elf.PF_W, Path: "[anon:MY_REGION]"},
	}, wantsNamed.reqs[0].Mappings)

	require.Len(wantsNothing.reqs, 1)
	require.Empty(wantsNothing.reqs[0].Mappings)
}
