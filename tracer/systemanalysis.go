// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	errSystemAnalysisNotHandled = errors.New("system analysis request was not handled")
	errSystemAnalysisFailed     = errors.New("system analysis helper failed")
)

const systemAnalysisRetryTimeout = 250 * time.Millisecond

// systemAnalysisProgNames maps system analysis work types to program names.
var systemAnalysisProgNames = map[uint32]string{
	support.SysAnalysisReadMem:  "read_kernel_memory",
	support.SysAnalysisReadTask: "read_task_struct",
}

// systemAnalysisProbes runs tid-guarded system analysis requests. Each
// program only services requests carrying its work type, so both probes
// can stay attached at the same time. The caller owns the maps.
type systemAnalysisProbes struct {
	coll           *cebpf.CollectionSpec
	systemAnalysis *cebpf.Map
	progs          map[string]*cebpf.Program
	links          map[string]link.Link

	// last describes the most recent request.
	last systemAnalysisAttempt
}

// systemAnalysisAttempt holds the retry diagnostics of a request.
type systemAnalysisAttempt struct {
	retries int
	waited  time.Duration
	// requesterCPUs counts the retries per CPU the requester polled from.
	requesterCPUs map[int]int
	// migratedCPU is the CPU that serviced the request once the requester
	// was moved there, or -1.
	migratedCPU     int
	recursionMisses uint64
	data            support.SystemAnalysis
	// threadFlags is the thread_info flags word of the requester, read once
	// the request is known to be unhandled.
	threadFlags string
}

func (a *systemAnalysisAttempt) String() string {
	lastCPU := "none"
	if a.data.PidRuns != 0 {
		lastCPU = fmt.Sprint(a.data.LastCpu)
	}
	s := fmt.Sprintf("retries=%d waited=%v requester_cpus=%v migrated_cpu=%d "+
		"armed_runs=%d requester_process_runs=%d last_tid=%d last_cpu=%s recursion_misses=%d",
		a.retries, a.waited, a.requesterCPUs, a.migratedCPU,
		a.data.Runs, a.data.PidRuns, a.data.LastTid, lastCPU, a.recursionMisses)
	if a.threadFlags != "" {
		s += " thread_flags=" + a.threadFlags
	}
	return s
}

func newSystemAnalysisProbes(coll *cebpf.CollectionSpec, systemAnalysis *cebpf.Map) *systemAnalysisProbes {
	return &systemAnalysisProbes{
		coll:           coll,
		systemAnalysis: systemAnalysis,
		progs:          make(map[string]*cebpf.Program),
		links:          make(map[string]link.Link),
	}
}

// loadProgram loads the named analysis program on first use. It stays loaded
// until Close so its stats can be queried across attachments.
func (p *systemAnalysisProbes) loadProgram(progName string) (*cebpf.Program, error) {
	if prog, ok := p.progs[progName]; ok {
		return prog, nil
	}

	progSpec, ok := p.coll.Programs[progName]
	if !ok {
		return nil, fmt.Errorf("program %s does not exist", progName)
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to adjust rlimit: %w", err)
	}
	defer restoreRlimit()

	prog, err := cebpf.NewProgram(progSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", progName, err)
	}
	p.progs[progName] = prog
	return prog, nil
}

// ensureAttached loads and attaches the named analysis program on first use.
func (p *systemAnalysisProbes) ensureAttached(progName string) error {
	if _, ok := p.links[progName]; ok {
		return nil
	}

	prog, err := p.loadProgram(progName)
	if err != nil {
		return err
	}

	var progLink link.Link
	switch prog.Type() {
	case cebpf.RawTracepoint:
		progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: prog,
		})
	case cebpf.TracePoint:
		progLink, err = link.Tracepoint("syscalls", "sys_enter_bpf", prog, nil)
	default:
		err = fmt.Errorf("invalid system analysis program type '%v'", prog.Type())
	}
	if err != nil {
		return fmt.Errorf("failed to attach %s to tracepoint: %w", progName, err)
	}

	p.links[progName] = progLink
	return nil
}

// detach removes the probes but keeps the programs loaded.
func (p *systemAnalysisProbes) detach() {
	for name, progLink := range p.links {
		if err := progLink.Close(); err != nil {
			log.Warnf("Failed to detach %s: %v", name, err)
		}
		delete(p.links, name)
	}
}

func (p *systemAnalysisProbes) Close() {
	p.detach()
	for name, prog := range p.progs {
		_ = prog.Close()
		delete(p.progs, name)
	}
}

// readKernelCode reads size bytes from the given kernel address.
func (p *systemAnalysisProbes) readKernelCode(address libpf.SymbolValue, size int) ([]byte, error) {
	code, _, err := p.execute(support.SysAnalysisReadMem, address, size)
	if err != nil {
		log.Warnf("Failed to load code: %v.\n"+
			"Possible reasons include using a kernel without syscall tracepoints enabled.", err)
	}
	return code, err
}

// readTaskStruct reads bytes from the given offset of the current task_struct.
func (p *systemAnalysisProbes) readTaskStruct(address libpf.SymbolValue, size int) ([]byte, uint64, error) {
	return p.execute(support.SysAnalysisReadTask, address, size)
}

// execute services a read request via the analysis program of the given
// work type. For read_task_struct, the returned addr is the struct
// pt_regs pointer on the entry stack.
func (p *systemAnalysisProbes) execute(work uint32, address libpf.SymbolValue, size int,
) (code []byte, addr uint64, err error) {
	if p.systemAnalysis == nil {
		return nil, 0, errors.New("system_analysis map is not available")
	}

	progName, ok := systemAnalysisProgNames[work]
	if !ok {
		return nil, 0, fmt.Errorf("invalid system analysis work %d", work)
	}

	maxSize := int(unsafe.Sizeof(support.SystemAnalysis{}.Code))
	if size < 0 || size > maxSize {
		return nil, 0, fmt.Errorf("invalid read size for system_analysis %d", size)
	}
	if size == 0 {
		size = maxSize
	}

	// Pin the thread so only its syscalls service the tid-guarded request.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = p.ensureAttached(progName); err != nil {
		return nil, 0, err
	}
	prog := p.progs[progName]
	missesBefore := recursionMisses(prog)

	systemAnalysis := p.systemAnalysis
	key0 := uint32(0)
	data := support.SystemAnalysis{
		Type:    work,
		Tid:     uint32(unix.Gettid()),
		Size:    uint32(size),
		Address: uint64(address),
		Pid:     uint32(unix.Getpid()),
		LastCpu: math.MaxUint32,
	}

	if err = systemAnalysis.Update(unsafe.Pointer(&key0), unsafe.Pointer(&data),
		cebpf.UpdateAny); err != nil {
		return nil, 0, fmt.Errorf("failed to write system_analysis 0x%x: %w",
			address, err)
	}

	// The tracepoint services the request on entry of the next syscall of
	// this thread, which is the lookup below.
	p.last = systemAnalysisAttempt{migratedCPU: -1}
	err = systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data))
	if err == nil && data.Tid != 0 {
		p.last.requesterCPUs = make(map[int]int)
		start := time.Now()
		for ; time.Since(start) < systemAnalysisRetryTimeout; time.Sleep(5 * time.Millisecond) {
			p.last.retries++
			p.last.requesterCPUs[getCPU()]++
			if err = systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data)); err != nil || data.Tid == 0 {
				break
			}
		}
		if err == nil && data.Tid != 0 {
			p.last.migratedCPU, err = retryOnEachCPU(systemAnalysis, &data)
		}
		p.last.waited = time.Since(start)
		p.last.recursionMisses = recursionMisses(prog) - missesBefore
		p.last.data = data
		if err == nil && data.Tid == 0 {
			log.Warnf("System analysis %s request needed retries: %v", progName, &p.last)
		}
		if err == nil && data.Tid != 0 {
			p.last.threadFlags = p.threadFlags()
		}
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get analysis data: %w", err)
	}
	if err = validateSystemAnalysisResult(data, address); err != nil {
		if errors.Is(err, errSystemAnalysisNotHandled) {
			return nil, 0, fmt.Errorf("%s: %w (%v)", progName, err, &p.last)
		}
		return nil, 0, err
	}

	return data.Code[:size:size], data.Address, nil
}

// retryOnEachCPU moves the calling thread to each allowed CPU in turn and
// polls the request there. This tells a probe that never fires from one that
// does not fire on some CPU. It returns the CPU that serviced the request,
// or -1.
func retryOnEachCPU(systemAnalysis *cebpf.Map, data *support.SystemAnalysis) (int, error) {
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		return -1, fmt.Errorf("failed to get CPU affinity: %w", err)
	}
	defer func() { _ = unix.SchedSetaffinity(0, &allowed) }()

	key0 := uint32(0)
	for cpu := range len(allowed) * 64 {
		if !allowed.IsSet(cpu) {
			continue
		}
		var one unix.CPUSet
		one.Set(cpu)
		if err := unix.SchedSetaffinity(0, &one); err != nil {
			continue
		}
		for range 3 {
			if err := systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(data)); err != nil {
				return -1, err
			}
			if data.Tid == 0 {
				return cpu, nil
			}
		}
	}
	return -1, nil
}

// threadFlags formats the thread_info flags word of the calling thread. It
// uses a test run of read_task_struct, so it works when the syscall
// tracepoints do not fire. thread_info is the first member of task_struct.
func (p *systemAnalysisProbes) threadFlags() string {
	prog, err := p.loadProgram(systemAnalysisProgNames[support.SysAnalysisReadTask])
	if err != nil {
		return err.Error()
	}

	key0 := uint32(0)
	data := support.SystemAnalysis{
		Type: support.SysAnalysisReadTask,
		Tid:  uint32(unix.Gettid()),
		Size: 8,
		Pid:  uint32(unix.Getpid()),
	}
	if err = p.systemAnalysis.Update(unsafe.Pointer(&key0), unsafe.Pointer(&data),
		cebpf.UpdateAny); err != nil {
		return err.Error()
	}
	// The ctx is struct bpf_raw_tracepoint_args, args[0] is the pt_regs pointer.
	if _, err = prog.Run(&cebpf.RunOptions{Context: []uint64{0}}); err != nil {
		return fmt.Sprintf("test run failed: %v", err)
	}
	if err = p.systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data)); err != nil {
		return err.Error()
	}
	if data.Tid != 0 || data.Err != 0 {
		return fmt.Sprintf("unreadable (tid=%d err=%d)", data.Tid, data.Err)
	}

	flags := binary.NativeEndian.Uint64(data.Code[:8])
	if runtime.GOARCH == "arm64" {
		const tifSyscallTracepoint = 10
		return fmt.Sprintf("0x%x(TIF_SYSCALL_TRACEPOINT=%t)", flags,
			flags&(1<<tifSyscallTracepoint) != 0)
	}
	return fmt.Sprintf("0x%x", flags)
}

// getCPU returns the CPU the calling thread runs on, or -1.
func getCPU() int {
	var cpu uint32
	if _, _, errno := unix.RawSyscall(unix.SYS_GETCPU, uintptr(unsafe.Pointer(&cpu)), 0, 0); errno != 0 {
		return -1
	}
	return int(cpu)
}

// recursionMisses returns how often the kernel skipped prog because a BPF
// program was already running on that CPU.
func recursionMisses(prog *cebpf.Program) uint64 {
	stats, err := prog.Stats()
	if err != nil {
		return 0
	}
	return stats.RecursionMisses
}

func validateSystemAnalysisResult(data support.SystemAnalysis, address libpf.SymbolValue) error {
	if data.Tid != 0 {
		return fmt.Errorf("%w for tid %d at 0x%x", errSystemAnalysisNotHandled, data.Tid, address)
	}

	if data.Err != 0 {
		if data.Err < 0 {
			return fmt.Errorf("%w at 0x%x: %w (helper err=%d)", errSystemAnalysisFailed, address, syscall.Errno(-data.Err), data.Err)
		}

		return fmt.Errorf("%w at 0x%x: helper err=%d", errSystemAnalysisFailed, address, data.Err)
	}

	return nil
}
