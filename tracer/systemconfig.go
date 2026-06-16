// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/pacmask"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// sysConfigVars supports collecting system configuration information.
type sysConfigVars struct {
	tpbase_offset       uint64
	task_stack_offset   uint32
	stack_ptregs_offset uint32
}

var (
	errSystemAnalysisNotHandled = errors.New("system analysis request was not handled")
	errSystemAnalysisFailed     = errors.New("system analysis helper failed")
)

// memberByName resolves btf Member from a Struct with given name
func memberByName(t *btf.Struct, field string) (*btf.Member, error) {
	for i, m := range t.Members {
		if m.Name == field {
			return &t.Members[i], nil
		}
	}
	return nil, fmt.Errorf("member '%s' not found", field)
}

// calculateFieldOffset calculates the offset for given fieldSpec which
// can refer to field within nested structs.
func calculateFieldOffset(t btf.Type, fieldSpec string) (uint, error) {
	offset := uint(0)
	for field := range strings.SplitSeq(fieldSpec, ".") {
		st, ok := t.(*btf.Struct)
		if !ok {
			return 0, fmt.Errorf("field '%s' is not a struct", field)
		}

		member, err := memberByName(st, field)
		if err != nil {
			return 0, err
		}
		offset += uint(member.Offset.Bytes())
		t = member.Type
	}
	return offset, nil
}

// getTSDBaseFieldSpec returns the architecture specific name of the `task_struct`
// member that contains base address for thread specific data.
func getTSDBaseFieldSpec() string {
	//nolint:goconst
	switch runtime.GOARCH {
	case "amd64":
		return "thread.fsbase"
	case "arm64":
		return "thread.uw.tp_value"
	default:
		panic("not supported")
	}
}

// parseBTF resolves the SystemConfig data from kernel BTF
func parseBTF(vars *sysConfigVars) error {
	fh, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	defer fh.Close()

	spec, err := btf.LoadSplitSpecFromReader(fh, nil)
	if err != nil {
		return err
	}

	var taskStruct *btf.Struct
	err = spec.TypeByName("task_struct", &taskStruct)
	if err != nil {
		return err
	}

	stackOffset, err := calculateFieldOffset(taskStruct, "stack")
	if err != nil {
		return err
	}
	vars.task_stack_offset = uint32(stackOffset)

	tpbaseOffset, err := calculateFieldOffset(taskStruct, getTSDBaseFieldSpec())
	if err != nil {
		return err
	}
	vars.tpbase_offset = uint64(tpbaseOffset)

	return nil
}

// globalPID returns the kernel-visible TGID of the current process. Inside a PID
// namespace, os.Getpid() returns the namespace-local PID while the eBPF helper
// bpf_get_current_pid_tgid() always returns the initial-namespace (host) TGID.
// When these differ the system analysis PID check fails silently. This function
// bootstraps the correct host PID by attaching a tiny tracepoint to
// sys_enter_bpf, making one BPF map lookup via a unique marker map, and reading
// back the TGID that the kernel observed. Falls back to os.Getpid() on error.
func globalPID() uint32 {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// marker: the map whose FD we watch for — unique to this process.
	marker, err := cebpf.NewMap(&cebpf.MapSpec{
		Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	if err != nil {
		return uint32(os.Getpid())
	}
	defer marker.Close()

	result, err := cebpf.NewMap(&cebpf.MapSpec{
		Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	if err != nil {
		return uint32(os.Getpid())
	}
	defer result.Close()

	markerFD := int32(marker.FD())

	// sys_enter_bpf tracepoint context layout (from trace format):
	//   offset  0: common_type (u16)
	//   offset  2: common_flags (u8)
	//   offset  3: common_preempt_count (u8)
	//   offset  4: common_pid (s32)
	//   offset  8: __syscall_nr (s32)
	//   offset 16: cmd (u64)
	//   offset 24: uattr (u64 — pointer to bpf_attr in user space)
	//   offset 32: size (u32)
	//
	// bpf_attr for BPF_MAP_LOOKUP_ELEM: first field is map_fd (u32).
	insns := asm.Instructions{
		// r6 = ctx; r7 = bpf_get_current_pid_tgid()
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),

		// Read ctx->uattr (offset 24) into stack[-8] via bpf_probe_read_kernel
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 8),
		asm.Mov.Reg(asm.R3, asm.R6), asm.Add.Imm(asm.R3, 24),
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord), // R8 = uattr (user ptr)

		// Read bpf_attr->map_fd (first 4 bytes at uattr) via bpf_probe_read_user
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R8, asm.RFP, -4, asm.Word), // R8 = map_fd (s32)

		// if map_fd != markerFD: return without writing
		asm.Mov.Imm(asm.R9, markerFD),
		asm.JEq.Reg(asm.R8, asm.R9, "fd_match"),
		asm.Return(),

		// Store TGID (r7 >> 32) into result[0]
		asm.Mov.Reg(asm.R6, asm.R7).WithSymbol("fd_match"),
		asm.RSh.Imm(asm.R6, 32),
		asm.Mov.Imm(asm.R3, 0), asm.StoreMem(asm.RFP, -4, asm.R3, asm.Word),
		asm.LoadMapPtr(asm.R1, result.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "store"),
		asm.Return(),
		asm.StoreMem(asm.R0, 0, asm.R6, asm.DWord).WithSymbol("store"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := cebpf.NewProgram(&cebpf.ProgramSpec{
		Type: cebpf.TracePoint, License: "GPL", Instructions: insns,
	})
	if err != nil {
		log.Debugf("globalPID: failed to load bootstrap program: %v", err)
		return uint32(os.Getpid())
	}
	defer prog.Close()

	lnk, err := link.Tracepoint("syscalls", "sys_enter_bpf", prog, nil)
	if err != nil {
		log.Debugf("globalPID: failed to attach bootstrap program: %v", err)
		return uint32(os.Getpid())
	}

	// This BPF map lookup triggers sys_enter_bpf with our unique marker FD.
	var dummy uint64
	key0 := uint32(0)
	_ = marker.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&dummy))
	_ = lnk.Close()

	var tgid uint64
	if err := result.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&tgid)); err != nil || tgid == 0 {
		return uint32(os.Getpid())
	}
	return uint32(tgid)
}

// executeSystemAnalysisBpfCode will execute given analysis program with the address argument.
func executeSystemAnalysisBpfCode(progSpec *cebpf.ProgramSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	systemAnalysis := maps["system_analysis"]

	key0 := uint32(0)
	data := support.SystemAnalysis{
		Pid:     globalPID(),
		Address: uint64(address),
	}

	if err = systemAnalysis.Update(unsafe.Pointer(&key0), unsafe.Pointer(&data),
		cebpf.UpdateAny); err != nil {
		return nil, 0, fmt.Errorf("failed to write system_analysis 0x%x: %v",
			address, err)
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	// Load a BPF program to load the function code in systemAnalysis.
	// It attaches to raw tracepoint of entering syscall and triggers
	// when running in our PID context.
	prog, err := cebpf.NewProgram(progSpec)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load read_kernel_function_or_task_struct: %v", err)
	}
	defer prog.Close()

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
		return nil, 0, fmt.Errorf("failed to configure tracepoint: %v", err)
	}
	err = systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data))
	_ = progLink.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get analysis data: %v", err)
	}
	if err = validateSystemAnalysisResult(data, address); err != nil {
		return nil, 0, err
	}

	return data.Code[:], data.Address, nil
}

func validateSystemAnalysisResult(data support.SystemAnalysis, address libpf.SymbolValue) error {
	if data.Pid != 0 {
		return fmt.Errorf("%w for pid %d at 0x%x", errSystemAnalysisNotHandled, data.Pid, address)
	}

	if data.Err != 0 {
		if data.Err < 0 {
			return fmt.Errorf("%w at 0x%x: %w (helper err=%d)", errSystemAnalysisFailed, address, syscall.Errno(-data.Err), data.Err)
		}

		return fmt.Errorf("%w at 0x%x: helper err=%d", errSystemAnalysisFailed, address, data.Err)
	}

	return nil
}

// loadKernelCode will request the ebpf code to read the first X bytes from given address.
func loadKernelCode(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) ([]byte, error) {
	code, _, err := executeSystemAnalysisBpfCode(coll.Programs["read_kernel_memory"], maps, address)
	if err != nil {
		log.Warnf("Failed to load code: %v.\n"+
			"Possible reasons include using a kernel without syscall tracepoints enabled.", err)
	}
	return code, err
}

// readTaskStruct will request the ebpf code to read bytes from the given offset from
// the current task_struct.
func readTaskStruct(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	address libpf.SymbolValue,
) (code []byte, addr uint64, err error) {
	return executeSystemAnalysisBpfCode(coll.Programs["read_task_struct"], maps, address)
}

// determineStackPtregs determines the offset of `struct pt_regs` within the entry stack
// when the `stack` field offset within `task_struct` is already known.
func determineStackPtregs(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	vars *sysConfigVars,
) error {
	data, ptregs, err := readTaskStruct(coll, maps, libpf.SymbolValue(vars.task_stack_offset))
	if err != nil {
		return err
	}
	stackBase := binary.LittleEndian.Uint64(data)
	vars.stack_ptregs_offset = uint32(ptregs - stackBase)
	return nil
}

// determineStackLayout scans `task_struct` for offset of the `stack` field, and using
// its value determines the offset of `struct pt_regs` within the entry stack.
func determineStackLayout(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	vars *sysConfigVars,
) error {
	const maxTaskStructSize = 8 * 1024
	const maxStackSize = 64 * 1024

	pageSizeMinusOne := uint64(os.Getpagesize() - 1)

	for offs := 0; offs < maxTaskStructSize; {
		data, ptregs, err := readTaskStruct(coll, maps, libpf.SymbolValue(offs))
		if err != nil {
			return err
		}

		for i := 0; i < len(data); i += 8 {
			stackBase := binary.LittleEndian.Uint64(data[i:])
			// Stack base should be page aligned
			if stackBase&pageSizeMinusOne != 0 {
				continue
			}
			if ptregs > stackBase && ptregs < stackBase+maxStackSize {
				vars.task_stack_offset = uint32(offs + i)
				vars.stack_ptregs_offset = uint32(ptregs - stackBase)
				return nil
			}
		}
		offs += len(data)
	}
	return errors.New("unable to find task stack offset")
}

// prepareAnalysis creates a new CollectionSpec for the system analysis.
func prepareAnalysis(orig *cebpf.CollectionSpec) (*cebpf.CollectionSpec, map[string]*cebpf.Map, error) {
	new := &cebpf.CollectionSpec{
		Maps:     make(map[string]*cebpf.MapSpec),
		Programs: make(map[string]*cebpf.ProgramSpec),
	}
	new.Maps["system_analysis"] = orig.Maps["system_analysis"].Copy()
	new.Maps[".rodata.var"] = orig.Maps[".rodata.var"].Copy()
	if rodata, ok := orig.Maps[".rodata"]; ok {
		new.Maps[".rodata"] = rodata.Copy()
	}

	new.Programs["read_kernel_memory"] = orig.Programs["read_kernel_memory"].Copy()
	new.Programs["read_task_struct"] = orig.Programs["read_task_struct"].Copy()

	maps := make(map[string]*cebpf.Map)

	if err := loadAllMaps(new, &Config{}, maps); err != nil {
		return nil, nil, err
	}

	if err := rewriteMaps(new, maps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	return new, maps, nil
}

func determineSysConfig(coll *cebpf.CollectionSpec, maps map[string]*cebpf.Map,
	kmod *kallsyms.Module, includeTracers types.IncludedTracers, vars *sysConfigVars,
) error {
	if err := parseBTF(vars); err != nil {
		log.Infof("Using binary analysis (BTF not available: %s)", err)

		if err = determineStackLayout(coll, maps, vars); err != nil {
			return err
		}

		if includeTracers.Has(types.PerlTracer) || includeTracers.Has(types.PythonTracer) ||
			includeTracers.Has(types.Labels) {
			var tpbaseOffset uint64
			tpbaseOffset, err = loadTPBaseOffset(coll, maps, kmod)
			if err != nil {
				return err
			}
			vars.tpbase_offset = tpbaseOffset
		}
	} else {
		// Sadly BTF does not currently include THREAD_SIZE which is needed
		// to calculate the offset of struct pt_regs in the entry stack.
		// The value also depends of some kernel configurations, so lets
		// analyze it dynamically for now.
		if err = determineStackPtregs(coll, maps, vars); err != nil {
			return err
		}
	}

	log.Infof("Found offsets: task stack %#x, pt_regs %#x, tpbase %#x",
		vars.task_stack_offset,
		vars.stack_ptregs_offset,
		vars.tpbase_offset)

	return nil
}

// loadRodataVars initializes RODATA variables for the eBPF programs.
func loadRodataVars(coll *cebpf.CollectionSpec, kmod *kallsyms.Module, cfg *Config,
	major, minor uint32,
) error {
	if cfg.VerboseMode {
		if err := coll.Variables["with_debug_output"].Set(uint32(1)); err != nil {
			return fmt.Errorf("failed to set debug output: %v", err)
		}
	}

	// The Python/native hybrid unwinder's per program loop count defaults to 10
	// which is the largest that fits the 5.x / 6.0-6.5 verifier. Kernels 6.6+ are
	// more efficient and can support more, but 6.18's verifier is tighter than
	// 6.6-6.16; 15 fits the floor across the 6.6+ CI matrix.
	if major > 6 || (major == 6 && minor >= 6) {
		if err := coll.Variables["python_frames_per_program"].Set(uint32(15)); err != nil {
			return fmt.Errorf("failed to set python_frames_per_program: %v", err)
		}
	}

	if err := coll.Variables["off_cpu_threshold"].Set(cfg.OffCPUThreshold); err != nil {
		return fmt.Errorf("failed to set off_cpu_threshold: %v", err)
	}

	if err := coll.Variables["filter_error_frames"].Set(cfg.FilterErrorFrames); err != nil {
		return fmt.Errorf("failed to set drop_error_only_traces: %v", err)
	}

	if err := coll.Variables["filter_idle_frames"].Set(cfg.FilterIdleFrames); err != nil {
		return fmt.Errorf("failed to set debug output: %v", err)
	}

	pacMask := pacmask.GetPACMask()
	if pacMask != 0 {
		log.Infof("Determined PAC mask to be 0x%016X", pacMask)
	} else {
		log.Debug("PAC is not enabled on the system.")
	}
	if err := coll.Variables["inverse_pac_mask"].Set(^pacMask); err != nil {
		return fmt.Errorf("failed to set inverse_pac_mask: %v", err)
	}

	rodataVars := sysConfigVars{}

	systemAnalysisColl, maps, err := prepareAnalysis(coll)
	if err != nil {
		return fmt.Errorf("failed to prepare programs and maps for system analysis: %v", err)
	}

	if err := determineSysConfig(systemAnalysisColl, maps, kmod, cfg.IncludeTracers, &rodataVars); err != nil {
		return fmt.Errorf("failed to determine system configs: %v", err)
	}
	if err := coll.Variables["tpbase_offset"].Set(rodataVars.tpbase_offset); err != nil {
		return fmt.Errorf("failed to set tpbase_offset: %v", err)
	}
	if err := coll.Variables["task_stack_offset"].Set(rodataVars.task_stack_offset); err != nil {
		return fmt.Errorf("failed to set task_stack_offset: %v", err)
	}
	if err := coll.Variables["stack_ptregs_offset"].Set(rodataVars.stack_ptregs_offset); err != nil {
		return fmt.Errorf("failed to set stack_ptregs_offset: %v", err)
	}

	return nil
}
