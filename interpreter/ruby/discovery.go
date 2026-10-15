// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// Stripped Ruby 3.3+ can hide all the symbols needed by the unwinder. These
// deliberately bounded recognizers recover a subset of compiler patterns from
// exported functions, dynamic TLS relocations and the existing unwind intervals.
// They do not look for separate debug files. Unsupported builds keep the normal
// loader's failure/fallback behavior; no address is selected from ambiguous matches.
type rubyFunction struct {
	address uint64
	code    []byte
}

func readRubyFunction(ef *pfelf.File, name libpf.SymbolName) (rubyFunction, error) {
	sym, code, err := ef.SymbolData(name, 4096)
	if err != nil {
		return rubyFunction{}, err
	}
	if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Size == 0 || uint64(len(code)) != sym.Size {
		return rubyFunction{}, fmt.Errorf("unbounded Ruby function %s", name)
	}
	return rubyFunction{uint64(sym.Address), code}, nil
}

func decodeRubyAMD(code []byte) (x86asm.Inst, error) {
	if ok, size := amd.DecodeSkippable(code); ok {
		return x86asm.Inst{Op: x86asm.NOP, Len: size}, nil
	}
	return x86asm.Decode(code, 64)
}

// x86asm zero-extends 32-bit displacements.
func rubyDisp(disp int64) int64 {
	return int64(int32(disp))
}

// rubyBranchTargets excludes intra-function control flow; its caller filters PLT stubs. The VM
// entry is the common tail-call target of rb_iseq_eval and rb_iseq_eval_main.
// On ARM64 the EC accessor is a common direct call from exported EC consumers.
func rubyBranchTargets(machine elf.Machine, fn rubyFunction, calls bool) (map[uint64]bool, error) {
	targets := make(map[uint64]bool)
	for off := 0; off < len(fn.code); {
		pc := fn.address + uint64(off)
		var target uint64
		switch machine {
		case elf.EM_AARCH64:
			ins, err := arm64asm.Decode(fn.code[off:])
			if err != nil {
				return nil, err
			}
			off += 4
			if (calls && ins.Op == arm64asm.BL) || (!calls && ins.Op == arm64asm.B) {
				if rel, ok := ins.Args[0].(arm64asm.PCRel); ok {
					target = uint64(int64(pc) + int64(rel))
				}
			}
		case elf.EM_X86_64:
			ins, err := decodeRubyAMD(fn.code[off:])
			if err != nil {
				return nil, fmt.Errorf("invalid Ruby instruction at %#x: %v", pc, err)
			}
			off += ins.Len
			if (calls && ins.Op == x86asm.CALL) || (!calls && ins.Op == x86asm.JMP) {
				if rel, ok := ins.Args[0].(x86asm.Rel); ok {
					target = uint64(int64(fn.address) + int64(off) + int64(rel))
				}
			}
		default:
			return nil, fmt.Errorf("unsupported Ruby machine %v", machine)
		}
		if target != 0 && (target < fn.address || target >= fn.address+uint64(len(fn.code))) {
			targets[target] = true
		}
	}
	return targets, nil
}

func commonRubyTarget(ef *pfelf.File, calls bool, names ...libpf.SymbolName) (uint64, error) {
	text := ef.Section(".text")
	if text == nil {
		return 0, fmt.Errorf("missing Ruby .text section")
	}
	var common map[uint64]bool
	for _, name := range names {
		fn, err := readRubyFunction(ef, name)
		if err != nil {
			return 0, err
		}
		targets, err := rubyBranchTargets(ef.Machine, fn, calls)
		if err != nil {
			return 0, err
		}
		if common == nil {
			common = targets
		} else {
			for target := range common {
				if !targets[target] {
					delete(common, target)
				}
			}
		}
	}
	for target := range common {
		if target < text.Addr || target-text.Addr >= text.Size {
			delete(common, target)
		}
	}
	if len(common) == 1 {
		for target := range common {
			return target, nil
		}
	}
	return 0, fmt.Errorf("expected one common Ruby target, found %d", len(common))
}

// The ARM64 Ruby 4.0.1 fixture has a 404-byte rb_vm_exec. The minimum size is
// a heuristic to reject small shared helpers, not a guaranteed VM size bound.
const (
	minRubyVMSize = 256
	maxRubyVMSize = 65536
)

func discoverRubyVM(ef *pfelf.File, info *interpreter.LoaderInfo) ([]util.Range, error) {
	entry, err := commonRubyTarget(ef, false, "rb_iseq_eval", "rb_iseq_eval_main")
	if err != nil {
		return nil, err
	}
	block := info.Intervals().Find(entry)
	if block == nil || block.Start != entry {
		return nil, fmt.Errorf("no unwind interval starting at Ruby VM entry %#x", entry)
	}
	if size := block.End - entry; size < minRubyVMSize || size > maxRubyVMSize {
		return nil, fmt.Errorf("implausible size %d for Ruby VM entry %#x", size, entry)
	}
	return []util.Range{{Start: entry, End: block.End}}, nil
}

// rubyARMECAccessor is GCC's 48-byte rb_current_ec accessor, including its
// TPIDR_EL0 read and final TLS load. Matching the whole function avoids
// silently following stale register values through unknown instructions.
var rubyARMECAccessor = [12]struct{ mask, want uint32 }{
	{0xffffffff, 0xd503233f}, {0xffffffff, 0xd53bd041},
	{0xffffffff, 0xa9bf7bfd}, {0xffffffff, 0x910003fd},
	{0x9f00001f, 0x90000000}, // ADRP X0, page
	{0xffc003ff, 0xf9400002}, // LDR X2, [X0, offset]
	{0xffc003ff, 0x91000000}, // ADD X0, X0, offset
	{0xffffffff, 0xd63f0040}, {0xffffffff, 0xf8606820},
	{0xffffffff, 0xa8c17bfd}, {0xffffffff, 0xd50323bf}, {0xffffffff, 0xd65f03c0},
}

func rubyARMTLSDescriptor(fn rubyFunction) (uint64, error) {
	if len(fn.code) != 4*len(rubyARMECAccessor) {
		return 0, fmt.Errorf("unsupported ARM64 Ruby EC accessor size")
	}
	for i, e := range rubyARMECAccessor {
		if binary.LittleEndian.Uint32(fn.code[i*4:])&e.mask != e.want {
			return 0, fmt.Errorf("unsupported ARM64 Ruby EC instruction %d", i)
		}
	}
	loadOffset := uint64((binary.LittleEndian.Uint32(fn.code[20:])>>10)&0xfff) * 8
	addOffset := uint64((binary.LittleEndian.Uint32(fn.code[24:]) >> 10) & 0xfff)
	if loadOffset != addOffset {
		return 0, fmt.Errorf("inconsistent Ruby TLSDESC argument")
	}
	ins, err := arm64asm.Decode(fn.code[16:])
	if err != nil {
		return 0, err
	}
	page := int64((fn.address + 16) &^ 4095)
	return uint64(page+int64(ins.Args[1].(arm64asm.PCRel))) + addOffset, nil
}

type rubyTLSAccess struct {
	slot         uint64
	loadOffset   int64
	resolverCall uint64
}

// rubyAMDTLSAccess recognizes a consecutive LEA tls_index, CALL resolver, MOV
// [RAX+offset] sequence. The caller verifies the TLS relocation and agreement
// between independent EC consumers before using it.
func rubyAMDTLSAccess(fn rubyFunction) (rubyTLSAccess, error) {
	var lea, call x86asm.Inst
	var matches []rubyTLSAccess
	for off := 0; off < len(fn.code); {
		pc := fn.address + uint64(off)
		ins, err := decodeRubyAMD(fn.code[off:])
		if err != nil {
			return rubyTLSAccess{}, fmt.Errorf("invalid AMD64 Ruby instruction at %#x", pc)
		}
		off += ins.Len
		if lea.Op == x86asm.LEA && call.Op == x86asm.CALL && ins.Op == x86asm.MOV {
			arg, argOK := lea.Args[1].(x86asm.Mem)
			rel, relOK := call.Args[0].(x86asm.Rel)
			load, loadOK := ins.Args[1].(x86asm.Mem)
			dst, dstOK := ins.Args[0].(x86asm.Reg)
			if lea.Args[0] == x86asm.RDI && argOK && arg.Base == x86asm.RIP &&
				arg.Index == 0 && arg.Segment == 0 && relOK &&
				dstOK && dst >= x86asm.RAX && dst <= x86asm.R15 && loadOK &&
				load.Base == x86asm.RAX && load.Index == 0 && load.Segment == 0 {
				// RIP-relative LEA is relative to the CALL that follows it.
				matches = append(matches, rubyTLSAccess{
					slot:       uint64(int64(pc) - int64(call.Len) + rubyDisp(arg.Disp)),
					loadOffset: rubyDisp(load.Disp), resolverCall: uint64(int64(pc) + int64(rel)),
				})
			}
		}
		lea, call = call, ins
	}
	if len(matches) != 1 {
		return rubyTLSAccess{}, fmt.Errorf("expected one Ruby TLS access, found %d", len(matches))
	}
	return matches[0], nil
}

// rubyAnonymousTLSReloc finds the symbol-less TLS relocation of the given kind at slot.
func rubyAnonymousTLSReloc(ef *pfelf.File, kind pfelf.RelocType, slot uint64) (
	reloc pfelf.ElfReloc, found bool, err error) {
	err = ef.VisitRelocations(func(r pfelf.ElfReloc, name string, _ pfelf.RelocType) bool {
		found = name == "" && r.Off == slot
		reloc = r
		return !found
	}, kind)
	return reloc, found, err
}

// rubyAMDECOffset returns the EC offset in the TLS block and the resolver used by name.
func rubyAMDECOffset(ef *pfelf.File, name libpf.SymbolName) (offset, resolver uint64, err error) {
	fn, err := readRubyFunction(ef, name)
	if err != nil {
		return 0, 0, err
	}
	access, err := rubyAMDTLSAccess(fn)
	if err != nil {
		return 0, 0, err
	}
	if access.loadOffset < 0 {
		return 0, 0, fmt.Errorf("negative Ruby EC load offset %d", access.loadOffset)
	}
	if _, found, err := rubyAnonymousTLSReloc(ef, pfelf.RelDTPMOD64, access.slot); err != nil || !found {
		return 0, 0, fmt.Errorf("no anonymous Ruby DTPMOD64 at %#x: %v", access.slot, err)
	}
	// For a local TLS variable the second tls_index word is initialized
	// in the ELF. It can name either the variable or the module base.
	data, err := ef.VirtualMemory(int64(access.slot+8), 8, 8)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot read Ruby tls_index: %v", err)
	}
	indexOffset := binary.LittleEndian.Uint64(data)
	offset = indexOffset + uint64(access.loadOffset)
	if offset < indexOffset {
		return 0, 0, fmt.Errorf("overflowing Ruby TLS offset")
	}
	return offset, access.resolverCall, nil
}

func discoverRubyEC(ef *pfelf.File) (*libpf.Symbol, error) {
	var offset uint64
	switch ef.Machine {
	case elf.EM_AARCH64:
		entry, err := commonRubyTarget(ef, true, "rb_thread_current", "rb_fiber_current", "rb_current_receiver")
		if err != nil {
			return nil, err
		}
		size := 4 * len(rubyARMECAccessor)
		code, err := ef.VirtualMemory(int64(entry), size, size)
		if err != nil {
			return nil, err
		}
		slot, err := rubyARMTLSDescriptor(rubyFunction{entry, code})
		if err != nil {
			return nil, err
		}
		reloc, found, err := rubyAnonymousTLSReloc(ef, pfelf.RelTLSDESC, slot)
		if err != nil || !found || reloc.Addend < 0 {
			return nil, fmt.Errorf("no anonymous Ruby TLSDESC at %#x: %v", slot, err)
		}
		offset = uint64(reloc.Addend)
	case elf.EM_X86_64:
		var resolver uint64
		var err error
		offset, resolver, err = rubyAMDECOffset(ef, "rb_thread_current")
		if err != nil {
			return nil, err
		}
		fiberOffset, fiberResolver, err := rubyAMDECOffset(ef, "rb_fiber_current")
		if err != nil {
			return nil, err
		}
		if offset != fiberOffset || resolver != fiberResolver {
			return nil, fmt.Errorf("inconsistent Ruby TLS accesses")
		}
	default:
		return nil, fmt.Errorf("unsupported Ruby TLS machine %v", ef.Machine)
	}
	prog := ef.ProgByType(elf.PT_TLS)
	if prog == nil || prog.Memsz < 8 || offset > prog.Memsz-8 || offset%8 != 0 {
		return nil, fmt.Errorf("recovered Ruby EC offset %#x is outside PT_TLS", offset)
	}
	for i, section := range ef.Sections {
		if section.Flags&elf.SHF_TLS != 0 {
			return &libpf.Symbol{Name: "ruby_current_ec", Address: libpf.SymbolValue(offset),
				Size: 8, Info: uint8(elf.STT_TLS), Shndx: uint16(i)}, nil
		}
	}
	return nil, fmt.Errorf("missing Ruby TLS section")
}

// rb_sym_immortal_count returns the first 32-bit field of ruby_global_symbols.
// Ruby 4 uses an acquire load and subtracts one from the counter.
func rubySymbolTable(machine elf.Machine, fn rubyFunction) (uint64, error) {
	switch machine {
	case elf.EM_AARCH64:
		if len(fn.code) < 12 {
			break
		}
		first, err := arm64asm.Decode(fn.code)
		if err != nil || first.Op != arm64asm.ADRP || first.Args[0] != arm64asm.X0 {
			break
		}
		address := uint64(int64(fn.address&^4095) + int64(first.Args[1].(arm64asm.PCRel)))
		word := binary.LittleEndian.Uint32(fn.code[4:])
		switch len(fn.code) {
		case 12:
			if word&0xffc003ff == 0xb9400000 &&
				binary.LittleEndian.Uint32(fn.code[8:]) == 0xd65f03c0 {
				return address + uint64((word>>10)&0xfff)*4, nil
			}
		case 20:
			if word&0xffc003ff == 0x91000000 &&
				binary.LittleEndian.Uint32(fn.code[8:]) == 0x88dffc00 &&
				binary.LittleEndian.Uint32(fn.code[12:]) == 0x51000400 &&
				binary.LittleEndian.Uint32(fn.code[16:]) == 0xd65f03c0 {
				return address + uint64((word>>10)&0xfff), nil
			}
		}
	case elf.EM_X86_64:
		if ok, size := amd.DecodeSkippable(fn.code); ok {
			fn = rubyFunction{fn.address + uint64(size), fn.code[size:]}
		}
		ins, err := x86asm.Decode(fn.code, 64)
		if err != nil || ins.Op != x86asm.MOV || ins.Args[0] != x86asm.EAX {
			break
		}
		mem, ok := ins.Args[1].(x86asm.Mem)
		if !ok || mem.Base != x86asm.RIP || mem.Index != 0 || mem.Segment != 0 {
			break
		}
		address := uint64(int64(fn.address) + int64(ins.Len) + rubyDisp(mem.Disp))
		code := fn.code[ins.Len:]
		if len(code) == 4 && code[0] == 0x83 && code[1] == 0xe8 && code[2] == 1 {
			code = code[3:]
		}
		if len(code) == 1 && code[0] == 0xc3 {
			return address, nil
		}
	}
	return 0, fmt.Errorf("unsupported rb_sym_immortal_count instructions")
}

func discoverRubySymbols(ef *pfelf.File) (libpf.SymbolValue, error) {
	fn, err := readRubyFunction(ef, "rb_sym_immortal_count")
	if err != nil {
		return 0, err
	}
	address, err := rubySymbolTable(ef.Machine, fn)
	if err != nil {
		return 0, err
	}
	prog := ef.ProgByVirtualAddress(address)
	if prog == nil || prog.Flags&elf.PF_W == 0 || prog.Vaddr+prog.Memsz-address < 24 || address%8 != 0 {
		return 0, fmt.Errorf("recovered Ruby symbol table %#x is outside writable memory", address)
	}
	return libpf.SymbolValue(address), nil
}
