// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

const rubyARMMaxCode = 128

var (
	rubyARMThreadPointer = e.Named("ruby.thread-pointer")
	rubyARMTLSResult     = e.Named("ruby.tls-offset")
)

// rubyARMState restricts the interpreter to instructions whose effects we know.
// The general interpreter deliberately ignores unsupported operations; doing so
// here could mistake a stale register expression for a TLS or symbol-table load.
type rubyARMState struct {
	it       *arm.Interpreter
	code     []byte
	allowTLS bool
	called   bool
	slot     uint64
}

func newRubyARMState(fn rubyFunction, allowTLS bool) *rubyARMState {
	code := fn.code[:min(len(fn.code), rubyARMMaxCode)]
	return &rubyARMState{it: arm.NewInterpreterWithCodeAt(code, e.Imm(fn.address)),
		code: code, allowTLS: allowTLS}
}

func (s *rubyARMState) clobber(reg arm64asm.Reg) {
	s.it.Regs.NameRegisterArm(reg, fmt.Sprintf("ruby.unknown.%d.%s", s.it.PC(), reg))
}

func (s *rubyARMState) step() (arm64asm.Inst, error) {
	pc := s.it.PC()
	ins, err := s.it.Step()
	if err != nil {
		return ins, err
	}
	word := binary.LittleEndian.Uint32(s.code[pc:])
	switch ins.Op {
	case arm64asm.ADRP:
		return ins, nil
	case arm64asm.ADD, arm64asm.SUB, arm64asm.MOV:
		// Immediate ADD/SUB (including MOV FP, SP), or register MOV. Reject
		// shifted-register arithmetic and other forms the interpreter omits.
		if word&0x3f800000 == 0x11000000 {
			// Keep SP derived only from SP, so ignored stack stores cannot
			// alias a descriptor or another tracked address.
			if (ins.Args[0] != arm64asm.RegSP(arm64asm.SP) && ins.Args[0] != arm64asm.RegSP(arm64asm.WSP)) || ins.Args[1] == ins.Args[0] {
				return ins, nil
			}
		} else if ins.Op == arm64asm.MOV {
			if dst, ok := ins.Args[0].(arm64asm.Reg); ok && dst >= arm64asm.W0 && dst <= arm64asm.X30 {
				switch ins.Args[1].(type) {
				case arm64asm.Reg, arm64asm.Imm:
					return ins, nil
				}
			}
		}
	case arm64asm.LDR:
		// W/X unsigned immediate loads and unshifted X register-offset
		// loads. Their widths and addressing modes are fully modeled.
		if word&0xffc00000 == 0xf9400000 || word&0xffc00000 == 0xb9400000 || word&0xffe0fc00 == 0xf8606800 {
			return ins, nil
		}
	case arm64asm.LDAR:
		if word&0xfffffc00 == 0x88dffc00 {
			mem := ins.Args[1].(arm64asm.MemImmediate)
			s.it.Regs.SetArm(ins.Args[0].(arm64asm.Reg), e.Mem8(s.it.Regs.GetArmSP(mem.Base)))
			return ins, nil
		}
	case arm64asm.MRS:
		if s.allowTLS && word&0xffffffe0 == 0xd53bd040 { // TPIDR_EL0
			s.it.Regs.SetArm(ins.Args[0].(arm64asm.Reg), rubyARMThreadPointer)
			return ins, nil
		}
	case arm64asm.BLR:
		reg, ok := ins.Args[0].(arm64asm.Reg)
		slot, constant := e.AsConstant(s.it.Regs.GetArm(arm64asm.X0))
		if !s.allowTLS || s.called || !ok || !constant || !s.it.Regs.GetArm(reg).Match(e.Mem8(e.Imm(slot))) {
			break
		}
		// A verified TLSDESC call returns a TP-relative offset in X0. Its
		// ABI preserves the other registers except X1 and LR. Older GCC
		// Linux sequences use BLR X2 with TP in X1, relying on the original
		// resolver convention that preserves X1; retain that known form.
		if reg != arm64asm.X2 || !s.it.Regs.GetArm(arm64asm.X1).Match(rubyARMThreadPointer) {
			s.clobber(arm64asm.X1)
		}
		s.clobber(arm64asm.X30)
		s.it.Regs.SetArm(arm64asm.X0, rubyARMTLSResult)
		s.slot, s.called = slot, true
		return ins, nil
	case arm64asm.STP, arm64asm.LDP:
		mem, ok := ins.Args[2].(arm64asm.MemImmediate)
		left, leftOK := ins.Args[0].(arm64asm.Reg)
		right, rightOK := ins.Args[1].(arm64asm.Reg)
		if ok && mem.Base == arm64asm.RegSP(arm64asm.SP) && leftOK && rightOK &&
			left >= arm64asm.X0 && left <= arm64asm.X30 && right >= arm64asm.X0 && right <= arm64asm.X30 {
			// Stack contents are not modeled. A restore must invalidate both
			// destinations, even when they happen to hold tracked values.
			if ins.Op == arm64asm.LDP {
				s.clobber(left)
				s.clobber(right)
			}
			return ins, nil
		}
	case arm64asm.HINT:
		switch word {
		case 0xd503233f, 0xd50323bf: // PACIASP, AUTIASP affect only LR.
			s.clobber(arm64asm.X30)
			return ins, nil
		case 0xd503201f, 0xd503245f: // NOP, BTI C.
			return ins, nil
		}
	case arm64asm.RET, arm64asm.B, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		// Callers stop at control flow; never interpret past these linearly.
		return ins, nil
	}
	return ins, fmt.Errorf("unsupported ARM64 Ruby instruction %s at +%#x", ins, pc)
}

func rubyARMEnd(ins arm64asm.Inst) bool {
	switch ins.Op {
	case arm64asm.RET, arm64asm.B, arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		return true
	default:
		return false
	}
}

// rubyARMECSlot recognizes a helper returning EC or a straight-line exported
// accessor prefix consuming EC. A second resolver call is ambiguous and rejected.
func rubyARMECSlot(fn rubyFunction, helper bool) (uint64, error) {
	s := newRubyARMState(fn, true)
	ec := e.Mem8(e.Add(rubyARMThreadPointer, rubyARMTLSResult))
	loaded := false
	for {
		ins, err := s.step()
		if err != nil {
			return 0, err
		}
		if ins.Op == arm64asm.LDR {
			dst, ok := ins.Args[0].(arm64asm.Reg)
			if ok && dst >= arm64asm.X0 && dst <= arm64asm.X30 && s.it.Regs.GetArm(dst).Match(ec) {
				loaded = true
			}
		}
		if rubyARMEnd(ins) {
			if !s.called || !loaded || (helper && (ins.Op != arm64asm.RET || ins.Args[0] != arm64asm.X30 || !s.it.Regs.GetArm(arm64asm.X0).Match(ec))) {
				return 0, fmt.Errorf("unproven ARM64 Ruby EC access")
			}
			return s.slot, nil
		}
	}
}

func rubyARMTLSDescriptor(fn rubyFunction) (uint64, error) {
	return rubyARMECSlot(fn, true)
}

func rubyARMECOffset(ef *pfelf.File) (uint64, error) {
	resolve := func(slot uint64) (uint64, error) {
		r, found, err := rubyAnonymousTLSReloc(ef, pfelf.RelTLSDESC, slot)
		if err != nil || !found || r.Addend < 0 {
			return 0, fmt.Errorf("no anonymous Ruby TLSDESC at %#x: %v", slot, err)
		}
		return uint64(r.Addend), nil
	}
	if entry, err := commonRubyTarget(ef, true, "rb_thread_current", "rb_fiber_current", "rb_current_receiver"); err == nil {
		text := ef.Section(".text")
		size := min(uint64(rubyARMMaxCode), text.Size-(entry-text.Addr))
		code, err := ef.VirtualMemory(int64(entry), int(size), int(size))
		if err != nil {
			return 0, err
		}
		slot, err := rubyARMTLSDescriptor(rubyFunction{entry, code})
		if err != nil {
			return 0, err
		}
		return resolve(slot)
	}
	var offset uint64
	for i, name := range []libpf.SymbolName{"rb_thread_current", "rb_fiber_current", "rb_current_receiver"} {
		fn, err := readRubyFunction(ef, name)
		if err != nil {
			return 0, err
		}
		slot, err := rubyARMECSlot(fn, false)
		if err != nil {
			return 0, err
		}
		value, err := resolve(slot)
		if err != nil {
			return 0, err
		}
		if i != 0 && offset != value {
			return 0, fmt.Errorf("inconsistent Ruby TLS accesses")
		}
		offset = value
	}
	return offset, nil
}

func rubyARMSymbolTable(fn rubyFunction) (uint64, error) {
	s := newRubyARMState(fn, false)
	for {
		ins, err := s.step()
		if err != nil {
			return 0, err
		}
		if !rubyARMEnd(ins) {
			continue
		}
		if ins.Op == arm64asm.RET && ins.Args[0] == arm64asm.X30 && s.it.PC() == uint64(len(fn.code)) {
			address := e.NewImmediateCapture("symbol-table")
			count := e.ZeroExtend32(e.Mem8(address))
			value := s.it.Regs.GetArm(arm64asm.X0)
			if value.Match(count) || value.Match(e.ZeroExtend32(e.Add(count, e.Imm(^uint64(0))))) {
				return address.CapturedValue(), nil
			}
		}
		return 0, fmt.Errorf("unproven ARM64 Ruby symbol-table load")
	}
}
