// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm // import "go.opentelemetry.io/ebpf-profiler/asm/arm"

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/expression"
)

type Interpreter struct {
	Regs        Registers
	code        []byte
	CodeAddress expression.Expression
	pc          uint64
}

func NewInterpreter() *Interpreter {
	it := &Interpreter{}
	it.initRegs()
	return it
}

func NewInterpreterWithCode(code []byte) *Interpreter {
	it := &Interpreter{code: code, CodeAddress: expression.Named("code address")}
	it.initRegs()
	return it
}

func (i *Interpreter) PC() uint64 {
	return i.pc
}

func (i *Interpreter) ResetCode(code []byte, address expression.Expression) {
	i.code = code
	i.CodeAddress = address
	i.pc = 0
}

func (i *Interpreter) Loop() (arm64asm.Inst, error) {
	return i.LoopWithBreak(func(arm64asm.Inst) bool { return false })
}

func (i *Interpreter) LoopWithBreak(breakLoop func(op arm64asm.Inst) bool) (arm64asm.Inst, error) {
	prev := arm64asm.Inst{}
	for {
		op, err := i.Step()
		if err != nil {
			return prev, err
		}
		if breakLoop(op) {
			return op, nil
		}
		prev = op
	}
}

const (
	// InstSz is the size (in bytes) of an aarch64 instruction;
	// in our universe, it is always 4.
	InstSz int = 4
)

// maybeHandleLoadStore checks if an instruction is a load or store, processing it if so.
// The first return value is true if we attempted to process the instruction.
func (i *Interpreter) maybeHandleLoadStore(inst arm64asm.Inst, instPC uint64) (bool, error) {
	// TODO: There are tons of load/store instructions. Fill in new ones if/when we need them.
	var isLoad bool
	switch inst.Op {
	case arm64asm.LDR, arm64asm.STR:
		isLoad = inst.Op == arm64asm.LDR
		dst, ok := inst.Args[0].(arm64asm.Reg)
		if !ok {
			return false, nil
		}
		var memAddr expression.Expression

		// for writeback instructions.
		var newValue expression.Expression
		// if newValue is set, this must also be set (it's where we will write the new value).
		var baseReg arm64asm.RegSP

		switch src := inst.Args[1].(type) {
		case arm64asm.MemImmediate:
			imm, _ := DecodeImmediate(src)
			baseReg = src.Base
			// A negative imm needs no special case: the two's complement
			// value is what Add folds modulo 2^64.
			immExpr := expression.Imm(uint64(imm))
			base := i.Regs.GetArmSP(baseReg)
			switch src.Mode {
			case arm64asm.AddrPostIndex:
				memAddr = base
				newValue = expression.Add(base, immExpr)
			case arm64asm.AddrPreIndex:
				memAddr = expression.Add(base, immExpr)
				newValue = memAddr
			case arm64asm.AddrOffset:
				memAddr = expression.Add(base, immExpr)
			default:
				return true, errors.New("apparently malformed ldr")
			}

		case arm64asm.MemExtend:
			if ext, ok := applyExtend(src.Extend.String(), i.Regs.GetArm(src.Index)); ok {
				memAddr = expression.Add(i.Regs.GetArmSP(src.Base),
					expression.ShiftLeft(ext, uint(src.Amount)))
			}
		case arm64asm.PCRel:
			memAddr = expression.Add(i.instAddr(instPC), expression.Imm(uint64(src)))
		}
		if memAddr != nil {
			if isLoad {
				// NB: encoding the read as all 8 bytes is fine even if the register is W*; setArm64asm
				// properly encodes that the higher order bytes should be zeroed in that case.
				i.Regs.setArm64asm(dst, expression.Mem8(memAddr))
			} else { //nolint:staticcheck
				// TODO: Our interpreter doesn't model memory contents yet,
				// so stores are currently a no-op (except that we will properly update
				// the register for writebacks below)
			}
			if newValue != nil {
				i.Regs.setArm64asmSP(baseReg, newValue)
			}
			return true, nil
		}
	}
	// either an instruction or an addressing mode that we didn't know how to handle; this isn't an error.
	return false, nil
}

// applyExtend applies an arm64 extend or shift name to v. It reports false for
// LSR, ASR and ROR, which the expression language cannot represent.
func applyExtend(name string, v expression.Expression) (expression.Expression, bool) {
	switch name {
	case "", "LSL", "UXTX", "SXTX":
		return v, true
	case "UXTW":
		return expression.ZeroExtend(v, 32), true
	case "SXTW":
		return expression.SignExtend(v, 32), true
	case "UXTH":
		return expression.ZeroExtend(v, 16), true
	case "SXTH":
		return expression.SignExtend(v, 16), true
	case "UXTB":
		return expression.ZeroExtend(v, 8), true
	case "SXTB":
		return expression.SignExtend(v, 8), true
	}
	return nil, false
}

// setDst writes v to the register an instruction names as its destination.
func (i *Interpreter) setDst(arg arm64asm.Arg, v expression.Expression) {
	switch dst := arg.(type) {
	case arm64asm.Reg:
		i.Regs.setArm64asm(dst, v)
	case arm64asm.RegSP:
		i.Regs.setArm64asmSP(dst, v)
	}
}

// regExtshift evaluates the third operand of an ALU instruction, which
// arm64asm always reports as a RegExtshiftAmount even for a bare register.
// Returns nil when the operand cannot be modeled.
func (i *Interpreter) regExtshift(arg arm64asm.RegExtshiftAmount) expression.Expression {
	reg, extshift, amount, ok := DecodeRegExtshiftAmount(arg)
	if !ok {
		return nil
	}
	v, ok := applyExtend(extshift, i.Regs.GetArm(reg))
	if !ok {
		return nil
	}
	return expression.ShiftLeft(v, amount)
}

// instAddr is the address of the instruction at offset pc. The PC register is
// unusable here: it holds its seed name until the first Step writes it.
func (i *Interpreter) instAddr(pc uint64) expression.Expression {
	return expression.Add(i.CodeAddress, expression.Imm(pc))
}

func (i *Interpreter) Step() (arm64asm.Inst, error) {
	if len(i.code) < InstSz {
		return arm64asm.Inst{}, io.EOF
	}
	inst, err := arm64asm.Decode(i.code)
	if err != nil {
		return inst, fmt.Errorf("at 0x%x : %v", i.pc, err)
	}
	instPC := i.pc
	i.pc += uint64(InstSz)
	i.code = i.code[InstSz:]
	i.Regs.setPC(i.instAddr(i.pc))
	if ok, err := i.maybeHandleLoadStore(inst, instPC); ok {
		return inst, err
	}
	switch inst.Op {
	case arm64asm.ADD, arm64asm.SUB:
		isSub := inst.Op == arm64asm.SUB
		var left, right expression.Expression
		switch leftArg := inst.Args[1].(type) {
		case arm64asm.RegSP:
			left = i.Regs.GetArmSP(leftArg)
		case arm64asm.Reg:
			left = i.Regs.GetArm(leftArg)
		}
		switch rightArg := inst.Args[2].(type) {
		case arm64asm.RegSP:
			right = i.Regs.GetArmSP(rightArg)
		case arm64asm.Reg:
			right = i.Regs.GetArm(rightArg)
		case arm64asm.Imm, arm64asm.ImmShift:
			if imm, ok := DecodeImmediate(rightArg); ok {
				right = expression.Imm(uint64(imm))
			}
		case arm64asm.RegExtshiftAmount:
			right = i.regExtshift(rightArg)
		}
		// The destination is written either way: leaving it alone would let a
		// consumer read its previous value as this instruction's result.
		sum := expression.Unknown()
		if left != nil && right != nil {
			if isSub {
				right = expression.Multiply(expression.Imm(^uint64(0)), right)
			}
			sum = expression.Add(left, right)
		}
		i.setDst(inst.Args[0], sum)
	case arm64asm.MOV:
		var v expression.Expression
		switch src := inst.Args[1].(type) {
		case arm64asm.Imm, arm64asm.Imm64:
			imm, _ := DecodeImmediate(src)
			v = expression.Imm(uint64(imm))
		case arm64asm.Reg:
			v = i.Regs.GetArm(src)
		case arm64asm.RegSP:
			v = i.Regs.GetArmSP(src)
		}
		if v == nil {
			v = expression.Unknown()
		}
		i.setDst(inst.Args[0], v)
	case arm64asm.ADRP:
		if src, ok := inst.Args[1].(arm64asm.PCRel); ok {
			if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
				pcPage := expression.Clear(i.instAddr(instPC), 12)
				i.Regs.setArm64asm(dst, expression.Add(pcPage, expression.Imm(uint64(src))))
			}
		}
	default:
	}
	return inst, nil
}

func (i *Interpreter) initRegs() {
	for j := range len(i.Regs.regs) {
		i.Regs.regs[j] = expression.Named(Reg(j).String())
	}
}
