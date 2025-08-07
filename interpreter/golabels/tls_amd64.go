//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"golang.org/x/arch/x86/x86asm"
)

// Most normal amd64 Go binaries use -8 as offset into TLS space for
// storing the current g but "static" binaries it ends up as -80. There
// may be dynamic relocating going on so just read it from a known
// symbol if possible.
func extractTLSGOffset(f *pfelf.File) (int32, error) {
	var addr int64
	syms, err := f.ReadSymbols()
	if err != nil {
		gopclntab, err2 := elfunwindinfo.NewGopclntab(f)
		if err2 != nil {
			return 0, err2
		}
		defer gopclntab.Close()
		funcPc, err2 := gopclntab.LookupFunction("runtime.stackcheck")
		if err2 != nil {
			return 0, err2
		}
		addr = int64(funcPc)
	} else {
		sym, err2 := syms.LookupSymbol("runtime.stackcheck.abi0")
		if err2 != nil {
			// Binary must be stripped, hope default is correct and warn.
			log.Warnf("Failed to find stackcheck symbol, Go labels might not work: %v", err2)
			return -8, err2
		}
		addr = int64(sym.Address)
	}

	// Dump of assembler code for function runtime.stackcheck:
	// 0x0000000000470080 <+0>:     mov    %fs:0xfffffffffffffff8,%rax

	// dockerd has a different assembly code for stackcheck with 2 movs:
	//  0x00000000007ec320 <+0>:	mov    $0xfffffffffffffff8,%rcx
	//  0x00000000007ec327 <+7>:	mov    %fs:(%rcx),%rax
	code, err := f.VirtualMemory(addr, 16, 16)
	if err != nil {
		return 0, err
	}

	offset := e.NewImmediateCapture("offset")
	it := amd.NewInterpreterWithCode(code)
	for {
		op, err := it.Step()
		if err != nil {
			break
		}
		if op.Op != x86asm.MOV {
			continue
		}
		mem, ok := op.Args[1].(x86asm.Mem)
		if !ok || mem.Segment != x86asm.FS {
			continue
		}
		if mem.Base == 0 {
			return int32(mem.Disp), nil
		}
		actual := it.Regs.GetX86(mem.Base)
		if actual.Match(offset) {
			return int32(offset.CapturedValue()), nil
		}
	}

	log.Warnf("Failed to decode stackcheck symbol, Go label collection might not work")
	return -8, nil
}
