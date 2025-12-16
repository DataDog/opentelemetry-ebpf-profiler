// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package customlabels implements a pseudo interpreter handler that reads the custom labels from the TLS.
package customlabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/customlabels"

import (
	"debug/elf"
	"errors"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// tlsExport defines the name of the thread info TLS export.
	tlsExport = "custom_labels_current_set_v2"
)

// Loader implements interpreter.Loader.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Resolve process storage symbol.
	threadStorageSym, err := ef.LookupSymbol(tlsExport)
	noRelocation := false
	if err != nil {
		ef.VisitSymbols(func(sym libpf.Symbol) bool {
			if sym.Name == tlsExport {
				threadStorageSym = &sym
				return false
			}
			return true
		})
		if threadStorageSym == nil {
			return nil, nil
		}
		noRelocation = true
	}
	if threadStorageSym.Size != 8 {
		return nil, fmt.Errorf("process storage export has wrong size %d", threadStorageSym.Size)
	}

	log.Infof("Found TLS export in ELF: %s, noRelocation: %v", info.FileName(), noRelocation)
	tlsOffset := uint64(0)
	tlsDescElfAddr := libpf.Address(0)

	if noRelocation {
		tlsOffset, err = getStaticTLSOffset(ef, threadStorageSym)
		if err != nil {
			return nil, fmt.Errorf("failed to get static TLS offset: %v", err)
		}
	} else {
		if err = ef.VisitTLSRelocations(func(r pfelf.ElfReloc, symName string) bool {
			if symName == tlsExport {
				tlsDescElfAddr = libpf.Address(r.Off)
				return false
			}
			return true
		}); err != nil {
			return nil, fmt.Errorf("failed to visit TLS descriptor: %v", err)
		}

		if tlsDescElfAddr == 0 {
			return nil, errors.New("failed to locate TLS descriptor")
		}
	}
	log.Infof("APM integration TLS descriptor address: 0x%08X, TLS offset: 0x%08X", tlsDescElfAddr, tlsOffset)

	return &data{
		tlsDescElfAddr: tlsDescElfAddr,
		tlsOffset:      tlsOffset,
	}, nil
}

func roundUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func getTLSProg(ef *pfelf.File) *pfelf.Prog {
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_TLS {
			return &prog
		}
	}
	return nil
}

func getStaticTLSOffset(ef *pfelf.File, threadStorageSym *libpf.Symbol) (uint64, error) {
	if ef.Machine == elf.EM_AARCH64 {
		return uint64(threadStorageSym.Address), nil
	}

	if ef.Machine == elf.EM_X86_64 {
		tlsProg := getTLSProg(ef)
		if tlsProg == nil {
			return 0, fmt.Errorf("failed to locate TLS segment")
		}
		return uint64(threadStorageSym.Address) - roundUp(uint64(tlsProg.Memsz), uint64(tlsProg.Align)), nil
	}
	return 0, fmt.Errorf("unsupported machine: %s", ef.Machine)
}

type data struct {
	tlsDescElfAddr libpf.Address
	tlsOffset      uint64
}

var _ interpreter.Data = &data{}

func (d data) String() string {
	return "APM integration"
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	var tlsOffset uint64
	if d.tlsOffset != 0 {
		tlsOffset = d.tlsOffset
	} else {
		// Read TLS offset from the TLS descriptor.
		tlsOffset = rm.Uint64(bias + d.tlsDescElfAddr + 8)

		if int64(tlsOffset) > 0x100000 {
			// dynamic TLS is used, read the tls_index structure.
			moduleID := rm.Uint64(libpf.Address(tlsOffset))
			offset := rm.Uint64(libpf.Address(tlsOffset + 8))
			log.Infof("PID %d dynamic TLS used, moduleID: %d, offset: 0x%08X",
				pid, moduleID, offset)
			return nil, fmt.Errorf("dynamic TLS is not supported")
		}
	}

	log.Infof("PID %d tls offset: 0x%08X", pid, tlsOffset)

	// if dynamic TLS is used, tlsOffset will be a pointer to a tls_index structure.
	// use an arbitrary size to distinguish between dynamic and static TLS.
	procInfo := support.CustomLabelsProcInfo{Offset: tlsOffset}
	if err := ebpf.UpdateProcData(libpf.CustomLabels, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	log.Debugf("PID %d tls offset: 0x%08X", pid, tlsOffset)

	return &Instance{}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {
}

type Instance struct {
	interpreter.InstanceStubs
}

var _ interpreter.Instance = &Instance{}

// Detach implements the interpreter.Instance interface.
func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.APMInt, pid)
}
