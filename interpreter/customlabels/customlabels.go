package customlabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/customlabels"

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"
import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	tlsExport         = "custom_labels_current_set"
)

var dsoRegex = regexp.MustCompile(`.*/libcustomlabels.*\.so|.*/customlabels\.node`)

type data struct {
	tlsAddr          libpf.Address
	isSharedLibrary  bool
}

var _ interpreter.Data = &data{}

func roundUp(multiple, value uint64) uint64 {
	if multiple == 0 {
		return value
	}
	return (value + multiple - 1) / multiple * multiple
}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// If this is the libcustomlabels.so library, we are using
	// global-dynamic TLS model and have to look up the TLS descriptor.
	// Otherwise, assume we're the main binary and just look up the
	// symbol.
	isSharedLibrary := dsoRegex.MatchString(info.FileName())
	var tlsAddr libpf.Address
	if isSharedLibrary {
		// Resolve thread info TLS export.
		tlsDescs, err := ef.TLSDescriptors()
		if err != nil {
			return nil, errors.New("failed to extract TLS descriptors")
		}
		var ok bool
		tlsAddr, ok = tlsDescs[tlsExport]
		if !ok {
			return nil, errors.New("failed to locate TLS descriptor for custom labels")
		}
	} else {
		tlsSym, err := ef.LookupSymbol(tlsExport)
		if err != nil {
			return nil, err
		}
		if ef.Machine == elf.EM_AARCH64 {
			tlsAddr = libpf.Address(tlsSym.Address + 16)
		} else if ef.Machine == elf.EM_X86_64 {
			// Symbol addresses are relative to the start of the
			// thread-local storage image, but the thread pointer points to the _end_
			// of the image. So we need to find the size of the image in order to know where the
			// beginning is.
			//
			// The image is just .tdata followed by .tbss,
			// but we also have to respect the alignment.
			tbss, err := ef.Tbss()
			if err != nil {
				return nil, err
			}
			tdata, err := ef.Tdata()
			var tdataSize uint64
			if err != nil {
				// No Tdata is ok, it's the same as size 0
				if err != pfelf.ErrNoTdata {
					return nil, err
				}
			} else {
				tdataSize = tdata.Size
			}
			imageSize := roundUp(tbss.Addralign, tdataSize) + tbss.Size
			tlsAddr = libpf.Address(int64(tlsSym.Address) - int64(imageSize))
		} else {
			return nil, fmt.Errorf("unrecognized machine: %s", ef.Machine.String())
		}
	}

	d := data{
		tlsAddr:          tlsAddr,
		isSharedLibrary:  isSharedLibrary,
	}
	return &d, nil
}

type Instance struct {
	interpreter.InstanceStubs
}

func (d data) Unload(_ interpreter.EbpfHandler) {
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {

	var tlsOffset uint64
	if d.isSharedLibrary {
		// Read TLS offset from the TLS descriptor
		tlsOffset = rm.Uint64(bias + d.tlsAddr + 8)
	} else {
		// We're in the main executable: TLS offset is known statically.
		tlsOffset = uint64(d.tlsAddr)
	}

	procInfo := C.NativeCustomLabelsProcInfo{tls_offset: C.u64(tlsOffset)}
	if err := ebpf.UpdateProcData(libpf.CustomLabels, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &Instance{
	}, nil
}

func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.CustomLabels, pid)
}
