// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package apmint implements a pseudo interpreter handler that detects APM agent
// libraries, establishes socket connections with them and notifies them about
// the stack traces that we collected for their process. This allows the APM
// agent to associate stack traces with APM traces / transactions / spans.
package apmint // import "go.opentelemetry.io/ebpf-profiler/interpreter/apmint"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"

const (
	// layoutMinorVersionLength defines the length of the layout minor version (uint16).
	layoutMinorVersionLength = 2
	// serviceNameMaxLength defines the maximum allowed length of service names.
	serviceNameMaxLength = 128
	// serviceEnvMaxLength defines the maximum allowed length of service environments.
	serviceEnvMaxLength = 128
	// socketPathMaxLength defines the maximum length of the APM agent socket path.
	socketPathMaxLength = 1024
	// runtimeIDLength defines the length of a UUID
	runtimeIDLength = 128

	// procStorageExport defines the name of the process storage ELF export.
	procStorageExport = "elastic_apm_profiling_correlation_process_storage_v1"
	// tlsExport defines the name of the thread info TLS export.
	tlsExport = "elastic_apm_profiling_correlation_tls_v1"
)

var dsoRegex = regexp.MustCompile(
	`[.*/]?((elastic-jvmti-linux-([\w-]*)\.so)|` +
		`(libdd_trace_cpp-shared\.so))`)

// apmProcessStorage represents a subset of the information present in the
// APM process storage.
//
// https://github.com/elastic/apm/blob/bd5fa9c1/specs/agents/universal-profiling-integration.md#process-storage-layout
//
//nolint:lll
type apmProcessStorage struct {
	LayoutMinorVersion uint16
	ServiceName        string
	TraceSocketPath    string
	RuntimeID          string
}

// Loader implements interpreter.Loader.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !isPotentialAgentLib(info.FileName()) {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Resolve process storage symbol.
	procStorageSym, err := ef.LookupSymbol(procStorageExport)
	if err != nil {
		if errors.Is(err, pfelf.ErrSymbolNotFound) {
			// APM<->profiling integration not supported by agent.
			return nil, nil
		}

		return nil, err
	}
	if procStorageSym.Size != 8 {
		return nil, fmt.Errorf("process storage export has wrong size %d", procStorageSym.Size)
	}

	// Resolve thread info TLS export.
	tlsDescs, err := ef.TLSDescriptors()
	if err != nil {
		return nil, errors.New("failed to extract TLS descriptors")
	}
	tlsDescElfAddr, ok := tlsDescs[tlsExport]
	if !ok {
		return nil, errors.New("failed to locate TLS descriptor")
	}

	log.Debugf("APM integration TLS descriptor offset: 0x%08X", tlsDescElfAddr)

	return &data{
		tlsDescElfAddr:   tlsDescElfAddr,
		procStorageElfVA: libpf.Address(procStorageSym.Address),
	}, nil
}

type data struct {
	tlsDescElfAddr   libpf.Address
	procStorageElfVA libpf.Address
}

var _ interpreter.Data = &data{}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	procStorage, err := readProcStorage(rm, bias+d.procStorageElfVA)
	if err != nil {
		return nil, fmt.Errorf("failed to read APM correlation process storage: %s", err)
	}

	// Read TLS offset from the TLS descriptor.
	tlsOffset := rm.Uint64(bias + d.tlsDescElfAddr + 8)
	procInfo := C.ApmIntProcInfo{tls_offset: C.u64(tlsOffset)}
	if err = ebpf.UpdateProcData(libpf.APMInt, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	var socket *apmAgentSocket
	if procStorage.LayoutMinorVersion == 1 {
		// Establish socket connection with the agent.
		socket, err = openAPMAgentSocket(pid, procStorage.TraceSocketPath)
		if err != nil {
			log.Warnf("Failed to open APM agent socket for PID %d", pid)
		}
	}

	log.Debugf("PID %d apm.service.name: %s, trace socket: %s",
		pid, procStorage.ServiceName, procStorage.TraceSocketPath)

	return &Instance{
		layoutMinorVersion: procStorage.LayoutMinorVersion,
		serviceName:        procStorage.ServiceName,
		runtimeID:          procStorage.RuntimeID,
		socket:             socket,
	}, nil
}

type Instance struct {
	layoutMinorVersion uint16
	serviceName        string
	runtimeID          string
	socket             *apmAgentSocket
	interpreter.InstanceStubs
}

var _ interpreter.Instance = &Instance{}

// Detach implements the interpreter.Instance interface.
func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.APMInt, pid)
}

// NotifyAPMAgent sends out collected traces to the connected APM agent.
// This is only called when layout-minor-version=1 (elastic's original Process Storage layout)
// TODO: add support for span ID
func (i *Instance) NotifyAPMAgent(
	pid libpf.PID, rawTrace *host.Trace, umTraceHash libpf.TraceHash, count uint16) {
	if rawTrace.APMTransactionID == libpf.InvalidAPMSpanID || i.socket == nil {
		return
	}

	log.Debugf("Reporting %dx trace hash %s -> TX %s for PID %d",
		count, umTraceHash.StringNoQuotes(),
		hex.EncodeToString(rawTrace.APMTransactionID[:]), pid)

	msg := traceCorrMsg{
		MessageType:      1,
		MinorVersion:     i.layoutMinorVersion,
		APMTraceID:       rawTrace.APMTraceID,
		APMTransactionID: rawTrace.APMTransactionID,
		StackTraceID:     umTraceHash,
		Count:            count,
	}

	if err := i.socket.SendMessage(msg.Serialize()); err != nil {
		log.Debugf("Failed to send trace mappings to APM agent: %v", err)
	}
}

// APMServiceName returns the service name advertised by the APM agent.
func (i *Instance) APMServiceName() string {
	return i.serviceName
}

// APMRuntimeID returns the runtimeID of the instrumented APM process
func (i *Instance) APMRuntimeID() string {
	return i.runtimeID
}

// isPotentialAgentLib checks whether the given path looks like a Java APM agent library.
func isPotentialAgentLib(path string) bool {
	return dsoRegex.MatchString(path)
}

// nextString reads the next `utf8-str` from memory and updates addr accordingly.
//
// https://github.com/elastic/apm/blob/bd5fa9c1/specs/agents/universal-profiling-integration.md#general-memory-layout
//
//nolint:lll
func nextString(rm remotememory.RemoteMemory, addr *libpf.Address, maxLen int) (string, error) {
	length := int(rm.Uint32(*addr))
	*addr += 4

	if length == 0 {
		return "", nil
	}

	if length > maxLen {
		return "", fmt.Errorf("APM string length %d exceeds maximum length of %d", length, maxLen)
	}

	raw := make([]byte, length)
	if _, err := rm.ReadAt(raw, int64(*addr)); err != nil {
		return "", errors.New("failed to read memory")
	}

	*addr += libpf.Address(length)
	return string(raw), nil
}

func getLayoutMinorVersion(rm remotememory.RemoteMemory, addr *libpf.Address) uint16 {
	layoutMinorVersion := rm.Uint16(*addr)
	*addr += layoutMinorVersionLength
	return layoutMinorVersion
}

// readProcStorage reads the APM process storage from memory.
//
// https://github.com/elastic/apm/blob/bd5fa9c1/specs/agents/universal-profiling-integration.md#process-storage-layout
//
//nolint:lll
func readProcStorage(
	rm remotememory.RemoteMemory,
	procStorageAddr libpf.Address,
) (*apmProcessStorage, error) {
	readPtr := rm.Ptr(procStorageAddr)
	if readPtr == 0 {
		return nil, errors.New("failed to read APM agent process state pointer")
	}

	// The specification guarantees that the struct can only be extended by adding
	// new fields after the old ones.
	layoutMinorVersion := getLayoutMinorVersion(rm, &readPtr)

	serviceName, err := nextString(rm, &readPtr, serviceNameMaxLength)
	if err != nil {
		return nil, err
	}

	// Currently not used by us.
	_, err = nextString(rm, &readPtr, serviceEnvMaxLength)
	if err != nil {
		return nil, err
	}

	var socketPath string
	if layoutMinorVersion == 1 {
		socketPath, err = nextString(rm, &readPtr, socketPathMaxLength)
		if err != nil {
			return nil, err
		}
	}

	var runtimeID string
	if layoutMinorVersion == 2 {
		runtimeID, err = nextString(rm, &readPtr, runtimeIDLength)
		if err != nil {
			return nil, err
		}
	}

	return &apmProcessStorage{
		LayoutMinorVersion: layoutMinorVersion,
		ServiceName:        serviceName,
		TraceSocketPath:    socketPath,
		RuntimeID:          runtimeID,
	}, nil
}
