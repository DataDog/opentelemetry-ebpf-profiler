// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package hosttrace holds the host-agent's assembled eBPF trace event. It lives
// outside libpf so that libpf, a foundational package, does not depend on the
// OpenTelemetry collector's pdata types.
package hosttrace // import "go.opentelemetry.io/ebpf-profiler/hosttrace"

import (
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// EbpfTrace represents a stack trace from Ebpf code.
type EbpfTrace struct {
	EnvVars          map[libpf.String]libpf.String
	ProcessName      libpf.String
	ExecutablePath   libpf.String
	ContainerID      libpf.String
	CustomLabels     map[libpf.String]libpf.String
	Comm             libpf.Comm
	FrameData        []uint64
	KernelFrames     libpf.Frames
	FrameDataBuf     [3072]uint64
	Resource         *pcommon.Resource
	Value            int64
	KTime            int64
	CpuID            uint32
	TID              libpf.PID
	PID              libpf.PID
	NumFrames        uint16
	Origin           libpf.Origin
	APMTraceID       libpf.APMTraceID
	APMTransactionID libpf.APMTransactionID
}
