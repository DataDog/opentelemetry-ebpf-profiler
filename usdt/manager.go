// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/util"
)

// parseCacheSize bounds the number of distinct backing files for which we
// keep cached `.note.stapsdt` parse results. One entry per binary/library
// the profiler has ever scanned.
const parseCacheSize = 4096

// Manager holds process-independent state for USDT attachment: BPF program
// handles, kernel capability flags, and a parse cache keyed by file identity.
//
// One Manager per profiler instance; lookup-only from many goroutines.
type Manager struct {
	// progs holds the BPF program to attach for each ProbeKind. Loaded by
	// the tracer alongside the rest of the collection spec.
	progs map[ProbeKind]*cebpf.Program

	// supportsRefCtr indicates whether the kernel/PMU supports
	// UprobeOptions.RefCtrOffset (i.e. semaphore management). When false we
	// still attach, but skip the semaphore so semaphored probes won't fire.
	supportsRefCtr bool

	// parseCache deduplicates `.note.stapsdt` parsing across processes that
	// share the same backing file.
	parseCache *lru.LRU[util.OnDiskFileIdentifier, []parsedProbe]
}

// NewManager constructs a Manager. progs must contain one entry per ProbeKind
// the caller wants attached; kinds without a program are silently skipped at
// reconcile time.
//
// Returns (nil, nil) if progs is empty, to make USDT support trivially
// disable-able from the tracer wiring without scattering nil checks.
func NewManager(progs map[ProbeKind]*cebpf.Program) (*Manager, error) {
	// TODO: short-circuit on empty progs
	// TODO: detect RefCtrOffset PMU support (cilium does this internally via
	//       haveRefCtrOffsetPMU; we may need our own probe since it's unexported)
	// TODO: init parseCache
	return nil, nil
}

// Close releases manager-owned resources. Per-PID links are owned by the
// Instances and closed via Instance.Detach.
func (m *Manager) Close() error {
	// TODO: drop parse cache; programs are owned by the tracer collection
	return nil
}
