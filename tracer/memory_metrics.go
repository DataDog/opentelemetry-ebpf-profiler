// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"
	"time"
	"unsafe"
)

// memoryCounters matches the eBPF struct memory_counters in memory_alloc.ebpf.c
// Must be kept in sync with the eBPF definition.
type memoryCounters struct {
	TotalAllocatedBytes uint64 // Cumulative bytes allocated (malloc + realloc grow)
	TotalFreedBytes     uint64 // Cumulative bytes freed (free + realloc shrink)
	MallocCount         uint64 // Number of successful malloc calls
	FreeCount           uint64 // Number of free calls
	ReallocCount        uint64 // Total realloc operations
	ReallocMovedCount   uint64 // Reallocs that moved to new location
}

// MemoryStatistics holds aggregate memory profiling statistics.
// This is the public API for reading memory stats, aggregated across all CPUs.
type MemoryStatistics struct {
	TotalAllocatedBytes uint64    // Total bytes allocated across all mallocs
	TotalFreedBytes     uint64    // Total bytes freed across all frees
	MallocCount         uint64    // Total number of malloc calls
	FreeCount           uint64    // Total number of free calls
	ReallocCount        uint64    // Total number of realloc calls
	ReallocMovedCount   uint64    // Number of reallocs that moved to new address
	NetGrowth           int64     // Allocated - Freed (can be negative if more freed)
	Timestamp           time.Time // When these stats were read
}

// ReadMemoryStatistics reads aggregate memory profiling counters from the eBPF memory_stats map.
// It aggregates per-CPU values and calculates derived metrics like net growth and growth rate.
//
// Returns nil and error if memory profiling is not enabled or map reading fails.
func (t *Tracer) ReadMemoryStatistics() (*MemoryStatistics, error) {
	// Get the memory_stats map
	statsMap, ok := t.ebpfMaps["memory_stats"]
	if !ok {
		return nil, fmt.Errorf("memory_stats map not found (memory profiling not enabled?)")
	}

	// Read per-CPU values
	// The eBPF map is BPF_MAP_TYPE_PERCPU_ARRAY, so we need to read all CPU values
	var perCPUValues []memoryCounters
	key := uint32(0) // Single entry map, indexed by 0

	if err := statsMap.Lookup(unsafe.Pointer(&key), &perCPUValues); err != nil {
		return nil, fmt.Errorf("failed to read memory_stats map: %w", err)
	}

	// Aggregate across all CPUs
	var stats MemoryStatistics
	stats.Timestamp = time.Now()

	for _, cpuStats := range perCPUValues {
		stats.TotalAllocatedBytes += cpuStats.TotalAllocatedBytes
		stats.TotalFreedBytes += cpuStats.TotalFreedBytes
		stats.MallocCount += cpuStats.MallocCount
		stats.FreeCount += cpuStats.FreeCount
		stats.ReallocCount += cpuStats.ReallocCount
		stats.ReallocMovedCount += cpuStats.ReallocMovedCount
	}

	stats.NetGrowth = int64(stats.TotalAllocatedBytes) - int64(stats.TotalFreedBytes)

	return &stats, nil
}
