//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"flag"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/support"
)

var systemAnalysisStress = flag.Int("system-analysis-stress", 0,
	"number of fresh-attach requests TestSystemAnalysisStress issues")

// TestSystemAnalysisStress repeats the request that sporadically goes
// unhandled on multi-vCPU arm64 TCG guests: a read_task_struct right after
// attaching the probe, while other threads spin. It is skipped unless
// -system-analysis-stress is set, see support/stress-system-analysis.sh.
func TestSystemAnalysisStress(t *testing.T) {
	n := *systemAnalysisStress
	if n <= 0 {
		t.Skip("enable with -system-analysis-stress=N")
	}

	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)
	probes, maps, err := prepareAnalysis(coll)
	require.NoError(t, err)
	t.Cleanup(func() {
		probes.Close()
		closeEBPFResources(maps, nil)
	})

	// Same load as the PID namespace sibling workload: each Gosched on a
	// locked thread hands the P off, causing a stream of futex syscalls and
	// context switches.
	var stop atomic.Bool
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			runtime.LockOSThread()
			for !stop.Load() {
				runtime.Gosched()
			}
		})
	}
	t.Cleanup(func() {
		stop.Store(true)
		wg.Wait()
	})

	var retried, migrated, unhandled int
	var maxWait time.Duration
	start := time.Now()
	for i := range n {
		_, _, err := probes.readTaskStruct(0, 8)
		last := &probes.last
		switch {
		case errors.Is(err, errSystemAnalysisNotHandled):
			unhandled++
			t.Logf("request %d unhandled: %v", i, err)
		case err != nil:
			t.Fatalf("request %d: %v", i, err)
		case last.migratedCPU >= 0:
			migrated++
			t.Logf("request %d serviced after migration: %v", i, last)
		case last.retries > 0:
			retried++
			maxWait = max(maxWait, last.waited)
			t.Logf("request %d serviced after retries: %v", i, last)
		}
		probes.detach()
	}

	t.Logf("%d requests in %v: %d retried (max wait %v), %d needed migration, %d unhandled",
		n, time.Since(start), retried, maxWait, migrated, unhandled)
	require.Zero(t, migrated+unhandled, "requests the requester thread never serviced")
}
