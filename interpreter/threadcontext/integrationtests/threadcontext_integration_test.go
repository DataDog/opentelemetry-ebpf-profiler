//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/otel/metric/noop"
)

// Test binaries are embedded at build time.
// Only binaries for the current architecture will be available; others are skipped.
// Build with: make -C testprog

//go:embed testdata/threadctx_exe_glibc
var threadctx_exe_glibc []byte

//go:embed testdata/threadctx_exe_musl
var threadctx_exe_musl []byte

//go:embed testdata/threadctx_lib_glibc
var threadctx_lib_glibc []byte

//go:embed testdata/threadctx_lib_musl
var threadctx_lib_musl []byte

//go:embed testdata/libthreadctx_glibc.so
var libthreadctx_glibc_so []byte

//go:embed testdata/libthreadctx_musl.so
var libthreadctx_musl_so []byte

//go:embed testdata/threadctx_dlopen_musl
var threadctx_dlopen_musl []byte

//go:embed testdata/threadctx_dlopen_glibc
var threadctx_dlopen_glibc []byte

type embeddedBinary struct {
	bin  []byte
	name string
}

var embeddedBinaries = []embeddedBinary{
	{bin: threadctx_exe_glibc, name: "threadctx_exe_glibc"},
	{bin: threadctx_exe_musl, name: "threadctx_exe_musl"},
	{bin: threadctx_lib_glibc, name: "threadctx_lib_glibc"},
	{bin: threadctx_lib_musl, name: "threadctx_lib_musl"},
	{bin: libthreadctx_glibc_so, name: "libthreadctx_glibc.so"},
	{bin: libthreadctx_musl_so, name: "libthreadctx_musl.so"},
	{bin: threadctx_dlopen_musl, name: "threadctx_dlopen_musl"},
	{bin: threadctx_dlopen_glibc, name: "threadctx_dlopen_glibc"},
}

const expectedTraceID = "efcdab90785634121032547698badcfe"
const expectedSpanID = "4660"

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

func isRoot() bool {
	return os.Geteuid() == 0
}

func Test_ThreadContext(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}

	tmpDir := t.TempDir()
	for _, binary := range embeddedBinaries {
		err := os.WriteFile(filepath.Join(tmpDir, binary.name), binary.bin, 0o755)
		require.NoError(t, err)
	}

	tests := map[string]struct {
		exeName string
		args    []string
	}{
		"glibc_exe":    {exeName: "threadctx_exe_glibc"},
		"musl_exe":     {exeName: "threadctx_exe_musl"},
		"glibc_lib":    {exeName: "threadctx_lib_glibc"},
		"musl_lib":     {exeName: "threadctx_lib_musl"},
		"musl_dlopen":  {exeName: "threadctx_dlopen_musl", args: []string{filepath.Join(tmpDir, "libthreadctx_musl.so")}},
		"glibc_dlopen": {exeName: "threadctx_dlopen_glibc", args: []string{filepath.Join(tmpDir, "libthreadctx_glibc.so")}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			metrics.Start(noop.Meter{})

			enabledTracers, _ := tracertypes.Parse("")
			enabledTracers.Enable(tracertypes.Labels)

			log.SetLevel(slog.LevelDebug)
			trc, err := tracer.NewTracer(ctx, &tracer.Config{
				Intervals:              &mockIntervals{},
				IncludeTracers:         enabledTracers,
				SamplesPerSecond:       20,
				ProbabilisticInterval:  100,
				ProbabilisticThreshold: 100,
				OffCPUThreshold:        uint32(math.MaxUint32 / 100),
				VerboseMode:            true,
			})
			require.NoError(t, err)
			defer trc.Close()

			trc.StartPIDEventProcessor(ctx)
			require.NoError(t, trc.AttachTracer())

			t.Log("Attached tracer program")
			require.NoError(t, trc.EnableProfiling())
			require.NoError(t, trc.AttachSchedMonitor())

			traceCh := make(chan *libpf.EbpfTrace)
			require.NoError(t, trc.StartMapMonitors(ctx, traceCh))

			cmd := exec.CommandContext(ctx, filepath.Join(tmpDir, tc.exeName), tc.args...)
			err = cmd.Start()
			require.NoError(t, err)

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := cmd.Wait()

				select {
				case <-ctx.Done():
					t.Log("Test program cancelled (run complete)")
				default:
					exitErr, ok := err.(*exec.ExitError)
					if ok {
						fmt.Println(exitErr.Stderr)
					}
					require.NoError(t, err, "test program exited with error")
					cancel()
				}
			}()

			timeout := time.NewTimer(2 * time.Second)

			ok := false
		Loop:
			for {
				select {
				case <-timeout.C:
					break Loop
				case trace := <-traceCh:
					if trace == nil || trace.PID != libpf.PID(cmd.Process.Pid) {
						continue
					}
					if len(trace.CustomLabels) > 0 {
						traceID := trace.CustomLabels[libpf.Intern("trace id")]
						spanID := trace.CustomLabels[libpf.Intern("span id")]
						traceIDStr := traceID.String()
						spanIDStr := spanID.String()

						if traceIDStr != "" && spanIDStr != "" {
							t.Logf("Got trace_id=%s span_id=%s", traceIDStr, spanIDStr)
							require.Equal(t, expectedTraceID, traceIDStr)
							require.Equal(t, expectedSpanID, spanIDStr)
							ok = true
							break Loop
						}
					}
				}
			}
			cancel()
			wg.Wait()
			require.True(t, ok, "thread context not received")
			t.Log("Exiting test case")
		})
	}
}
