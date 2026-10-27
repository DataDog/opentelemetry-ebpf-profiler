//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer_test

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	processcontextpb "go.opentelemetry.io/proto/otlp/processcontext/v1development"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

var otelCtxPublisherKind = flag.String("otel-ctx-publisher", "",
	"run as a process context publisher with an anonymous or memfd header mapping")

// envService is the service name publishers derive from their environment.
const envService = "otel-ctx-env"

// otelCtxPublisher publishes a process context per OTEP 4719, with the header
// and the payload in one mapping.
type otelCtxPublisher struct {
	mem         []byte
	publishedAt uint64
}

const otelCtxHeaderSize = 32

func newOtelCtxPublisher(kind string) (*otelCtxPublisher, error) {
	size := os.Getpagesize()
	fd, flags := -1, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS
	switch kind {
	case "anonymous":
	case "memfd":
		var err error
		if fd, err = unix.MemfdCreate("OTEL_CTX", unix.MFD_CLOEXEC); err != nil {
			return nil, err
		}
		defer unix.Close(fd)
		if err := unix.Ftruncate(fd, int64(size)); err != nil {
			return nil, err
		}
		flags = unix.MAP_PRIVATE
	default:
		return nil, fmt.Errorf("unknown header mapping kind %q", kind)
	}
	mem, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, flags)
	if err != nil {
		return nil, err
	}
	// The header fields that updates don't change. The timestamp stays zero
	// until the first publication.
	copy(mem, "OTEL_CTX")
	binary.NativeEndian.PutUint32(mem[8:], 2) // version
	binary.NativeEndian.PutUint64(mem[24:],
		uint64(uintptr(unsafe.Pointer(&mem[otelCtxHeaderSize]))))
	return &otelCtxPublisher{mem: mem}, nil
}

// publish publishes a context resolving service.name to service, or updates the
// published one, then announces the header with prctl. It returns the errno of
// prctl.
func (p *otelCtxPublisher) publish(service string) (unix.Errno, error) {
	payload, err := proto.Marshal(&processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
			Key:   "service.name",
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: service}},
		}}},
	})
	if err != nil {
		return 0, err
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return 0, err
	}

	// A zero timestamp marks the update in progress. The atomic operations order
	// the zero before the update, and the update before the new timestamp.
	publishedAt := (*uint64)(unsafe.Pointer(&p.mem[16]))
	atomic.SwapUint64(publishedAt, 0)
	binary.NativeEndian.PutUint32(p.mem[12:], uint32(len(payload)))
	copy(p.mem[otelCtxHeaderSize:], payload)
	p.publishedAt = max(uint64(now.Nano()), p.publishedAt+1)
	atomic.StoreUint64(publishedAt, p.publishedAt)

	err = announceOtelCtx(uintptr(unsafe.Pointer(&p.mem[0])), len(p.mem), otelCtxName())
	var errno unix.Errno
	if err != nil && !errors.As(err, &errno) {
		return 0, err
	}
	return errno, nil
}

// announceOtelCtx names the mapping at addr, as publishers do to announce their header.
func announceOtelCtx(addr uintptr, length int, name unsafe.Pointer) error {
	return unix.PrctlArg5Ptr(unix.PR_SET_VMA, unix.PR_SET_VMA_ANON_NAME, addr, uintptr(length),
		name)
}

// otelCtxName returns "OTEL_CTX" in freshly written memory. The prctl monitor
// can't fault in the name, and kernels without naming support don't read it, so a
// name in read-only data may not be resident.
func otelCtxName() unsafe.Pointer {
	name, _ := unix.ByteSliceFromString("OTEL_CTX")
	return unsafe.Pointer(&name[0])
}

// runOtelCtxPublisher is the publisher process. Once started, it prints "ready"
// and reads commands from stdin, one per line: "start" makes it keep a CPU busy, so
// the profiler samples it, and any other line is a service name to publish, after
// which it reports the errno of the prctl on stdout.
func runOtelCtxPublisher(kind string) int {
	p, err := newOtelCtxPublisher(kind)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	publish := func(service string) bool {
		errno, err := p.publish(service)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
		fmt.Println(int(errno))
		return true
	}
	fmt.Println("ready")

	lines := bufio.NewScanner(os.Stdin)
	for lines.Scan() {
		if lines.Text() == "start" {
			go func() {
				for {
					runtime.Gosched()
				}
			}()
			continue
		}
		if !publish(lines.Text()) {
			return 1
		}
	}
	return 0
}

// otelCtxPublisherProcess controls a publisher process.
type otelCtxPublisherProcess struct {
	pid    libpf.PID
	stdin  io.Writer
	stdout *bufio.Reader
	// stop makes the publisher exit, and waits for it. It can be called more than once.
	stop func()
}

func startOtelCtxPublisher(t *testing.T, kind string) *otelCtxPublisherProcess {
	t.Helper()
	// The publisher is killed when the test ends, if it hasn't exited by then.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-otel-ctx-publisher="+kind)
	cmd.Env = append(os.Environ(), "OTEL_SERVICE_NAME="+envService)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	p := &otelCtxPublisherProcess{
		pid:    libpf.PID(cmd.Process.Pid),
		stdin:  stdin,
		stdout: bufio.NewReader(stdout),
		// Closing stdin makes the publisher exit.
		stop: sync.OnceFunc(func() {
			_ = stdin.Close()
			_ = cmd.Wait()
		}),
	}
	t.Cleanup(p.stop)
	var ready string
	_, err = fmt.Fscan(p.stdout, &ready)
	require.NoError(t, err, "waiting for the publisher to start")
	require.Equal(t, "ready", ready)
	return p
}

// start makes the publisher keep a CPU busy, so the profiler samples it.
func (p *otelCtxPublisherProcess) start(t *testing.T) {
	t.Helper()
	_, err := fmt.Fprintln(p.stdin, "start")
	require.NoError(t, err)
}

// publish makes the publisher publish service, and waits until it has. It logs
// what prctl returned, which the prctl monitor ignores, to show which kernel
// behavior the run exercised.
func (p *otelCtxPublisherProcess) publish(t *testing.T, service string) {
	t.Helper()
	_, err := fmt.Fprintln(p.stdin, service)
	require.NoError(t, err)
	var errno int
	_, err = fmt.Fscan(p.stdout, &errno)
	require.NoError(t, err, "reading the publisher's prctl errno")
	if errno == 0 {
		t.Log("prctl succeeded")
	} else {
		t.Logf("prctl failed: %v", unix.Errno(errno))
	}
}

// serviceReporter records the service.name of the latest trace of each process.
type serviceReporter struct {
	mu       sync.Mutex
	services map[libpf.PID]string
}

func (r *serviceReporter) ReportTraceEvent(_ *libpf.Trace, meta *samples.TraceEventMeta) error {
	service, _ := meta.ResourceAttrs.Value("service.name")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[meta.PID] = service.AsString()
	return nil
}

func (r *serviceReporter) requireService(t *testing.T, pid libpf.PID, service string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		r.mu.Lock()
		defer r.mu.Unlock()
		got, seen := r.services[pid]
		if assert.True(c, seen, "no trace from PID %d", pid) {
			assert.Equal(c, service, got, "service.name of PID %d", pid)
		}
	}, 10*time.Second, 50*time.Millisecond)
}

func newProcessContextTracer(t *testing.T, rep reporter.TraceReporter) *tracer.Tracer {
	t.Helper()
	tr, err := tracer.NewTracer(t.Context(), &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		VerboseMode:            true,
		TraceReporter:          rep,
	})
	require.NoError(t, err)
	t.Cleanup(tr.Close)
	// Every supported kernel is expected to provide the prctl tracepoint.
	require.NoError(t, tr.AttachPrctlMonitor())
	return tr
}

// ebpfMetric returns the value of an eBPF counter, summed over CPUs.
func ebpfMetric(t *testing.T, tr *tracer.Tracer, id metrics.MetricID) uint64 {
	t.Helper()
	ebpfID := slices.Index(support.MetricsTranslation, id)
	require.GreaterOrEqual(t, ebpfID, 0)
	var perCPU []uint64
	require.NoError(t, tr.GetEbpfMaps()["metrics"].Lookup(uint32(ebpfID), &perCPU))
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}

// startProfiling starts a tracer that profiles every process, and reports their
// traces to rep.
func startProfiling(t *testing.T, rep reporter.TraceReporter) *tracer.Tracer {
	t.Helper()
	tr := newProcessContextTracer(t, rep)
	tr.StartPIDEventProcessor(t.Context())
	require.NoError(t, tr.AttachTracer(nil))
	require.NoError(t, tr.EnableProfiling())
	require.NoError(t, tr.AttachSchedMonitor())
	traceCh := make(chan *libpf.EbpfTrace)
	require.NoError(t, tr.StartMapMonitors(t.Context(), traceCh))
	go func() {
		for {
			select {
			case <-t.Context().Done():
				return
			case trace := <-traceCh:
				// The tracer sends nil as a barrier before calling ProcessedUntil.
				if trace != nil {
					tr.HandleTrace(trace)
				}
			}
		}
	}()
	return tr
}

// TestProcessContextRefresh checks that the contexts that a tracked process
// publishes and updates reach its traces through the announced header addresses.
func TestProcessContextRefresh(t *testing.T) {
	// The publishers start before profiling does. A sync during an exec could cache
	// the environment of the parent, or an empty one, and the profiler doesn't read it
	// again after an exec of the same executable.
	kinds := []string{"anonymous", "memfd"}
	publishers := make(map[string]*otelCtxPublisherProcess, len(kinds))
	for _, kind := range kinds {
		publishers[kind] = startOtelCtxPublisher(t, kind)
	}
	rep := &serviceReporter{services: make(map[libpf.PID]string)}
	tr := startProfiling(t, rep)

	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			// One publisher at a time keeps a CPU busy.
			p := publishers[kind]
			p.start(t)
			t.Cleanup(p.stop)
			// The env-derived service shows that the initial sync resolved the context.
			rep.requireService(t, p.pid, envService)

			events := ebpfMetric(t, tr, metrics.IDNumOtelCtxEvents)
			for _, service := range []string{"published", "updated"} {
				p.publish(t, service)
				rep.requireService(t, p.pid, service)
			}

			assert.Greater(t, ebpfMetric(t, tr, metrics.IDNumOtelCtxEvents), events)
		})
	}
}

// TestOtelCtxEventsKeepLatestAddress checks that the prctl monitor keeps one entry
// per process, holding the latest address that any of its threads announced.
func TestOtelCtxEventsKeepLatestAddress(t *testing.T) {
	// Without map monitors, nothing drains otel_ctx_events.
	tr := newProcessContextTracer(t, nil)
	pid := uint32(os.Getpid())
	// The prctl monitor ignores processes the profiler doesn't track.
	require.NoError(t, tr.GetEbpfMaps()["reported_pids"].Put(pid, uint64(0)))

	pageSize := os.Getpagesize()
	mem, err := unix.Mmap(-1, 0, 2*pageSize, unix.PROT_READ, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	require.NoError(t, err)
	defer func() { require.NoError(t, unix.Munmap(mem)) }()
	addrs := []uintptr{uintptr(unsafe.Pointer(&mem[0])), uintptr(unsafe.Pointer(&mem[pageSize]))}

	// Each address is announced in turn from its own thread, which stays alive
	// until the end, so the next announcement comes from another one.
	name := otelCtxName()
	tids := make([]int, len(addrs))
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i, addr := range addrs {
		announced := make(chan struct{})
		wg.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tids[i] = unix.Gettid()
			_ = announceOtelCtx(addr, pageSize, name) // recorded whatever prctl returns
			close(announced)
			<-done
		})
		<-announced
	}
	close(done)
	wg.Wait()
	require.NotEqual(t, tids[0], tids[1])

	entries := make(map[uint32]uint64)
	var key uint32
	var value uint64
	iter := tr.GetEbpfMaps()["otel_ctx_events"].Iterate()
	for iter.Next(&key, &value) {
		entries[key] = value
	}
	require.NoError(t, iter.Err())
	assert.Equal(t, map[uint32]uint64{pid: uint64(addrs[1])}, entries)
}
