// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/times"
)

// pendingReport holds a report waiting for ProcessedUntil confirmation
type pendingReport struct {
	samples   samples.TraceEventsTree
	startTime time.Time   // wall-clock collection start
	endTime   time.Time   // wall-clock collection end
	endKTime  times.KTime // kernel time at collection end
}

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[samples.TraceEventsTree]

	// collectionStartTime tracks when the current collection window started.
	// Initialized when Start() is called. The duration of the first profile may be
	// slightly overestimated as it includes tracer setup time before samples arrive.
	collectionStartTime time.Time

	// pending holds a report waiting for ProcessedUntil confirmation before sending
	pending *pendingReport

	// pendingMu protects pending and maxProcessedUntilKTime
	pendingMu sync.Mutex

	// maxProcessedUntilKTime is the monotonically increasing watermark for ProcessedUntil.
	// ProcessedUntil can go backward due to per-CPU reordering, so we track the max.
	maxProcessedUntilKTime times.KTime

	// readyCh signals the runLoop that ProcessedUntil has passed the pending threshold.
	// Capacity 1 allows non-blocking signal; runLoop drains it.
	readyCh chan struct{}
}

var errUnknownOrigin = errors.New("unknown trace origin")

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

// ProcessedUntil implements ProcessedUntilReporter.
func (b *baseReporter) ProcessedUntil(ktime times.KTime) {
	b.pendingMu.Lock()

	// Track monotonically increasing watermark (ProcessedUntil can go backward)
	if ktime > b.maxProcessedUntilKTime {
		b.maxProcessedUntilKTime = ktime
	}

	// Check if we should signal runLoop
	shouldSignal := b.pending != nil && b.maxProcessedUntilKTime >= b.pending.endKTime
	b.pendingMu.Unlock()

	if shouldSignal {
		select {
		case b.readyCh <- struct{}{}:
		default:
			// Already signaled, runLoop will handle it
		}
	}
}

// popPendingIfReady returns the pending report if ProcessedUntil has passed its threshold,
// and clears it from the baseReporter. Returns nil if not ready.
func (b *baseReporter) popPendingIfReady() *pendingReport {
	b.pendingMu.Lock()
	defer b.pendingMu.Unlock()

	if b.pending != nil && b.maxProcessedUntilKTime >= b.pending.endKTime {
		p := b.pending
		b.pending = nil
		return p
	}
	return nil
}

// swapPendingReport swaps the current buffer and returns any reports that should be sent.
// Returns (timeoutFallback, newReport) where timeoutFallback is a previous pending that
// wasn't sent in time, and newReport is set if ProcessedUntil has already passed.
func (b *baseReporter) swapPendingReport() (toSend, sendImmediately *pendingReport) {
	b.pendingMu.Lock()
	defer b.pendingMu.Unlock()

	// Timeout fallback: if pending exists, swap it out for sending
	if b.pending != nil {
		toSend = b.pending
		b.pending = nil
	}

	// Swap buffer and create new pending
	traceEventsPtr := b.traceEvents.WLock()
	reportedEvents := (*traceEventsPtr)
	*traceEventsPtr = make(samples.TraceEventsTree)
	collectionEndTime := time.Now()
	collectionEndKTime := times.GetKTime()
	collectionStartTime := b.collectionStartTime
	b.collectionStartTime = collectionEndTime
	b.traceEvents.WUnlock(&traceEventsPtr)

	newPending := &pendingReport{
		samples:   reportedEvents,
		startTime: collectionStartTime,
		endTime:   collectionEndTime,
		endKTime:  collectionEndKTime,
	}

	// Check if ProcessedUntil already passed - if so, send immediately
	if b.maxProcessedUntilKTime >= collectionEndKTime {
		sendImmediately = newPending
	} else {
		b.pending = newPending
	}

	return toSend, sendImmediately
}

// addSampleToTree adds a sample to the given trace events tree.
// The tree must be locked by the caller.
func addSampleToTree(tree *samples.TraceEventsTree, containerID libpf.String,
	origin libpf.Origin, key samples.TraceAndMetaKey, trace *libpf.Trace,
	meta *samples.TraceEventMeta) {
	if _, exists := (*tree)[samples.ContainerID(containerID)]; !exists {
		(*tree)[samples.ContainerID(containerID)] =
			make(map[libpf.Origin]samples.KeyToEventMapping)
	}

	if _, exists := (*tree)[samples.ContainerID(containerID)][origin]; !exists {
		(*tree)[samples.ContainerID(containerID)][origin] =
			make(samples.KeyToEventMapping)
	}

	if events, exists := (*tree)[samples.ContainerID(containerID)][origin][key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		(*tree)[samples.ContainerID(containerID)][origin][key] = events
		return
	}
	(*tree)[samples.ContainerID(containerID)][origin][key] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		OffTimes:   []int64{meta.OffTime},
		EnvVars:    meta.EnvVars,
		Labels:     trace.CustomLabels,
	}
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	switch meta.Origin {
	case support.TraceOriginSampling:
	case support.TraceOriginOffCPU:
	case support.TraceOriginProbe:
	default:
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin,
			errUnknownOrigin)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	containerID := meta.ContainerID
	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		ProcessName:    meta.ProcessName,
		ExecutablePath: meta.ExecutablePath,
		ApmServiceName: meta.APMServiceName,
		Pid:            int64(meta.PID),
		Tid:            int64(meta.TID),
		CPU:            int64(meta.CPU),
		ExtraMeta:      extraMeta,
	}

	// Check if sample should go to pending report.
	// Use <= to include samples exactly at the boundary in the pending window.
	b.pendingMu.Lock()
	if b.pending != nil && meta.Timestamp <= libpf.UnixTime64(b.pending.endKTime.UnixNano()) {
		// Sample belongs to pending report window
		addSampleToTree(&b.pending.samples, containerID, meta.Origin, key, trace, meta)
		b.pendingMu.Unlock()
		return nil
	}
	b.pendingMu.Unlock()

	// Sample goes to current buffer
	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	addSampleToTree(eventsTree, containerID, meta.Origin, key, trace, meta)
	return nil
}
