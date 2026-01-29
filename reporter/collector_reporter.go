// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*CollectorReporter)(nil)

// Assert that we implement the ProcessedUntilReporter interface.
var _ ProcessedUntilReporter = (*CollectorReporter)(nil)

// CollectorReporter receives and transforms information to be Collector Collector compliant.
type CollectorReporter struct {
	*baseReporter

	nextConsumer xconsumer.Profiles
}

// NewCollector builds a new CollectorReporter
func NewCollector(cfg *Config, nextConsumer xconsumer.Profiles) (*CollectorReporter, error) {
	data, err := pdata.New(
		cfg.SamplesPerSecond,
		cfg.ExtraSampleAttrProd,
	)
	if err != nil {
		return nil, err
	}

	tree := make(samples.TraceEventsTree)

	return &CollectorReporter{
		baseReporter: &baseReporter{
			cfg:         cfg,
			name:        cfg.Name,
			version:     cfg.Version,
			pdata:       data,
			traceEvents: xsync.NewRWMutex(tree),
			runLoop: &runLoop{
				stopSignal: make(chan libpf.Void),
			},
			readyCh: make(chan struct{}, 1),
		},
		nextConsumer: nextConsumer,
	}, nil
}

func (r *CollectorReporter) Start(ctx context.Context) error {
	r.collectionStartTime = time.Now()

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(ctx)

	r.runLoop.Start(ctx, r.cfg.ReportInterval, r.cfg.ReportJitter, func() {
		if err := r.reportProfile(ctx); err != nil {
			log.Errorf("Request failed: %v", err)
		}
	}, func() {
		// Allow the GC to purge expired entries to avoid memory leaks.
		r.pdata.Purge()
	}, r.readyCh, func() {
		r.trySendPending(ctx)
	})

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	go func() {
		<-r.runLoop.stopSignal
		cancelReporting()
	}()

	return nil
}

// reportProfile creates and sends out a profile.
func (r *CollectorReporter) reportProfile(ctx context.Context) error {
	toSend, sendImmediately := r.swapPendingReport()

	if toSend != nil {
		r.sendPending(ctx, toSend)
	}
	if sendImmediately != nil {
		r.sendPending(ctx, sendImmediately)
	}
	return nil
}

// trySendPending attempts to send the pending report if ProcessedUntil has passed its threshold.
func (r *CollectorReporter) trySendPending(ctx context.Context) {
	if pending := r.popPendingIfReady(); pending != nil {
		r.sendPending(ctx, pending)
	}
}

// sendPending sends a pending report (must be called WITHOUT holding pendingMu).
func (r *CollectorReporter) sendPending(ctx context.Context, pending *pendingReport) {
	profiles, err := r.pdata.Generate(pending.samples, r.name, r.version,
		pending.startTime, pending.endTime)
	if err != nil {
		log.Errorf("pdata: %v", err)
		return
	}

	if profiles.SampleCount() == 0 {
		log.Debugf("Skip sending profile with no samples")
		return
	}

	if err := r.nextConsumer.ConsumeProfiles(ctx, profiles); err != nil {
		log.Errorf("Failed to send profile: %v", err)
	}
}
