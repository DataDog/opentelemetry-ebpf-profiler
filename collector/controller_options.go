// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type Option interface {
	apply(*controllerOption) *controllerOption
}

type controllerOption struct {
	executableReporter    reporter.ExecutableReporter
	reporterFactory       func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)
	onShutdown            func() error
	tracerAccessCallback  func(*tracer.Tracer)
	memoryProfilingEnabled bool
	memoryAllocThreshold  uint32
}

type optFunc func(*controllerOption) *controllerOption

func (f optFunc) apply(c *controllerOption) *controllerOption { return f(c) }

// WithExecutableReporter is a function that allows to configure a ExecutableReporter.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.executableReporter = executableReporter
		return option
	})
}

// WithOnShutdown is a function that allows to configure a function to be called when the controller is shutdown.
func WithOnShutdown(onShutdown func() error) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.onShutdown = onShutdown
		return option
	})
}

// WithReporterFactory is a function that allows to define a custom collector reporter factory.
// If reporterFactory is not set, the default reporter will be used (reporter.NewCollector).
func WithReporterFactory(reporterFactory func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.reporterFactory = reporterFactory
		return option
	})
}

// WithTracerAccess registers a callback invoked after the tracer is initialized, before profiling starts.
func WithTracerAccess(callback func(*tracer.Tracer)) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.tracerAccessCallback = callback
		return option
	})
}

// WithMemoryProfiling configures memory allocation profiling for the collector.
// When enabled, the collector will track memory allocations using eBPF probes.
//
// Parameters:
//   - enabled: Whether to enable memory profiling
//   - allocThreshold: Sampling rate for memory allocations (0-100, where 0 means all allocations)
//
// Example:
//
//	collector.BuildProfilesReceiver(
//	    collector.WithMemoryProfiling(true, 10),
//	)
func WithMemoryProfiling(enabled bool, allocThreshold uint32) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.memoryProfilingEnabled = enabled
		option.memoryAllocThreshold = allocThreshold
		return option
	})
}
