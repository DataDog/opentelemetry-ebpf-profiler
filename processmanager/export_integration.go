//go:build integration

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

// ProcessContextRefreshes returns how many RefreshProcessContext calls installed a
// newer context, and how many kept the previous one, for integration tests. Metrics
// reporting resets these counters, so they only accumulate while metrics are disabled.
func (pm *ProcessManager) ProcessContextRefreshes() (updated, noChange uint32) {
	return pm.ctxStats.updated.Load(), pm.ctxStats.noChange.Load()
}
