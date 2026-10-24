//go:build integration

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

// ProcessContextRefreshes returns how many RefreshProcessContext calls installed a
// newer context, for integration tests. Metrics reporting resets the counter, so it
// only accumulates while metrics are disabled.
func (pm *ProcessManager) ProcessContextRefreshes() uint32 {
	return pm.ctxStats.updated.Load()
}
