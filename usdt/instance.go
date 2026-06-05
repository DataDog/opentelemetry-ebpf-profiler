// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// noopMapping silences "imported and not used" while Reconcile is stubbed.
var _ = (*process.RawMapping)(nil)

// Instance holds the set of live USDT attachments for one PID.
//
// Owned by ProcessManager and stored in its usdtInstances map. Lifetime is
// bounded by the process lifetime: created/extended in Reconcile and torn
// down in Detach from processPIDExit.
type Instance struct {
	pid libpf.PID

	// attached is the source of truth for what is currently attached for
	// this pid. Keyed for O(1) diff against the desired set computed from
	// current mappings.
	attached map[ProbeKey]AttachedProbe
}

// Reconcile diffs the set of USDT probes desired for `pid` (derived by
// scanning the executable mappings) against what is currently attached on
// `inst`, attaches any newly-desired probes, and detaches any that are no
// longer present in the mapping set.
//
// Called from ProcessManager.SynchronizeProcess on every sync (not only on
// first sight) so that probes inside libraries dlopen'd after process start
// are eventually picked up.
//
// If `inst` is nil a new Instance is created. The returned Instance should
// always be stored back into ProcessManager.usdtInstances[pid] (replacing
// any previous value), even on partial failure.
func (m *Manager) Reconcile(
	pid libpf.PID,
	pr process.Process,
	inst *Instance,
) (*Instance, error) {
	// TODO: if inst == nil, allocate a fresh Instance with empty map.
	// TODO: build desired set by iterating pr.IterateMappings, keeping only
	//       executable file-backed mappings, and calling m.scanMapping per
	//       mapping (results cached by fileID, so repeats are cheap):
	//         for each parsed probe:
	//           desired[ProbeKey{pid, fileID, kind, location}] = (mapping, probe)
	// TODO: attach diff:
	//         for key in desired \ inst.attached:
	//           link, err := m.attach(pid, pr, mapping, probe)
	//           on success: inst.attached[key] = AttachedProbe{key, link}
	//           on error:   log and continue (partial success is fine)
	// TODO: detach diff:
	//         for key in inst.attached \ desired:
	//           close link; delete from map
	// TODO: return (inst, joined errors)
	return inst, nil
}

// Detach closes every live attachment for this pid. Called from
// ProcessManager.processPIDExit.
func (inst *Instance) Detach() error {
	// TODO: iterate inst.attached, close each link.Link, join errors
	// TODO: clear map so a stale Instance reference can't double-close
	return nil
}
