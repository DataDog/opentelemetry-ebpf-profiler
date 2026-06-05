// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// attach creates one PID-scoped uprobe link for a single parsed probe.
//
// The kernel attaches uprobes by (inode, file_offset), so we pass the
// per-process mapping's backing file path. Using /proc/<pid>/map_files/...
// (via pr.OpenMappingFile) gives us a path that resolves to the exact inode
// the target process has mapped, regardless of mount namespace or whether
// the file has been deleted on disk.
//
// Returns an error if the BPF program for this ProbeKind is not loaded
// (heap profiling disabled for this kind), or if the kernel rejects the
// uprobe attach.
func (m *Manager) attach(
	pid libpf.PID,
	pr process.Process,
	mapping *process.RawMapping,
	p parsedProbe,
) (link.Link, error) {
	// TODO: prog := m.progs[p.Kind]; if nil, return errProgramNotLoaded
	// TODO: resolve a path suitable for link.OpenExecutable. Two options:
	//         a) pass "/proc/<pid>/map_files/<start>-<end>" directly
	//         b) open via pr.OpenMappingFile and use /proc/self/fd/N
	//       (a) is simpler if link.OpenExecutable accepts the symlink; verify.
	// TODO: ex, err := link.OpenExecutable(path)
	// TODO: opts := &link.UprobeOptions{
	//         PID:          int(pid),
	//         Address:      p.Location,
	//         RefCtrOffset: refctrIfSupported(m.supportsRefCtr, p.SemaphoreOffset),
	//         Cookie:       uint64(p.Kind), // richer encoding once we need it
	//       }
	// TODO: return ex.Uprobe("", prog, opts)
	return nil, nil
}

// refctrIfSupported returns offset if the kernel supports RefCtrOffset PMU
// attachments, else 0. Returning 0 degrades gracefully: the uprobe still
// attaches, but the USDT semaphore won't be flipped and semaphored probe
// sites will skip the call entirely.
func refctrIfSupported(supported bool, offset uint64) uint64 {
	if !supported {
		return 0
	}
	return offset
}
