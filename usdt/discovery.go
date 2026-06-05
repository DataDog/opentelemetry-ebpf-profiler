// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"go.opentelemetry.io/ebpf-profiler/process"
)

// scanMapping returns the list of USDT probes we care about within one
// memory mapping's backing file.
//
// Results are cached on the Manager by OnDiskFileIdentifier, so each
// distinct binary/library is parsed at most once across the lifetime of
// the profiler. This matters because the same .so is typically mapped by
// many processes.
//
// Implementation outline:
//   - open the backing file via pr.OpenMappingFile (uses /proc/<pid>/map_files
//     so it works for deleted-on-disk binaries and respects mount namespaces)
//   - parse `.note.stapsdt` (via github.com/parca-dev/usdt's parser fed an
//     ELFReader backed by our pfelf)
//   - filter to Provider == ProbeProvider
//   - map each (provider, name) to a ProbeKind via probeKindFromName
//   - return []parsedProbe with file-offset-adjusted Location/SemaphoreOffset
func (m *Manager) scanMapping(
	pr process.Process,
	mapping *process.RawMapping,
) ([]parsedProbe, error) {
	// TODO: fileID := mapping.GetOnDiskFileIdentifier()
	// TODO: if cached, return from m.parseCache
	// TODO: rac, err := pr.OpenMappingFile(mapping); defer rac.Close()
	// TODO: wrap rac in a pfelf reader compatible with parcausdt.ELFReader
	// TODO: parcausdt.ParseProbes(reader) -> []parcausdt.Probe
	// TODO: filter Provider == ProbeProvider; map name -> ProbeKind via
	//       probeKindFromName; drop ProbeUnknown
	// TODO: store result (possibly empty slice) in m.parseCache
	return nil, nil
}

// probeKindFromName maps a USDT probe name to a ProbeKind. Provider is
// assumed to already have been filtered to ProbeProvider.
func probeKindFromName(name string) ProbeKind {
	switch name {
	case "alloc":
		return ProbeHeapAlloc
	case "free":
		return ProbeHeapFree
	// TODO: "mmap", "munmap" once defined upstream
	default:
		return ProbeUnknown
	}
}
