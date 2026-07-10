// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"path/filepath"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/liveheap"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
)

// appendInuseProfiles appends inuse_space and inuse_objects profiles to the
// existing Profiles object, sharing the same dictionary and ordered sets.
// Profiles are added to existing ResourceProfiles entries (matched by PID)
// so the backend sees them in the same upload group as alloc+cpu.
func appendInuseProfiles(
	profiles pprofile.Profiles,
	dic pprofile.ProfilesDictionary,
	stringSet orderedset.OrderedSet[string],
	funcSet orderedset.OrderedSet[funcInfo],
	locationSet orderedset.OrderedSet[locationInfo],
	mappingSet orderedset.OrderedSet[libpf.FrameMapping],
	stackSet orderedset.OrderedSet[stackInfo],
	agentName, agentVersion string,
	collectionStartTime, collectionEndTime time.Time,
	entries []liveheap.InuseEntry,
	processMeta func(libpf.PID) liveheap.ProcessMeta,
) {
	// Group entries by PID for per-process resource profiles.
	byPID := make(map[libpf.PID][]liveheap.InuseEntry)
	for _, e := range entries {
		byPID[e.PID] = append(byPID[e.PID], e)
	}

	durationNanos := uint64(collectionEndTime.Sub(collectionStartTime).Nanoseconds())

	// Build an index of existing ResourceProfiles by PID so we can append
	// inuse profiles to the same resource that holds alloc+cpu.
	rpByPID := make(map[libpf.PID]pprofile.ResourceProfiles)
	for i := range profiles.ResourceProfiles().Len() {
		rp := profiles.ResourceProfiles().At(i)
		pidVal, ok := rp.Resource().Attributes().Get(string(semconv.ProcessPIDKey))
		if ok {
			rpByPID[libpf.PID(pidVal.Int())] = rp
		}
	}

	for pid, pidEntries := range byPID {
		// Try to find the existing ResourceProfiles for this PID.
		rp, found := rpByPID[pid]
		if !found {
			// No existing resource for this PID — create a new one.
			rp = profiles.ResourceProfiles().AppendEmpty()
			attrs := rp.Resource().Attributes()
			attrs.PutInt(string(semconv.ProcessPIDKey), int64(pid))
			if processMeta != nil {
				meta := processMeta(pid)
				if meta.ExecutablePath != libpf.NullString {
					attrs.PutStr(string(semconv.ProcessExecutablePathKey), meta.ExecutablePath.String())
					_, exeName := filepath.Split(meta.ExecutablePath.String())
					attrs.PutStr(string(semconv.ProcessExecutableNameKey), exeName)
				}
				if meta.ContainerID != libpf.NullString {
					attrs.PutStr(string(semconv.ContainerIDKey), meta.ContainerID.String())
				}
			}
		}

		// Find or create a ScopeProfiles within this resource.
		var sp pprofile.ScopeProfiles
		if rp.ScopeProfiles().Len() > 0 {
			sp = rp.ScopeProfiles().At(0)
		} else {
			sp = rp.ScopeProfiles().AppendEmpty()
			scope := sp.Scope()
			scope.SetName(agentName)
			scope.SetVersion(agentVersion)
		}

		for _, kind := range []profileKind{profileKindHeapInuseSpace, profileKindHeapInuseObjects} {
			prof := sp.Profiles().AppendEmpty()

			st := prof.SampleType()
			if kind == profileKindHeapInuseSpace {
				st.SetTypeStrindex(stringSet.Add("inuse_space"))
				st.SetUnitStrindex(stringSet.Add("bytes"))
			} else {
				st.SetTypeStrindex(stringSet.Add("inuse_objects"))
				st.SetUnitStrindex(stringSet.Add("count"))
			}

			for _, entry := range pidEntries {
				sample := prof.Samples().AppendEmpty()
				if kind == profileKindHeapInuseSpace {
					sample.Values().Append(entry.Space)
				} else {
					sample.Values().Append(entry.Objects)
				}
				sample.TimestampsUnixNano().Append(uint64(collectionEndTime.UnixNano()))

				// Build location indices from frames.
				locationIndices := make([]int32, 0, len(entry.Frames))
				for _, uniqueFrame := range entry.Frames {
					frame := uniqueFrame.Value()
					locInfo := locationInfo{
						address:   uint64(frame.AddressOrLineno),
						frameType: frame.Type,
					}

					index, ok := mappingSet.AddWithCheck(frame.Mapping)
					if !ok {
						m := frame.Mapping.Value()
						mf := m.File.Value()
						mapping := dic.MappingTable().AppendEmpty()
						mapping.SetMemoryStart(uint64(m.Start))
						mapping.SetMemoryLimit(uint64(m.End))
						mapping.SetFileOffset(m.FileOffset)
						mapping.SetFilenameStrindex(stringSet.Add(mf.FileName.String()))
					}
					locInfo.mappingIndex = index

					if frame.FunctionName != libpf.NullString || frame.SourceFile != libpf.NullString {
						locInfo.hasLine = true
						locInfo.lineNumber = int64(frame.SourceLine)
						locInfo.columnNumber = int64(frame.SourceColumn)
						fi := funcInfo{
							nameIdx:     stringSet.Add(frame.FunctionName.String()),
							fileNameIdx: stringSet.Add(frame.SourceFile.String()),
						}
						locInfo.functionIndex = funcSet.Add(fi)
					}

					idx, exists := locationSet.AddWithCheck(locInfo)
					if !exists {
						loc := dic.LocationTable().AppendEmpty()
						loc.SetAddress(locInfo.address)
						loc.SetMappingIndex(locInfo.mappingIndex)
						if locInfo.hasLine {
							line := loc.Lines().AppendEmpty()
							line.SetLine(locInfo.lineNumber)
							line.SetColumn(locInfo.columnNumber)
							line.SetFunctionIndex(locInfo.functionIndex)
						}
					}
					locationIndices = append(locationIndices, idx)
				}

				stackIdx, exists := stackSet.AddWithCheck(stackInfo{
					locationIndicesHash: hashLocationIndices(locationIndices),
				})
				if !exists {
					stack := dic.StackTable().AppendEmpty()
					for _, locIdx := range locationIndices {
						stack.LocationIndices().Append(locIdx)
					}
				}
				sample.SetStackIndex(stackIdx)
			}

			prof.SetDurationNano(durationNanos)
			prof.SetTime(pcommon.Timestamp(collectionStartTime.UnixNano()))
		}
	}

	log.Debugf("HEAP_PROFILE_PIPELINE stage=pdata_inuse_appended pids=%d entries=%d",
		len(byPID), len(entries))
}
