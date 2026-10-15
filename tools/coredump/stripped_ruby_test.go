// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/cloudstore"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

// Strip only a temporary copy, without a dependency on objcopy or new uploaded
// fixtures. Erase the non-allocated symbol/debug sections and their headers;
// preserve .dynsym, .eh_frame and all loaded bytes and addresses.
func stripRubyTestModule(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	file, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	require.Equal(t, elf.ELFCLASS64, file.Class)
	require.Equal(t, elf.ELFDATA2LSB, file.Data)
	var header elf.Header64
	require.NoError(t, binary.Read(bytes.NewReader(data), binary.LittleEndian, &header))
	removedSymbols := false
	for i, section := range file.Sections {
		if section.Type != elf.SHT_SYMTAB && section.Name != ".strtab" &&
			!strings.HasPrefix(section.Name, ".debug") && !strings.HasPrefix(section.Name, ".zdebug") &&
			section.Name != ".gnu_debuglink" && section.Name != ".gnu_debugaltlink" {
			continue
		}
		require.Zero(t, section.Flags&elf.SHF_ALLOC)
		removedSymbols = removedSymbols || section.Type == elf.SHT_SYMTAB
		require.LessOrEqual(t, section.Offset+section.FileSize, uint64(len(data)))
		clear(data[section.Offset : section.Offset+section.FileSize])
		off := header.Shoff + uint64(i)*uint64(header.Shentsize)
		clear(data[off : off+uint64(header.Shentsize)])
	}
	require.True(t, removedSymbols, "fixture must exercise removal of local symbols")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	stripped, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	require.Nil(t, stripped.Section(".symtab"))
	symbols, err := stripped.DynamicSymbols()
	require.NoError(t, err)
	for _, symbol := range symbols {
		switch symbol.Name {
		case "ruby_current_ec", "rb_vm_exec", "ruby_global_symbols", "ruby_single_main_ractor":
			t.Fatalf("fixture exports %s; discovery would not be exercised", symbol.Name)
		}
	}
}

type strippedRubyProcess struct {
	process.Process
	modulePath  string
	replacement string
}

func (p *strippedRubyProcess) OpenMappingFile(mapping *process.RawMapping) (fs.File, error) {
	if mapping.Path == p.modulePath {
		return os.Open(p.replacement)
	}
	return p.Process.OpenMappingFile(mapping)
}

func (p *strippedRubyProcess) Open(name string) (fs.File, error) {
	if "/"+name == p.modulePath {
		return os.Open(p.replacement)
	}
	return p.Process.Open(name)
}

func TestStrippedRubyCoreDumps(t *testing.T) {
	store, err := modulestore.New(nil, cloudstore.PublicReadURL(), cloudstore.ModulestoreS3Bucket(), "modulecache")
	require.NoError(t, err)
	cases := []string{"3.3.9-loop", "4.0.1-loop", "4.0.6-loop"}
	if runtime.GOARCH == "arm64" {
		// There is no AMD64 fixture for Ruby 3.3.9 with Ractors.
		cases = append(cases, "3.3.9-loop-with-ractors")
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := filepath.Join("testdata", runtime.GOARCH, "ruby-"+name+".json")
			testCase, err := readTestCase(fixture)
			require.NoError(t, err)
			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
			require.NoError(t, err)
			defer core.Close()
			pr := &strippedRubyProcess{Process: core}
			for _, module := range testCase.Modules {
				if !strings.HasPrefix(filepath.Base(module.LocalPath), "libruby.so.") {
					continue
				}
				require.Empty(t, pr.modulePath, "multiple libruby modules")
				pr.modulePath = module.LocalPath
				pr.replacement = filepath.Join(t.TempDir(), "libruby.so")
				require.NoError(t, store.UnpackModuleToPath(module.Ref, pr.replacement))
				stripRubyTestModule(t, pr.replacement)
			}
			require.NotEmpty(t, pr.modulePath)
			data, err := ExtractTracesWithInterpreters(t.Context(), pr, false, nil, nil,
				testCase.interpretersConfig())
			require.NoError(t, err)
			require.Equal(t, testCase.Threads, data)
		})
	}
}
