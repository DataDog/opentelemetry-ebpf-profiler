// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package allocator provides memory allocator discovery and symbol resolution
// for memory profiling. It auto-detects which allocator a process uses
// (glibc, tcmalloc, jemalloc, musl) and resolves the correct symbols for
// uprobe attachment, including handling versioned symbols and container namespaces.
package allocator

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// Sentinel errors for better error handling.
var (
	ErrUnsupportedAllocator = errors.New("allocator not supported in POC")
	ErrNoAllocatorFound     = errors.New("no allocator library found")
	ErrStaticBinary         = errors.New("static binary (no dynamic allocator)")
	ErrProcessGone          = errors.New("process exited during discovery")
)

// AllocatorType represents the type of memory allocator used by a process.
type AllocatorType int

const (
	// AllocatorUnknown indicates the allocator could not be determined.
	AllocatorUnknown AllocatorType = iota
	// AllocatorGlibc indicates the GNU C Library allocator (malloc/free).
	AllocatorGlibc
	// AllocatorTcmalloc indicates Google's TCMalloc allocator.
	AllocatorTcmalloc
	// AllocatorJemalloc indicates the jemalloc allocator.
	AllocatorJemalloc
	// AllocatorMusl indicates the musl libc allocator (Alpine Linux).
	AllocatorMusl
	// AllocatorStatic indicates a statically linked binary.
	AllocatorStatic
)

// String returns a human-readable name for the allocator type.
func (a AllocatorType) String() string {
	switch a {
	case AllocatorGlibc:
		return "glibc"
	case AllocatorTcmalloc:
		return "tcmalloc"
	case AllocatorJemalloc:
		return "jemalloc"
	case AllocatorMusl:
		return "musl"
	case AllocatorStatic:
		return "static"
	default:
		return "unknown"
	}
}

// AllocatorInfo contains information about a process's memory allocator.
type AllocatorInfo struct {
	// Type is the detected allocator type.
	Type AllocatorType
	// LibraryPath is the absolute path to the allocator library, potentially
	// prefixed with /proc/PID/root for containers.
	LibraryPath string
	// Symbols maps function names to their actual symbol names in the library.
	// For example: {"malloc": "malloc@@GLIBC_2.2.5", "free": "free@@GLIBC_2.2.5"}
	Symbols map[string]string
}

// DiscoverAllocator detects which memory allocator a process is using by
// parsing /proc/PID/maps and resolving symbols. It prioritizes allocators
// in the order: tcmalloc > jemalloc > libc (glibc/musl).
//
// For POC, only glibc is fully supported. Other allocators are detected
// but return ErrUnsupportedAllocator to enable graceful degradation.
func DiscoverAllocator(pid int) (*AllocatorInfo, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsFile, err := os.Open(mapsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("PID %d: %w", pid, ErrProcessGone)
		}
		return nil, fmt.Errorf("PID %d: failed to open %s: %w", pid, mapsPath, err)
	}
	defer mapsFile.Close()

	// Scan /proc/PID/maps to find allocator libraries.
	// We track all candidates and choose by priority at the end.
	var (
		tcmallocPath string
		jemallocPath string
		libcPath     string
		hasExecutable bool
	)

	scanner := bufio.NewScanner(mapsFile)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse mapping line format:
		// address           perms offset  dev   inode   pathname
		// 7f1234567000-7f1234568000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6
		fields := strings.Fields(line)
		if len(fields) < 6 {
			// Anonymous mapping or special mapping without pathname
			continue
		}

		pathname := fields[5]

		// Track if we've seen any executable mapping (to detect static binaries)
		perms := fields[1]
		if strings.Contains(perms, "x") && !strings.HasPrefix(pathname, "[") {
			hasExecutable = true
		}

		// Check for tcmalloc (highest priority)
		if tcmallocPath == "" && strings.Contains(pathname, "libtcmalloc") {
			tcmallocPath = pathname
		}

		// Check for jemalloc (second priority)
		if jemallocPath == "" && strings.Contains(pathname, "libjemalloc") {
			jemallocPath = pathname
		}

		// Check for libc (glibc or musl) - only store first occurrence
		if libcPath == "" && (strings.Contains(pathname, "libc.so") || strings.Contains(pathname, "libc-")) {
			libcPath = pathname
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("PID %d: failed to scan %s: %w", pid, mapsPath, err)
	}

	// Choose allocator by priority
	var allocType AllocatorType
	var selectedPath string

	if tcmallocPath != "" {
		return &AllocatorInfo{
			Type: AllocatorTcmalloc,
		}, fmt.Errorf("PID %d: tcmalloc detected: %w (Phase 2)", pid, ErrUnsupportedAllocator)
	}

	if jemallocPath != "" {
		return &AllocatorInfo{
			Type: AllocatorJemalloc,
		}, fmt.Errorf("PID %d: jemalloc detected: %w (Phase 2)", pid, ErrUnsupportedAllocator)
	}

	if libcPath != "" {
		// Detect if it's musl or glibc
		if strings.Contains(libcPath, "musl") {
			return &AllocatorInfo{
				Type: AllocatorMusl,
			}, fmt.Errorf("PID %d: musl libc detected: %w (Phase 2)", pid, ErrUnsupportedAllocator)
		}
		allocType = AllocatorGlibc
		selectedPath = libcPath
	} else {
		// No allocator library found
		if hasExecutable {
			// Likely a static binary (Go, Rust)
			return &AllocatorInfo{
				Type: AllocatorStatic,
			}, fmt.Errorf("PID %d: %w (Go/Rust binary)", pid, ErrStaticBinary)
		}
		return &AllocatorInfo{
			Type: AllocatorUnknown,
		}, fmt.Errorf("PID %d: %w", pid, ErrNoAllocatorFound)
	}

	// Validate the library path is absolute and doesn't contain path traversal
	if !filepath.IsAbs(selectedPath) {
		return nil, fmt.Errorf("PID %d: library path is not absolute: %s", pid, selectedPath)
	}
	if strings.Contains(selectedPath, "..") {
		return nil, fmt.Errorf("PID %d: library path contains '..': %s", pid, selectedPath)
	}

	// Resolve the library path for namespace-aware access
	resolvedPath, err := resolveLibraryPath(pid, selectedPath)
	if err != nil {
		return nil, fmt.Errorf("PID %d: failed to resolve library path %s: %w", pid, selectedPath, err)
	}

	// Validate the resolved path exists before trying to parse it
	if _, err := os.Stat(resolvedPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("PID %d: library %s not accessible (container namespace issue?): %w",
				pid, resolvedPath, err)
		}
		return nil, fmt.Errorf("PID %d: cannot stat library %s: %w", pid, resolvedPath, err)
	}

	// Resolve symbols from the library
	symbols, err := resolveLibcSymbols(pid, resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("PID %d: failed to resolve symbols from %s: %w", pid, resolvedPath, err)
	}

	return &AllocatorInfo{
		Type:        allocType,
		LibraryPath: resolvedPath,
		Symbols:     symbols,
	}, nil
}

// resolveLibraryPath converts a library path from /proc/PID/maps into
// a namespace-aware path suitable for opening the ELF file. For processes
// in containers with different mount namespaces, this prefixes the path
// with /proc/PID/root.
func resolveLibraryPath(pid int, libraryPath string) (string, error) {
	// Check if the process is in a different mount namespace by comparing
	// the mount namespace inode of the process with our own.
	selfNsPath := "/proc/self/ns/mnt"
	procNsPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	var selfStat, procStat syscall.Stat_t

	// If we can't stat our own namespace, that's a real error
	if err := syscall.Stat(selfNsPath, &selfStat); err != nil {
		return "", fmt.Errorf("cannot stat own mount namespace %s: %w (missing capabilities?)", selfNsPath, err)
	}

	// If we can't stat the process namespace, it might have exited
	if err := syscall.Stat(procNsPath, &procStat); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return "", fmt.Errorf("%w", ErrProcessGone)
		}
		return "", fmt.Errorf("cannot stat process %d mount namespace: %w (permission denied?)", pid, err)
	}

	// If inodes match, we're in the same mount namespace
	if selfStat.Ino == procStat.Ino {
		return libraryPath, nil
	}

	// Different mount namespace (container) - use /proc/PID/root prefix
	return fmt.Sprintf("/proc/%d/root%s", pid, libraryPath), nil
}

// resolveLibcSymbols reads the ELF file and resolves malloc/free symbols,
// handling versioned symbols like malloc@@GLIBC_2.2.5. It returns a map
// of function names to their actual symbol names.
func resolveLibcSymbols(pid int, libPath string) (map[string]string, error) {
	// Open the ELF file using pfelf
	elfFile, err := pfelf.Open(libPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer elfFile.Close()

	symbols := make(map[string]string, 3) // Pre-allocate for malloc, free, and realloc

	// Create a set for faster lookup
	requiredSet := map[string]bool{
		"malloc":  true,
		"free":    true,
		"realloc": true,
	}

	// Visit dynamic symbols to find malloc and free
	// Dynamic symbols are used for shared libraries
	err = elfFile.VisitDynamicSymbols(func(sym libpf.Symbol) bool {
		symName := string(sym.Name)

		// Split on '@' to get base name for versioned symbols
		// Example: "malloc@@GLIBC_2.2.5" -> "malloc"
		baseName := symName
		if idx := strings.IndexByte(symName, '@'); idx != -1 {
			baseName = symName[:idx]
		}

		// Check if this is a required symbol
		if requiredSet[baseName] {
			// Store the full symbol name (with version if present)
			// Only store if we haven't seen this base name yet
			if _, exists := symbols[baseName]; !exists {
				symbols[baseName] = symName
			}

			// Early exit if we found all required symbols
			if len(symbols) == len(requiredSet) {
				return false
			}
		}

		return true
	})

	if err != nil {
		return nil, fmt.Errorf("failed to visit dynamic symbols: %w", err)
	}

	// Verify we found all required symbols
	for required := range requiredSet {
		if _, found := symbols[required]; !found {
			return nil, fmt.Errorf("required symbol '%s' not found", required)
		}
	}

	return symbols, nil
}

// GetProcessExeInode returns the inode of the process's executable for caching purposes.
// This helps detect if the process has exec'd into a different binary.
func GetProcessExeInode(pid int) (uint64, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	var stat syscall.Stat_t
	if err := syscall.Stat(exePath, &stat); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return 0, ErrProcessGone
		}
		return 0, fmt.Errorf("failed to stat %s: %w", exePath, err)
	}
	return stat.Ino, nil
}
