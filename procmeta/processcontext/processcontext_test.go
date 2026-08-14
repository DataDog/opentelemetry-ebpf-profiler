// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package processcontext

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	processcontextpb "go.opentelemetry.io/proto/otlp/processcontext/v1development"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

var testContext = processcontextpb.ProcessContext{
	Resource: &resourcepb.Resource{
		Attributes: []*commonpb.KeyValue{
			{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{
						StringValue: "test-service",
					},
				},
			},
			{
				Key: "service.version",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_IntValue{
						IntValue: 42,
					},
				},
			},
			{
				Key: "service.active",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_BoolValue{
						BoolValue: true,
					},
				},
			},
			{
				Key: "service.weight",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_DoubleValue{
						DoubleValue: 3.14,
					},
				},
			},
			{
				Key: "service.tags",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_ArrayValue{
						ArrayValue: &commonpb.ArrayValue{
							Values: []*commonpb.AnyValue{
								{Value: &commonpb.AnyValue_StringValue{StringValue: "tag1"}},
								{Value: &commonpb.AnyValue_IntValue{IntValue: 2}},
							},
						},
					},
				},
			},
			{
				Key: "service.metadata",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_KvlistValue{
						KvlistValue: &commonpb.KeyValueList{
							Values: []*commonpb.KeyValue{
								{
									Key: "nested.key",
									Value: &commonpb.AnyValue{
										Value: &commonpb.AnyValue_StringValue{
											StringValue: "nested-value",
										},
									},
								},
								{
									Key: "nested.count",
									Value: &commonpb.AnyValue{
										Value: &commonpb.AnyValue_IntValue{
											IntValue: 7,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	},
	Attributes: []*commonpb.KeyValue{
		{
			Key: "custom.attribute",
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: "custom-value",
				},
			},
		},
	},
}

// mockReader serves reads from a set of (address, bytes) regions. A read may
// not span two regions.
type mockReader struct {
	regions []mockRegion
	err     error
}

type mockRegion struct {
	addr uint64
	data []byte
}

func newMockReader() *mockReader {
	return &mockReader{}
}

func (m *mockReader) setError(err error) {
	m.err = err
}

func (m *mockReader) writeAt(addr uint64, data []byte) {
	m.regions = append(m.regions, mockRegion{addr: addr, data: append([]byte{}, data...)})
}

func (m *mockReader) ReadAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}

	addr := uint64(off)
	for _, r := range m.regions {
		if addr >= r.addr && addr+uint64(len(p)) <= r.addr+uint64(len(r.data)) {
			offset := addr - r.addr
			copy(p, r.data[offset:offset+uint64(len(p))])
			return len(p), nil
		}
	}
	return 0, io.EOF
}

// createHeader serializes via the header struct itself, so a layout change in
// the reader cannot leave the fixtures producing a stale wire format.
func createHeader(signature string, version uint32, payloadSize uint32, payloadPtr uint64, publishedAt uint64) []byte {
	hdr := header{
		Version:                version,
		PayloadSize:            payloadSize,
		MonotonicPublishedAtNs: publishedAt,
		PayloadPtr:             payloadPtr,
	}
	copy(hdr.Signature[:], signature)
	return bytes.Clone(pfunsafe.FromPointer(&hdr))
}

func createValidHeader(payloadSize uint32, payloadPtr uint64, publishedAt uint64) []byte {
	return createHeader(signatureOTELCTX, supportedVersion, payloadSize, payloadPtr, publishedAt)
}

func TestProcessContext_IsContextMapping(t *testing.T) {
	assert.True(t, IsContextMapping(false, "[anon:OTEL_CTX]"))
	assert.True(t, IsContextMapping(false, "[anon_shmem:OTEL_CTX]"))
	assert.True(t, IsContextMapping(false, "/memfd:OTEL_CTX"))
	assert.True(t, IsContextMapping(false, "/memfd:OTEL_CTX (deleted)"))
	assert.False(t, IsContextMapping(false, "test"))
	assert.False(t, IsContextMapping(true, "[anon:OTEL_CTX]"))
}

func TestProcessContext_Read(t *testing.T) {
	payload, err := proto.Marshal(&testContext)
	require.NoError(t, err)

	mappingAddr := libpf.Address(0x1000)

	tests := []struct {
		name              string
		setupMock         func(*mockReader)
		expectedResult    Info
		expectedErr       error
		errorSubstring    string
		lastPublishedAtNs uint64
	}{
		{
			name: "success with valid context",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				payloadAddr := uint64(0x2000)
				header := createValidHeader(uint32(len(payload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, payload)
			},
			expectedResult: Info{
				ResourceAttrs: expectedResourceAttrs(),
				publishedAtNs: 123456789,
				valid:         true,
			},
		},
		{
			name: "read error",
			setupMock: func(mock *mockReader) {
				mock.setError(errors.New("read error"))
			},
			expectedErr: errInvalidContext,
		},
		{
			name: "invalid protobuf",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				payloadAddr := uint64(0x2000)
				invalidPayload := []byte{0xff, 0xff, 0xff, 0xff}
				header := createValidHeader(uint32(len(invalidPayload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, invalidPayload)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "failed to unmarshal",
		},
		{
			name: "invalid signature",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader("INVALID!", supportedVersion, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "signature",
		},
		{
			name: "invalid version",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader(signatureOTELCTX, 999, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "version",
		},
		{
			name: "zero payload size",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(0, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "payload size too large",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader(signatureOTELCTX, supportedVersion, 1024*1024, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "published at zero - update in progress",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 0)
				mock.writeAt(headerAddr, header)
			},
			expectedErr: errConcurrentUpdate,
		},
		{
			name: "published at same as last published",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 123456788)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       errNoUpdate,
		},
		{
			name: "published at too old",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 123456787)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       errNoUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReader()
			tt.setupMock(mock)

			rm := remotememory.RemoteMemory{ReaderAt: mock}

			info, err := read(mappingAddr, 0, rm, tt.lastPublishedAtNs, 0)

			if tt.expectedErr == nil {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResult, info)
			} else {
				assert.Zero(t, info.ResourceAttrs.Len())
				assert.Nil(t, info.ThreadLabelDecoder())
				assert.Zero(t, info.publishedAtNs)
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
			}
		})
	}
}

func TestProcessContext_Read_RealProcessContext(t *testing.T) {
	tests := []struct {
		name     string
		useMemfd bool
		usePrctl bool
	}{
		{
			name:     "memfd only",
			useMemfd: true,
			usePrctl: false,
		},
		{
			name:     "prctl only",
			useMemfd: false,
			usePrctl: true,
		},
		{
			name:     "memfd and prctl",
			useMemfd: true,
			usePrctl: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := proto.Marshal(&testContext)
			require.NoError(t, err)

			payloadAddr := libpf.Address(unsafe.Pointer(&payload[0]))
			header := createValidHeader(uint32(len(payload)), uint64(payloadAddr), 123456789)

			memSize := len(header)
			var mem []byte
			if tt.useMemfd {
				fd, err := unix.MemfdCreate(signatureOTELCTX, 0)
				require.NoError(t, err)
				defer unix.Close(fd)

				err = unix.Ftruncate(fd, int64(memSize))
				require.NoError(t, err)
				mem, err = unix.Mmap(
					fd, 0, memSize,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_PRIVATE,
				)
				require.NoError(t, err)
				defer unix.Munmap(mem)
				unix.Close(fd)
			} else {
				mem, err = unix.Mmap(
					-1, 0, memSize,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
				)
				require.NoError(t, err)
				defer unix.Munmap(mem)
			}

			copy(mem[0:len(header)], header)

			if tt.usePrctl {
				nameNullTerminated, _ := unix.ByteSliceFromString(signatureOTELCTX)
				err = unix.Prctl(unix.PR_SET_VMA,
					unix.PR_SET_VMA_ANON_NAME,
					uintptr(unsafe.Pointer(&mem[0])),
					uintptr(memSize),
					uintptr(unsafe.Pointer(&nameNullTerminated[0])),
				)
				if err != nil {
					t.Skipf("prctl not supported: %v", err)
				}
			}

			pid := libpf.PID(os.Getpid())
			proc := process.New(pid, pid)
			defer proc.Close()

			var contextMappingAddr uint64
			_, err = proc.IterateMappings(func(m process.RawMapping) bool {
				if IsContextMapping(m.IsExecutable(), m.Path) {
					contextMappingAddr = m.Vaddr
					return false
				}
				return true
			})
			if err != nil && !errors.Is(err, process.ErrCallbackStopped) {
				require.NoError(t, err)
			}
			require.NotZero(t, contextMappingAddr)

			info, err := read(libpf.Address(contextMappingAddr), pid, proc.GetRemoteMemory(), 0, 0)
			require.NoError(t, err)
			require.Equal(t,
				Info{
					ResourceAttrs: expectedResourceAttrs(),
					publishedAtNs: 123456789,
					valid:         true,
				},
				info)

		})
	}
}

func expectedResourceAttrs() attribute.Set {
	return attribute.NewSet(
		attribute.String("service.name", "test-service"),
		attribute.Int64("service.version", 42),
		attribute.Bool("service.active", true),
		attribute.Float64("service.weight", 3.14),
		attribute.Slice("service.tags",
			attribute.StringValue("tag1"),
			attribute.Int64Value(2)),
		attribute.Map("service.metadata",
			attribute.String("nested.key", "nested-value"),
			attribute.Int64("nested.count", 7)),
	)
}

func serviceName(t *testing.T, info Info) string {
	t.Helper()
	v, ok := info.ResourceAttrs.Value("service.name")
	require.True(t, ok)
	return v.AsString()
}

func buildPayload(t *testing.T, threadAttrs ...*commonpb.KeyValue) []byte {
	t.Helper()
	payload, err := proto.Marshal(&processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			{Key: "service.name", Value: strVal("test-service")},
		}},
		Attributes: threadAttrs,
	})
	require.NoError(t, err)
	return payload
}

// An AnyValue with no variant set is a valid empty value per OTLP
// common.proto. The key must survive the read with an EMPTY value rather than
// be dropped.
func TestProcessContext_Read_KeepsEmptyValues(t *testing.T) {
	payload, err := proto.Marshal(&processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			{Key: "set", Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{StringValue: "v"}}},
			{Key: "unset.oneof", Value: &commonpb.AnyValue{}},
			{Key: "absent.value"},
		}},
	})
	require.NoError(t, err)

	const payloadAddr = 0x2000
	mock := newMockReader()
	mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), payloadAddr, 1))
	mock.writeAt(payloadAddr, payload)

	info, err := read(libpf.Address(0x1000), 0,
		remotememory.RemoteMemory{ReaderAt: mock}, 0, 0)
	require.NoError(t, err)

	require.Equal(t, attribute.NewSet(
		attribute.String("set", "v"),
		attribute.KeyValue{Key: "unset.oneof"},
		attribute.KeyValue{Key: "absent.value"},
	), info.ResourceAttrs)
}

// tornTimestampReader simulates a concurrent publish observed between
// readOnce's two coherence checks.
type tornTimestampReader struct {
	inner         io.ReaderAt
	tsAddr        int64
	first, second uint64
	reads         int
}

func (r *tornTimestampReader) ReadAt(p []byte, off int64) (int, error) {
	if off == r.tsAddr && len(p) == 8 {
		r.reads++
		ts := r.first
		if r.reads > 1 {
			ts = r.second
		}
		binary.LittleEndian.PutUint64(p, ts)
		return len(p), nil
	}
	return r.inner.ReadAt(p, off)
}

// A publish landing between the header and the payload read can leave garbage
// mid-unmarshal at the payload address. The recheck must report this as a
// concurrent update, not surface the garbage as errInvalidContext: readPayload's
// error is only genuine when the timestamp is stable across both reads.
func TestProcessContext_Read_TornPayload(t *testing.T) {
	garbage := []byte{0xff, 0xff, 0xff, 0xff}
	mock := newMockReader()
	mock.writeAt(0x1000, createValidHeader(uint32(len(garbage)), 0x2000, 1))
	mock.writeAt(0x2000, garbage)

	reader := &tornTimestampReader{
		inner:  mock,
		tsAddr: 0x1000 + int64(monotonicPublishedAtNsOffset),
		first:  1,
		second: 2,
	}

	info, err := readOnce(libpf.Address(0x1000), 0,
		remotememory.RemoteMemory{ReaderAt: reader}, 0)
	require.ErrorIs(t, err, errConcurrentUpdate)
	require.NotErrorIs(t, err, errInvalidContext)
	assert.Zero(t, info)
}

func TestProcessContext_Read_ThreadContext(t *testing.T) {
	validSchema := []*commonpb.KeyValue{
		attr(threadCtxSchemaVersionKey, strVal(supportedThreadCtxSchemaVersion)),
		attr(threadCtxKeyMapKey, arrVal(strVal("route"), strVal("method"))),
	}
	malformedSchema := []*commonpb.KeyValue{
		attr(threadCtxSchemaVersionKey, strVal("v99")),
	}

	t.Run("valid schema reaches Info.threadCtx", func(t *testing.T) {
		payload := buildPayload(t, validSchema...)
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), 0x2000, 1))
		mock.writeAt(0x2000, payload)

		info, err := read(libpf.Address(0x1000), 0,
			remotememory.RemoteMemory{ReaderAt: mock}, 0, 0)
		require.NoError(t, err)

		decoder := info.ThreadLabelDecoder()
		require.NotNil(t, decoder)
		labels, dropped := decoder.DecodeLabels(append([]byte{0, 3}, "/rt"...))
		assert.Zero(t, dropped)
		assert.Equal(t,
			libpf.ThreadLabels{libpf.Intern("route"): libpf.Intern("/rt")},
			labels)
	})

	t.Run("malformed schema is non-fatal", func(t *testing.T) {
		payload := buildPayload(t, malformedSchema...)
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), 0x2000, 1))
		mock.writeAt(0x2000, payload)

		info, err := read(libpf.Address(0x1000), 0,
			remotememory.RemoteMemory{ReaderAt: mock}, 0, 0)
		require.NoError(t, err)
		assert.Equal(t, "test-service", serviceName(t, info))
		assert.Nil(t, info.ThreadLabelDecoder())
	})
}

func TestResolve(t *testing.T) {
	resolvedEmpty := Info{publishedAtNs: 7, valid: true}
	midUpdate := func() remotememory.RemoteMemory {
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(100, 0x2000, 0))
		return remotememory.RemoteMemory{ReaderAt: mock}
	}

	t.Run("no mapping has no contribution", func(t *testing.T) {
		info, changed := Resolve(0, 1, remotememory.RemoteMemory{}, Info{})
		assert.False(t, changed)
		assert.Equal(t, Info{}, info)
	})
	t.Run("mapping disappeared withdraws its attributes", func(t *testing.T) {
		old := Info{
			ResourceAttrs: attribute.NewSet(attribute.String("from.mapping", "v")),
			publishedAtNs: 7, valid: true,
		}
		info, changed := Resolve(0, 1, remotememory.RemoteMemory{}, old)
		assert.True(t, changed)
		assert.Equal(t, Info{}, info)
	})
	t.Run("concurrent update preserves an empty resolved context", func(t *testing.T) {
		info, changed := Resolve(0x1000, 1, midUpdate(), resolvedEmpty)
		assert.False(t, changed)
		assert.Equal(t, resolvedEmpty, info)
	})
	t.Run("initial concurrent update has no contribution", func(t *testing.T) {
		info, changed := Resolve(0x1000, 1, midUpdate(), Info{})
		assert.False(t, changed)
		assert.Equal(t, Info{}, info)
	})
	t.Run("read failure withdraws a stale contribution", func(t *testing.T) {
		mock := newMockReader()
		mock.setError(errors.New("read error"))
		info, changed := Resolve(0x1000, 1,
			remotememory.RemoteMemory{ReaderAt: mock}, resolvedEmpty)
		assert.True(t, changed)
		assert.Equal(t, Info{}, info)
	})
	t.Run("successful publication and unchanged timestamp", func(t *testing.T) {
		payload, err := proto.Marshal(&testContext)
		require.NoError(t, err)
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), 0x2000, 7))
		mock.writeAt(0x2000, payload)
		rm := remotememory.RemoteMemory{ReaderAt: mock}
		first, changed := Resolve(0x1000, 1, rm, Info{})
		require.True(t, changed)
		require.True(t, first.valid)
		assert.Equal(t, "test-service", serviceName(t, first))
		second, changed := Resolve(0x1000, 1, rm, first)
		assert.False(t, changed)
		assert.Equal(t, first, second)
	})
}
