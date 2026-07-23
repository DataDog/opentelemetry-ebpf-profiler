// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

type attributeStruct struct {
	Key   string
	Value any
}

func TestAttrTableManager(t *testing.T) {
	tests := map[string]struct {
		k                      []ResourceKey
		expectedIndices        [][]int32
		expectedAttributeTable []attributeStruct
	}{
		"empty": {
			k: []ResourceKey{
				{
					ServiceName: "",
					PID:         0,
				},
			},
			expectedIndices: [][]int32{{0}},
			expectedAttributeTable: []attributeStruct{
				{Key: "process.pid", Value: int64(0)},
			},
		},
		"duplicate": {
			k: []ResourceKey{
				{
					ServiceName: "APMServiceName1",
					PID:         1234,
				},
				{
					ServiceName: "APMServiceName1",
					PID:         1234,
				},
			},
			expectedIndices: [][]int32{{0, 1}, {0, 1}},
			expectedAttributeTable: []attributeStruct{
				{Key: "service.name", Value: "APMServiceName1"},
				{Key: "process.pid", Value: int64(1234)},
			},
		},
		"different": {
			k: []ResourceKey{
				{
					ServiceName: "APMServiceName1",
					PID:         1234,
				},
				{
					ServiceName: "APMServiceName2",
					PID:         6789,
				},
			},
			expectedIndices: [][]int32{{0, 1}, {2, 3}},
			expectedAttributeTable: []attributeStruct{
				{Key: "service.name", Value: "APMServiceName1"},
				{Key: "process.pid", Value: int64(1234)},
				{Key: "service.name", Value: "APMServiceName2"},
				{Key: "process.pid", Value: int64(6789)},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			strSet := orderedset.OrderedSet[string]{}
			attrTable := pprofile.NewKeyValueAndUnitSlice()
			mgr := NewAttrTableManager(strSet, attrTable)
			indices := make([][]int32, 0)
			for _, k := range tc.k {
				inner := pcommon.NewInt32Slice()
				mgr.AppendOptionalString(inner, semconv.ServiceNameKey, k.ServiceName)
				mgr.AppendInt(inner, semconv.ProcessPIDKey, k.PID)
				indices = append(indices, inner.AsRaw())
			}

			require.Equal(t, tc.expectedIndices, indices)
			require.Equal(t, len(tc.expectedAttributeTable), attrTable.Len())
			strSlice := strSet.ToSlice()

			for i, v := range tc.expectedAttributeTable {
				attr := attrTable.At(i)
				assert.Equal(t, v.Key, strSlice[int(attr.KeyStrindex())])
				assert.Equal(t, v.Value, attr.Value().AsRaw())
			}
		})
	}
}
