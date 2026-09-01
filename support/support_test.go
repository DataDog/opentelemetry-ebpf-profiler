package support

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestSizeOfCGoStruct(t *testing.T) {
	tests := []struct {
		// Name of Go wrapper struct
		name  string
		input uintptr
		want  uintptr
	}{
		{name: "ApmIntProcInfo", input: unsafe.Sizeof(ApmIntProcInfo{}),
			want: sizeof_ApmIntProcInfo},
		{name: "DotnetProcInfo", input: unsafe.Sizeof(DotnetProcInfo{}),
			want: sizeof_DotnetProcInfo},
		{name: "PHPProcInfo", input: unsafe.Sizeof(PHPProcInfo{}),
			want: sizeof_PHPProcInfo},
		{name: "RubyProcInfo", input: unsafe.Sizeof(RubyProcInfo{}),
			want: sizeof_RubyProcInfo},
		{name: "ThreadContextProcInfo", input: unsafe.Sizeof(ThreadContextProcInfo{}),
			want: sizeof_ThreadContextProcInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equalf(t, tt.want, tt.input,
				"unsafe.Sizeof(%v{}) = %v, want %v", tt.name, tt.input, tt.want)
		})
	}
}

// TestCustomLabelsUnionAlignment guards the unsafe.Pointer reinterpret of
// Trace.Custom_labels_data as CustomLabelsArray (tracer/tracer.go): the field
// must be aligned for CustomLabelsArray, or the cast reads misaligned data.
func TestCustomLabelsUnionAlignment(t *testing.T) {
	require.Zero(t,
		unsafe.Offsetof(Trace{}.Custom_labels_data)%unsafe.Alignof(CustomLabelsArray{}),
		"Trace.Custom_labels_data is not aligned for CustomLabelsArray")
}
