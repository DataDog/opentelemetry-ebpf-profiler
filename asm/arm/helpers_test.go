// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	aa "golang.org/x/arch/arm64/arm64asm"
)

func TestParseImmField(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		// ImmShift's bare form. decodeImmShift handles the shifted form.
		{"#0x1234", 0x1234, true},
		// MemImmediate prints signed decimal, bracketed except post-index.
		{"#16]", 16, true},
		{"#-16]", -16, true},
		{" #16", 16, true},
		{"#0", 0, true},
		// No immediate, or not a number.
		{"X5", 0, false},
		{"#", 0, false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseImmField(tc.in)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDecodeImmediateShiftedImm pins that the ADD/SUB immediate's optional
// "LSL #12" is applied, not discarded: arm64asm renders it as part of the
// same ImmShift string parseImmField alone would truncate at the comma.
func TestDecodeImmediateShiftedImm(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
		want int64
	}{
		{"no shift", 0x910aa020, 0x2a8},           // add x0, x1, #0x2a8
		{"lsl #12", 0x91400420, 0x1000},           // add x0, x1, #0x1, lsl #12
		{"max shifted imm", 0x917ffc20, 0xfff000}, // add x0, x1, #0xfff, lsl #12
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := aa.Decode(insns(tc.code))
			require.NoError(t, err)
			require.IsType(t, aa.ImmShift{}, inst.Args[2])

			got, ok := DecodeImmediate(inst.Args[2])
			assert.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestXreg2numRejectsExtendedOperand(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
		want int
		ok   bool
	}{
		{"bare register", 0x8b020020, 2, true},        // add x0, x1, x2
		{"lsl", 0x8b020c20, 0, false},                 // add x0, x1, x2, lsl #3
		{"sxtw without amount", 0x8b22c020, 0, false}, // add x0, x1, w2, sxtw
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := aa.Decode(insns(tc.code))
			require.NoError(t, err)
			require.IsType(t, aa.RegExtshiftAmount{}, inst.Args[2])

			got, ok := Xreg2num(inst.Args[2])
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
