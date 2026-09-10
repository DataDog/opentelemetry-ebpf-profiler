// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSignExtendSimplification pins the canonical shape: arm SXTW and x86
// MOVSX must build the same expression, or patterns become arch-dependent.
func TestSignExtendSimplification(t *testing.T) {
	x := Named("x")

	for _, tc := range []struct {
		name string
		got  Expression
		want string
	}{
		{
			"zero-extend of the same width is absorbed",
			SignExtend(ZeroExtend32(x), 32),
			"sign-extend(@x, 32 bits)",
		},
		{
			// A narrower zero-extend leaves the sign bit clear, so the
			// sign-extend is the no-op, not the zero-extend.
			"narrower zero-extend wins",
			SignExtend(ZeroExtend(x, 8), 32),
			"zero-extend(@x, 8 bits)",
		},
		{
			"narrower sign-extend wins",
			SignExtend(SignExtend(x, 8), 32),
			"sign-extend(@x, 8 bits)",
		},
		{
			"equal-width sign-extend is idempotent",
			SignExtend(SignExtend(x, 32), 32),
			"sign-extend(@x, 32 bits)",
		},
		{
			"wider inner extend is narrowed",
			SignExtend(SignExtend(x, 32), 8),
			"sign-extend(@x, 8 bits)",
		},
		{
			"64 bits is the identity",
			SignExtend(x, 64),
			"@x",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got.DebugString())
		})
	}
}

func TestSignExtendFoldsImmediates(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  Expression
		want uint64
	}{
		{"positive stays", SignExtend(Imm(0x7f), 8), 0x7f},
		{"negative byte", SignExtend(Imm(0x80), 8), 0xffffffffffffff80},
		{"negative word", SignExtend(Imm(0xffffffff), 32), 0xffffffffffffffff},
		{"high bits ignored", SignExtend(Imm(0xff00), 8), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := AsConstant(tc.got)
			assert.True(t, ok, "want a folded immediate, got %s", tc.got.DebugString())
			assert.Equal(t, tc.want, v)
		})
	}
}
