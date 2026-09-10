// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression // import "go.opentelemetry.io/ebpf-profiler/asm/expression"
import "fmt"

var _ Expression = &extend{}

func SignExtend32(v Expression) Expression {
	return SignExtend(v, 32)
}

func SignExtend8(v Expression) Expression {
	return SignExtend(v, 8)
}

func SignExtend(v Expression, bits int) Expression {
	return extendTo(v, bits, true)
}

func ZeroExtend32(v Expression) Expression {
	return ZeroExtend(v, 32)
}

func ZeroExtend8(v Expression) Expression {
	return ZeroExtend(v, 8)
}

func ZeroExtend(v Expression, bits int) Expression {
	return extendTo(v, bits, false)
}

// extendTo keeps the low bits of v and fills the rest from the sign bit or
// with zeroes. Allocates only when the result cannot be folded: every write to
// a 64-bit register goes through here.
func extendTo(v Expression, bits int, sign bool) Expression {
	if bits >= 64 {
		return v
	}
	if bits == 0 {
		return Imm(0)
	}
	switch typed := v.(type) {
	case *immediate:
		if sign {
			shift := 64 - bits
			return Imm(uint64(int64(typed.Value<<shift) >> shift))
		}
		return Imm(typed.Value & (1<<bits - 1))
	case *extend:
		if sign {
			// Only the low bits survive, so an inner extend narrower than this
			// one already determines the result. A zero-extend of exactly bits
			// does not: its top bit is data here, but was padding there.
			if typed.bits < bits || (typed.sign && typed.bits == bits) {
				return typed
			}
			return &extend{typed.v, bits, true}
		}
		if !typed.sign {
			if typed.bits <= bits {
				return typed
			}
			return &extend{typed.v, bits, false}
		}
		// A sign-extend under a zero-extend keeps both: the inner sign bits
		// are data the outer one must preserve.
	}
	return &extend{v, bits, sign}
}

type extend struct {
	v    Expression
	bits int
	sign bool
}

func (c *extend) Match(pattern Expression) bool {
	switch typedPattern := pattern.(type) {
	case *extend:
		return typedPattern.bits == c.bits &&
			typedPattern.sign == c.sign &&
			c.v.Match(typedPattern.v)
	default:
		return false
	}
}

func (c *extend) DebugString() string {
	s := "zero"
	if c.sign {
		s = "sign"
	}
	return fmt.Sprintf("%s-extend(%s, %d bits)", s, c.v.DebugString(), c.bits)
}
