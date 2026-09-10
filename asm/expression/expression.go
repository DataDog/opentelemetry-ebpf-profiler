// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression // import "go.opentelemetry.io/ebpf-profiler/asm/expression"

import (
	"cmp"
	"slices"
	"strings"
)

// Expression is an interface representing a 64-bit size value. It can be immediate
type Expression interface {
	// Match compares this Expression value against a pattern Expression.
	// The order of the arguments matters: a.Match(b) or b.Match(a) may
	// produce different results. The intended order The pattern should be passed as
	// an argument, not the other way around.
	// It returns true if the values are considered equal or compatible according to
	// the type-specific rules:
	// - For operations (add, mul): checks if operation types and operands match
	// - For immediate: checks if values are equal and extracts value into a ImmediateCapture
	// - For mem references: checks if segments and addresses match
	// - For extend operations: checks if sizes and inner values match
	// - For named: checks if they are pointing to the same object instance.
	// - For ImmediateCapture: matches nothing - see immediate
	Match(pattern Expression) bool
	DebugString() string
}

type operands []Expression

// Match pairs operands positionally. Both sides are canonically ordered by
// newOp, the only place an operands slice is built, so re-sorting here would
// be a no-op.
func (os *operands) Match(other operands) bool {
	if len(*os) != len(other) {
		return false
	}
	for i, o := range *os {
		if !o.Match(other[i]) {
			return false
		}
	}
	return true
}

func cmpOrder(u Expression) int {
	switch u.(type) {
	case *mem:
		return 1
	case *op:
		return 2
	case *named:
		return 3
	case *ImmediateCapture:
		return 4
	case *immediate:
		return 5
	case *clear:
		return 6
	case *extend:
		return 7
	case *unknown:
		return 8
	default:
		return 0
	}
}

// compare is a total order over expressions, used to pair the operands of a
// commutative op. The tie-break within a kind has to be structural: DebugString
// is a rendering, free to change and finer than the Match it canonicalizes.
// Operands that compare equal are still paired positionally, as Match is not an
// equivalence relation (immediate vs capture is asymmetric).
func compare(a, b Expression) int {
	if c := cmp.Compare(cmpOrder(a), cmpOrder(b)); c != 0 {
		return c
	}
	// Equal cmpOrder ranks mean a and b are the same concrete type, so these
	// assertions cannot fail. Unranked types fall through the switch.
	switch x := a.(type) {
	case *mem:
		y := b.(*mem)
		if c := cmp.Compare(x.segment, y.segment); c != 0 {
			return c
		}
		// sizeBytes is deliberately not compared: mem.Match ignores it, and an
		// order finer than Match would sort matching siblings apart.
		return compare(x.at, y.at)
	case *op:
		y := b.(*op)
		if c := cmp.Compare(x.typ, y.typ); c != 0 {
			return c
		}
		return slices.CompareFunc(x.operands, y.operands, compare)
	case *named:
		return strings.Compare(x.name, b.(*named).name)
	case *ImmediateCapture:
		return strings.Compare(x.name, b.(*ImmediateCapture).name)
	case *immediate:
		return cmp.Compare(x.Value, b.(*immediate).Value)
	case *clear:
		y := b.(*clear)
		if c := cmp.Compare(x.bits, y.bits); c != 0 {
			return c
		}
		return compare(x.v, y.v)
	case *extend:
		y := b.(*extend)
		if c := cmp.Compare(x.bits, y.bits); c != 0 {
			return c
		}
		if x.sign != y.sign {
			if x.sign {
				return 1
			}
			return -1
		}
		return compare(x.v, y.v)
	}
	return 0
}

// AsConstant checks whether the value of the expression is statically known,
// and if so, returns it.
//
// Currently, we don't attempt to do any simplification that hasn't
// already been done while constructing expressions, so this is just
// shorthand for the common pattern of checking for an immediate at
// the top level:
//
//	cap := expression.NewImmediateCapture("cap")
//
//	if v.Match(cap) {
//	  return cap.CapturedValue(), true
//	}
//
//	 return 0, false;
func AsConstant(v Expression) (uint64, bool) {
	switch typed := v.(type) {
	case *immediate:
		return typed.Value, true
	default:
		return 0, false
	}
}

// AsNamed checks whether `v` is a named value, returning its name if so.
func AsNamed(v Expression) (string, bool) {
	switch typed := v.(type) {
	case *named:
		return typed.name, true
	default:
		return "", false
	}
}
