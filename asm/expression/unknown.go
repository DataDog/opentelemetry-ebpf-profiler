// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expression // import "go.opentelemetry.io/ebpf-profiler/asm/expression"

var _ Expression = &unknown{}

var unknownValue = &unknown{}

// Unknown is a value the interpreter could not model. It matches nothing, so a
// consumer cannot mistake a stale destination for a computed result.
func Unknown() Expression {
	return unknownValue
}

type unknown struct{}

func (*unknown) Match(Expression) bool {
	return false
}

func (*unknown) DebugString() string {
	return "unknown"
}
