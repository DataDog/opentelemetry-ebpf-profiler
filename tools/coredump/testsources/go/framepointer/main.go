// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

package main

func framepointerTarget()

//go:noescape
func use(*[256]byte)

//go:noinline
func caller() {
	framepointerTarget()
}

//go:noinline
func largeCaller() {
	var buf [256]byte
	use(&buf)
	framepointerTarget()
}

func main() {
	caller()
	largeCaller()
}
