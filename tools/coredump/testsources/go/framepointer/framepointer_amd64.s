// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "textflag.h"

// Attribute the function to a Go source file so the Go pclntab extractor uses
// the frame-pointer recipe for its full range. The instructions remain hand
// written so each capture offset denotes a stable machine state:
//
//   +0:  before PUSHQ BP
//   +1:  after PUSHQ BP, before MOVQ SP, BP
//   +8:  complete frame, at a second MOVQ SP, BP
//   +20: complete frame, before POPQ BP
//   +21: after POPQ BP, before RET
#line 1 "framepointer.go"
TEXT ·framepointerTarget(SB), NOSPLIT, $0-0
	PUSHQ BP
	MOVQ SP, BP
	SUBQ $8, SP
	MOVQ SP, BP
	LEAQ 8(SP), BP
	ADDQ $8, SP
	POPQ BP
	RET

TEXT ·use(SB), NOSPLIT|NOFRAME, $0-8
	RET
