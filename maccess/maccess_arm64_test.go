//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package maccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:lll
var codeblobs = map[string]struct {
	code      []byte
	isPatched bool
}{
	"Debian - 6.1.0-13-arm64": {
		isPatched: true,
		code: []byte{
			0x1f, 0x20, 0x03, 0xd5, // nop
			0x1f, 0x20, 0x03, 0xd5, // nop
			0x3f, 0x23, 0x03, 0xd5, // paciasp
			0xfd, 0x7b, 0xbd, 0xa9, // stp	x29, x30, [sp, #-48]!
			0xfd, 0x03, 0x00, 0x91, // mov	x29, sp
			0xf3, 0x53, 0x01, 0xa9, // stp	x19, x20, [sp, #16]
			0xf4, 0x03, 0x01, 0xaa, // mov	x20, x1
			0x21, 0x00, 0xe0, 0xd2, // mov	x1, #0x1000000000000       	// #281474976710656
			0x5f, 0x00, 0x01, 0xeb, // cmp	x2, x1
			0xa8, 0x00, 0x00, 0x54, // b.hi	ffff8000082b1508 <copy_from_user_nofault+0x38>  // b.pmore
			0x21, 0x00, 0x02, 0xcb, // sub	x1, x1, x2
			0xf3, 0x03, 0x02, 0xaa, // mov	x19, x2
			0x9f, 0x02, 0x01, 0xeb, // cmp	x20, x1
			0xc9, 0x00, 0x00, 0x54, // b.ls	ffff8000082b151c <copy_from_user_nofault+0x4c>  // b.plast
			0xf3, 0x53, 0x41, 0xa9, // ldp	x19, x20, [sp, #16]
			0xa0, 0x01, 0x80, 0x92, // mov	x0, #0xfffffffffffffff2    	// #-14
		},
	},
	"Amazon Linux - 6.1.59-84.139.amzn2023.aarch64": {
		isPatched: true,
		code: []byte{
			0xe9, 0x03, 0x1e, 0xaa, // MOV X9, X30
			0x1f, 0x20, 0x03, 0xd5, // NOP
			0x3f, 0x23, 0x03, 0xd5, // HINT #0x19
			0xfd, 0x7b, 0xbd, 0xa9, // STP X29, X30, [SP,#-48]!
			0xfd, 0x03, 0x00, 0x91, // MOV X29, SP
			0xf3, 0x53, 0x01, 0xa9, // STP X19, X20, [SP,#16]
			0xf3, 0x03, 0x02, 0xaa, // MOV X19, X2
			0x22, 0x00, 0xe0, 0xd2, // MOV X2, #0x1000000000000
			0x7f, 0x02, 0x02, 0xeb, // CMP X19, X2
			0xa8, 0x00, 0x00, 0x54, // B HI, .+0x14
			0x42, 0x00, 0x13, 0xcb, // SUB X2, X2, X19
			0xf4, 0x03, 0x01, 0xaa, // MOV X20, X1
			0x3f, 0x00, 0x02, 0xeb, // CMP X1, X2
			0xc9, 0x00, 0x00, 0x54, // B LS, .+0x18
			0xa0, 0x01, 0x80, 0x92, // MOV X0, #0xfffffffffffffff2
			0xf3, 0x53, 0x41, 0xa9, // LDP X19, X20, [SP,#16]
		},
	},
	"Debian - 5.19.0": {
		// https://snapshot.debian.org/archive/debian/20230501T024743Z/pool/main/l/linux/linux-image-5.19.0-0.deb11.2-cloud-arm64-dbg_5.19.11-1~bpo11%2B1_arm64.deb
		isPatched: false,
		code: []byte{
			0x1f, 0x20, 0x03, 0xd5, // nop
			0x1f, 0x20, 0x03, 0xd5, // nop
			0x3f, 0x23, 0x03, 0xd5, // paciasp
			0xfd, 0x7b, 0xbd, 0xa9, // stp	x29, x30, [sp, #-48]!
			0x03, 0x41, 0x38, 0xd5, // mrs	x3, sp_el0
			0xfd, 0x03, 0x00, 0x91, // mov	x29, sp
			0xf3, 0x53, 0x01, 0xa9, // stp	x19, x20, [sp, #16]
			0xf3, 0x03, 0x01, 0xaa, // mov	x19, x1
			0xf4, 0x03, 0x02, 0xaa, // mov	x20, x2
			0xf5, 0x5b, 0x02, 0xa9, // stp	x21, x22, [sp, #32]
			0xf5, 0x03, 0x00, 0xaa, // mov	x21, x0
			0x64, 0x2c, 0x40, 0xb9, // ldr	w4, [x3, #44]
			0x44, 0x05, 0xa8, 0x37, // tbnz	w4, #21, ffff80000829eb98 <copy_from_user_nofault+0xd8>
			0x60, 0x00, 0x40, 0xf9, // ldr	x0, [x3]
			0x1f, 0x00, 0x06, 0x72, // tst	w0, #0x4000000
			0xe1, 0x04, 0x00, 0x54, // b.ne	ffff80000829eb98 <copy_from_user_nofault+0xd8>  // b.any
		},
	},
	"Linux 6.5.11 compiled with LLVM-17": {
		// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=v6.5.11&id=799441832db16b99e400ccbec55db801e6992819
		isPatched: true,
		code: []byte{
			0x5f, 0x24, 0x03, 0xd5, // bti c
			0x29, 0x00, 0xe0, 0xd2, // mov	x9, #0x1000000000000    // =281474976710656
			0xa8, 0x01, 0x80, 0x92, // mov	x8, #-0xe               // =-14
			0x5f, 0x00, 0x09, 0xeb, // cmp	x2, x9
			0xe8, 0x02, 0x00, 0x54, // b.hi	0x2227b8 <.text+0x2127b8>
			0x29, 0x01, 0x02, 0xcb, // sub	x9, x9, x2
			0x3f, 0x01, 0x01, 0xeb, // cmp	x9, x1
			0x83, 0x02, 0x00, 0x54, // b.lo	0x2227b8 <.text+0x2127b8>
			0x3f, 0x23, 0x03, 0xd5, // paciasp
			0xfd, 0x7b, 0xbe, 0xa9, // stp	x29, x30, [sp, #-0x20]!
			0xf3, 0x0b, 0x00, 0xf9, // str	x19, [sp, #0x10]
			0xfd, 0x03, 0x00, 0x91, // mov	x29, sp
			0x13, 0x41, 0x38, 0xd5, // mrs	x19, SP_EL0
			0x68, 0xae, 0x48, 0xb9, // ldr	w8, [x19, #0x8ac]
			0x08, 0x05, 0x00, 0x11, // add	w8, w8, #0x1
			0x68, 0xae, 0x08, 0xb9, // str	w8, [x19, #0x8ac]
		},
	},
}

func TestGetJumpInCopyFromUserNoFault(t *testing.T) {
	for name, test := range codeblobs {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			isPatched, err := CopyFromUserNoFaultIsPatched(test.code, 0, 0)
			if assert.NoError(t, err) {
				assert.Equal(t, test.isPatched, isPatched)
			}
		})
	}
}
