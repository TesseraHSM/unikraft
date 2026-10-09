/* SPDX-License-Identifier: ISC */
/*
 * Authors: Dan Williams
 *          Martin Lucina
 *          Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2015-2017 IBM
 * Copyright (c) 2016-2017 Docker, Inc.
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Taken from solo5 */

#ifndef __UK_PLAT_COMMON_X86_CPU_VECTORS_H__
#define __UK_PLAT_COMMON_X86_CPU_VECTORS_H__

#include <uk/asm/cfi.h>

#define ENTRY(X)     .global X ; .type X, @function ; X:

.macro PUSH_CALLER_SAVE
	pushq_reg_cfi rdi
	pushq_reg_cfi rsi
	pushq_reg_cfi rdx
	pushq_reg_cfi rcx
	pushq_reg_cfi rax
	pushq_reg_cfi r8
	pushq_reg_cfi r9
	pushq_reg_cfi r10
	pushq_reg_cfi r11
	pushq_reg_cfi rbx
	pushq_reg_cfi rbp
	pushq_reg_cfi r12
	pushq_reg_cfi r13
	pushq_reg_cfi r14
	pushq_reg_cfi r15
.endm

.macro POP_CALLER_SAVE
	popq_reg_cfi r15
	popq_reg_cfi r14
	popq_reg_cfi r13
	popq_reg_cfi r12
	popq_reg_cfi rbp
	popq_reg_cfi rbx
	popq_reg_cfi r11
	popq_reg_cfi r10
	popq_reg_cfi r9
	popq_reg_cfi r8
	popq_reg_cfi rax
	popq_reg_cfi rcx
	popq_reg_cfi rdx
	popq_reg_cfi rsi
	popq_reg_cfi rdi
.endm

#endif /* __UK_PLAT_COMMON_X86_CPU_VECTORS_H__ */
