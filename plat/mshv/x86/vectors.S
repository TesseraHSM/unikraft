/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <uk/arch/x86_64.h>
#include <x86/traps.h>
#include <uk/asm/cfi.h>
#include <x86/cpu_vectors.h>
#include <uk/intctlr.h>
#include <uk/lcpu.h>

.altmacro

/* #HV, vector 28.
 *
 * Only emitted where the C handler exists and the gate is installed: both
 * uk_plat_native_except_hv_handler() and the idt_fillgate() call for vector 28
 * live behind CONFIG_HAVE_MSHV_SYNIC in plat/native. Emitting the entry
 * point unconditionally left every build without the synthetic interrupt
 * controller with a call to a handler that was never compiled.
 *
 * Modelled on IRQ_ENTRY rather than TRAP_ENTRY: it pushes no error code, and
 * what it means is "an interrupt is waiting on the doorbell page", not a
 * fault to be reported. RI enters on a dedicated IST landing stack and moves
 * dispatch to an owned work stack before acknowledging the doorbell. Deferred
 * entries stay on the landing stack without acknowledging another signal.
 */
.macro HV_ENTRY
ENTRY(cpu_trap_hv_injection)
	.cfi_startproc simple
	.cfi_signal_frame
	.cfi_def_cfa rsp, 8
	.cfi_offset rip, -8
	.cfi_offset cs, 0

#ifdef __clang__
	.cfi_offset flags, 8
#elif __GNUC__
	.cfi_offset rflags, 8
#else
#error "Unsupported Compiler"
#endif

	.cfi_offset rsp, 16
	.cfi_offset ss, 24
	cld

	pushq_cfi $0                        /* no error code */
	PUSH_CALLER_SAVE
	/* we have some padding */
	subq $UK_LCPU_X86_64_REGS_OFFSETOF_R15, %rsp
	.cfi_adjust_cfa_offset UK_LCPU_X86_64_REGS_OFFSETOF_R15

	movq %rsp, %rdi
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	call uk_plat_native_hv_stack_enter
	movq %rax, %rsp
	movq %rsp, %rdi
#endif
	call uk_plat_native_except_hv_handler

	/* we have some padding */
	addq $UK_LCPU_X86_64_REGS_OFFSETOF_R15, %rsp
	.cfi_adjust_cfa_offset -UK_LCPU_X86_64_REGS_OFFSETOF_R15
	POP_CALLER_SAVE
	addq $8, %rsp
	.cfi_adjust_cfa_offset -8

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	jmp uk_plat_native_hv_thunk_redo
#else
	iretq
#endif
	.cfi_endproc
.endm

HV_ENTRY

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
/* Both callers have restored all registers and left only the IRET frame.
 * A nested #HV restarts the check while scratch is above RSP, or re-pushes
 * the restored RAX at IRET. No popped stack slot is replayed.
 */
.set hv_thunk_push_bytes, 0
.macro HV_THUNK_PUSH reg
	pushq_reg_cfi \reg
	.set hv_thunk_push_bytes, hv_thunk_push_bytes + 8
.endm

ENTRY(uk_plat_native_hv_thunk_redo)
	.cfi_startproc simple
	.cfi_signal_frame
	.cfi_def_cfa rsp, 8
	.cfi_offset rip, -8
	cli
	HV_THUNK_PUSH rax
.globl uk_plat_native_hv_thunk_chk
uk_plat_native_hv_thunk_chk:
	/* A nested #HV may rewind a return after ownership was released. */
	leaq 8(%rsp), %rax
	cmpq uk_plat_native_hv_work_frame(%rip), %rax
	jne .Lhv_thunk_check_pending
	movl $1, uk_plat_native_hv_work_active(%rip)
.Lhv_thunk_check_pending:
	movq mshv_hv_pending_word(%rip), %rax
	testq %rax, %rax
	jz .Lhv_thunk_finish
	testl $0x200, 24(%rsp)
	jz .Lhv_thunk_finish
	cmpw $0, (%rax)
	jne .Lhv_thunk_more
.Lhv_thunk_finish:
	leaq 8(%rsp), %rax
	cmpq uk_plat_native_hv_work_frame(%rip), %rax
	jne uk_plat_native_hv_thunk_pop
	movl $0, uk_plat_native_hv_work_active(%rip)
	.cfi_remember_state
.globl uk_plat_native_hv_thunk_pop
uk_plat_native_hv_thunk_pop:
	popq_reg_cfi rax
.globl uk_plat_native_hv_thunk_iret
uk_plat_native_hv_thunk_iret:
	iretq
.Lhv_thunk_more:
	.cfi_restore_state
	HV_THUNK_PUSH rcx
	HV_THUNK_PUSH rdx
	HV_THUNK_PUSH rsi
	HV_THUNK_PUSH rdi
	HV_THUNK_PUSH r8
	HV_THUNK_PUSH r9
	HV_THUNK_PUSH r10
	HV_THUNK_PUSH r11
	.if ((5 * 8 + hv_thunk_push_bytes) % 16) != 0
	.error "Unaligned restricted-injection drain call"
	.endif
	cld
	call uk_plat_native_hv_tail_drain
	cli
	testl %eax, %eax
	popq_reg_cfi r11
	popq_reg_cfi r10
	popq_reg_cfi r9
	popq_reg_cfi r8
	popq_reg_cfi rdi
	popq_reg_cfi rsi
	popq_reg_cfi rdx
	popq_reg_cfi rcx
	jnz uk_plat_native_hv_thunk_chk
	jmp .Lhv_thunk_finish
	.cfi_endproc
.purgem HV_THUNK_PUSH
#endif
.noaltmacro
