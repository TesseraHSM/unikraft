/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2022, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <uk/config.h>
#include <uk/asm.h>
#include <uk/lcpu.h>

#include <x86/lxboot.h>

/**
 * Stack and entry function to use during CPU initialization
 */
.section .bss
.space 4096
lxboot_bootstack:

/**
 * 64-bit Linux Boot Protocol entry function
 *
 * RSI holds base address of struct lxboot_params. Flat 4GiB CS and DS segments,
 * with ES and SS set to DS. A20 gate enabled. Protected mode enabled, paging
 * enabled with ident mapping for loaded kernel, zero page (i.e., struct
 * lxboot_params) and command line buffer. Interrupts disabled.
 */
.code64
.section .text.64.boot
ENTRY(_lxboot_entry)

	testq	%rsi, %rsi
	jz	no_lxboot

	cmpl	$LXBOOT_HDR_HEADER_MAGIC, LXBOOT_HDR_HEADER_OFFSET(%rsi)
	je	lxboot_hdr_ok
	/* Hyper-V's Linux direct loader fills the boot parameters itself when
	 * it loads an ELF kernel and leaves the setup header zeroed, so accept
	 * an absent magic as well. Anything else is a wrong arrival.
	 */
	cmpl	$0, LXBOOT_HDR_HEADER_OFFSET(%rsi)
	jne	no_lxboot

lxboot_hdr_ok:

#if CONFIG_LIBUKRELOC
	/* We are going to taint the early lcpu_bootstack but we do not care.
	 * Since it's a stack, it does not need to not be tainted anyway.
	 */
	leaq	lxboot_bootstack(%rip), %rsp
	/* Make sure it is aligned */
	andq	$~0xf, %rsp
	pushq	%rsi
	subq	$0x8, %rsp
	xorl	%esi, %esi
	xorl	%edi, %edi
	call	do_uk_reloc
	addq	$0x8, %rsp
	popq	%rsi
	/* We do not restore the previous %rsp. At this time it does not seem to
	 * be needed.
	 */
#endif /* CONFIG_LIBUKRELOC */


	leaq	lxboot_bootstack(%rip), %rax
	movq	%rax, uk_plat_native_sstackp(%rip)

	leaq	lxboot_entry(%rip), %rax
	movq	%rax, uk_plat_native_sentry(%rip)

	movq	%rsi, uk_plat_native_sarg(%rip)


	/* The boot page table is built without the memory encryption (C-)bit.
	 * Under SEV-SNP with vTOM disabled the C-bit is what marks a mapping
	 * private, so switching to a table without it would make every fetch
	 * and access target private memory as shared, faulting immediately.
	 *
	 * The loader hands control over on its own page table, so the C-bit
	 * position can be recovered from the incoming %cr3 instead of from
	 * CPUID, which is itself an intercepted event this early. Only bits
	 * 47-51 are considered: the C-bit always lies in that window, and no
	 * page table pointer reaches it, so this is a no-op when memory
	 * encryption is not in use.
	 */
	movq	%cr3, %rcx
	movabsq	$0x000f800000000000, %rdx
	andq	%rdx, %rcx
	jz	.Lbpt_cbit_done

	leaq	x86_bpt_begin(%rip), %rax
	leaq	x86_bpt_end(%rip), %rdx
.Lbpt_cbit_next:
	testb	$1, (%rax)
	jz	.Lbpt_cbit_skip
	orq	%rcx, (%rax)
.Lbpt_cbit_skip:
	addq	$0x8, %rax
	cmpq	%rdx, %rax
	jb	.Lbpt_cbit_next
.Lbpt_cbit_done:

	leaq	x86_bpt_pml4(%rip), %rax
	orq	%rcx, %rax
	movq	%rax, %cr3


#if CONFIG_X86_SNP_EARLY_CON || CONFIG_X86_SNP_VC_EARLY
	/* Both of these need a stack. lcpu_start64 scales %rsp by the APIC id
	 * and so runs with it zero on the boot processor, which is why they
	 * are called here rather than left to later code.
	 */
	leaq	lxboot_bootstack(%rip), %rsp
	andq	$~0xf, %rsp
	pushq	%rsi
#endif

#if CONFIG_X86_SNP_EARLY_CON
	/* Brought up before the #VC handler so that a failure installing the
	 * handler has somewhere to report itself. Nothing here can raise an
	 * NAE event, so the ordering is safe.
	 */
	call	snp_dbg_init
	leaq	snp_dbg_banner(%rip), %rdi
	call	snp_dbg_puts
#endif

#if CONFIG_X86_SNP_VC_EARLY
	/* The values CPUID must answer with were recorded at launch and are
	 * covered by the measurement. Find them before the handler that serves
	 * them is installed; the boot parameters that name them are on the
	 * stack. Failing to find them is not fatal - the handler then falls
	 * back to asking the host - so nothing is checked here.
	 */
	movq	(%rsp), %rdi
	call	snp_vc_cpuid_page_init

	/* lcpu_start64 issues CPUID immediately, which on SEV-SNP is an NAE
	 * event rather than an instruction.
	 */
	call	snp_vc_early_init
#if CONFIG_X86_SNP_EARLY_CON
	leaq	snp_dbg_vc_ready(%rip), %rdi
	call	snp_dbg_puts
#endif
#endif

#if CONFIG_X86_SNP_EARLY_CON || CONFIG_X86_SNP_VC_EARLY
	popq	%rsi
#endif

	jmp	lcpu_start64

no_lxboot:
	cli
1:
	hlt
	jmp	1b
END(_lxboot_entry)

#if CONFIG_X86_SNP_EARLY_CON
.section .rodata
snp_dbg_banner:
	.asciz	"\nlxboot: page table adopted, early console up\n"
#if CONFIG_X86_SNP_VC_EARLY
snp_dbg_vc_ready:
	.asciz	"lxboot: #VC handler installed, entering lcpu_start64\n"
#endif
#endif
