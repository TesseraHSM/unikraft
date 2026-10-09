/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * An early console for a SEV-SNP guest running in VTL0 with no paravisor.
 *
 * A paravisor guest can report a failure through the VTL2 error page, but that
 * mechanism is not the guest's: the page is only ever collected because the
 * host watches for a VTL2 triple fault. With no VTL2 there is nothing on the
 * other side to read it, so a VTL0 guest that dies early is silent, and the
 * only signal left is whether the machine faulted or kept running. That is a
 * single bit per boot.
 *
 * This provides the missing channel by driving COM1 the way any SNP guest must
 * drive a device: port access is an NAE event, so the access is described in a
 * GHCB and handed to the host with VMGEXIT. Establishing the GHCB is the whole
 * of the work, and it needs no console of its own - the page state change and
 * the registration both travel in the GHCB MSR, which is not intercepted.
 *
 * Nothing here calls into the rest of the kernel. The console has to work when
 * nothing else does, including before the boot page table switch has been
 * proven and inside the #VC handler, so it depends on no allocator, no
 * initialised state and no other subsystem.
 *
 * Written against the AMD GHCB specification (publication 56421); the GHCB
 * layout and the MSR request encodings below are that architectural interface.
 */

#include <uk/config.h>
#include <uk/asm.h>
#include <x86/snp.h>

#define MSR_AMD64_GHCB			0xc0010130

#define GHCB_MSR_PSC_REQ		0x014
#define GHCB_MSR_PSC_RESP		0x015
#define GHCB_MSR_REG_GPA_REQ		0x012
#define GHCB_MSR_REG_GPA_RESP		0x013
#define GHCB_MSR_SEV_INFO_REQ		0x002
#define GHCB_MSR_SEV_INFO_RESP		0x001
#define GHCB_MSR_INFO_MASK		0xfff

/* Highest GHCB protocol version this code knows how to speak. The host
 * reports the range it accepts, and a request carrying a version outside it
 * is refused, so the version used is negotiated rather than assumed.
 */
#define GHCB_PROTOCOL_MAX		2

#define SNP_PAGE_STATE_SHARED		2

#define SVM_EXIT_IOIO			0x7b
#define SVM_EXIT_MSR			0x7c
#define SVM_EXIT_VMMCALL		0x81

/* The GHCB must be shared with the host, so it cannot live in the image: the
 * image is mapped with 2 MiB pages and clearing the C-bit for one page would
 * mean splitting one. The first 2 MiB is already mapped with 4 KiB pages and
 * holds nothing of ours, so a page is taken from there instead.
 */
#define GHCB_GPA			SNP_GHCB_GPA
#define GHCB_PTE_OFFSET			((GHCB_GPA >> 12) * 8)

/* The C-bit is never below bit 47, and no page table pointer reaches that far,
 * so masking %cr3 with this window recovers it without asking CPUID.
 */
#define CBIT_WINDOW			0x000f800000000000

/* GHCB field offsets. The valid bitmap covers the save area at one bit per
 * 8-byte slot, so a field's bit index is its offset divided by 8.
 *
 * The last three fields sit at the very end of the page: the shared buffer
 * runs to 0xff0, ten reserved bytes follow, and the version and usage close
 * out the 4 KiB.
 */
#define GHCB_RAX			0x1f8
#define GHCB_RCX			0x308
#define GHCB_RDX			0x310
#define GHCB_R8				0x340
#define GHCB_CPL			0x0cb
#define GHCB_SW_EXITCODE		0x390
#define GHCB_SW_EXITINFO1		0x398
#define GHCB_SW_EXITINFO2		0x3a0
#define GHCB_VALID_BITMAP		0x3f0
#define GHCB_VERSION			0xffa
#define GHCB_USAGE			0xffc

#define GHCB_VALID_RAX_BYTE		(GHCB_VALID_BITMAP + (GHCB_RAX / 8 / 8))
#define GHCB_VALID_RAX_BIT		(1 << ((GHCB_RAX / 8) % 8))
/* %rcx and %rdx are adjacent slots and so share a bitmap byte. */
#define GHCB_VALID_RCXDX_BYTE		(GHCB_VALID_BITMAP + (GHCB_RCX / 8 / 8))
#define GHCB_VALID_RCXDX_BITS		((1 << ((GHCB_RCX / 8) % 8)) | \
					 (1 << ((GHCB_RDX / 8) % 8)))
/* SW_EXITCODE, SW_EXITINFO1 and SW_EXITINFO2 are consecutive slots and share
 * a bitmap byte.
 */
#define GHCB_VALID_EXIT_BYTE		\
	(GHCB_VALID_BITMAP + (GHCB_SW_EXITCODE / 8 / 8))
#define GHCB_VALID_EXIT_BITS		0x1c

#define GHCB_VALID_R8_BYTE		(GHCB_VALID_BITMAP + (GHCB_R8 / 8 / 8))
#define GHCB_VALID_R8_BIT		(1 << ((GHCB_R8 / 8) % 8))
#define GHCB_VALID_CPL_BYTE		(GHCB_VALID_BITMAP + (GHCB_CPL / 8 / 8))
#define GHCB_VALID_CPL_BIT		(1 << ((GHCB_CPL / 8) % 8))

#define COM1_THR			0x3f8
#define COM1_IER			0x3f9
#define COM1_LCR			0x3fb

/* IOIO exit information: an 8-bit write to a port. */
#define IOIO_OUT_BYTE(port)		(((port) << 16) | (1 << 4))

.section .data
.align 8
/* Set only once the GHCB is usable. Every entry point checks it, so a host
 * that refuses any step leaves the console silent rather than faulting.
 */
.global snp_dbg_ready
snp_dbg_ready:
	.byte	0

.align 2
/* Negotiated at init from the range the host reports. */
.global snp_dbg_version
snp_dbg_version:
	.word	0

.code64
.section .text.64.boot

/**
 * Hand one port write to the host through the GHCB.
 *
 *   %esi  port
 *   %dil  value
 *
 * Preserves all registers. Assumes the GHCB is established.
 */
snp_dbg_outb:
	pushq	%rax
	pushq	%rcx
	pushq	%rdx
	pushq	%rbx

	movq	$GHCB_GPA, %rbx

	/* The host reads only the fields the valid bitmap points at, and a
	 * stale bit would offer it a field this request never filled in.
	 */
	movq	$0, GHCB_VALID_BITMAP(%rbx)
	movq	$0, GHCB_VALID_BITMAP + 8(%rbx)

	movzbl	%dil, %eax
	movq	%rax, GHCB_RAX(%rbx)

	movl	%esi, %eax
	shll	$16, %eax
	orl	$(1 << 4), %eax		/* 8-bit, direction out */
	movq	$SVM_EXIT_IOIO, GHCB_SW_EXITCODE(%rbx)
	movq	%rax, GHCB_SW_EXITINFO1(%rbx)
	movq	$0, GHCB_SW_EXITINFO2(%rbx)

	orb	$GHCB_VALID_RAX_BIT, GHCB_VALID_RAX_BYTE(%rbx)
	orb	$GHCB_VALID_EXIT_BITS, GHCB_VALID_EXIT_BYTE(%rbx)

	movw	snp_dbg_version(%rip), %ax
	movw	%ax, GHCB_VERSION(%rbx)
	movl	$0, GHCB_USAGE(%rbx)

	/* A GHCB exchange is selected by putting the page's address in the
	 * MSR, as opposed to one of the short request encodings.
	 */
	movl	$MSR_AMD64_GHCB, %ecx
	movl	$GHCB_GPA, %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall			/* VMGEXIT */

	popq	%rbx
	popq	%rdx
	popq	%rcx
	popq	%rax
	ret

/**
 * Hand one port access to the host through the GHCB.
 *
 *   %edi  IOIO exit information: direction, width and port
 *   %esi  value to write, for a write
 *
 * Returns the value read in %eax, and 1 or 0 in %edx according to whether the
 * host completed the request. Preserves every other register.
 *
 * This is the general form of the write above, and serves the #VC handler.
 * Port I/O is how a guest reaches a UART or a timer, so a guest that cannot
 * emulate it has no console and no clock; but it is also entirely host
 * observable, so nothing secret may travel this way.
 */
ENTRY(snp_ghcb_ioio)
	pushq	%rbx
	pushq	%rcx

	xorl	%eax, %eax
	xorl	%edx, %edx
	cmpb	$0, snp_dbg_ready(%rip)
	je	2f

	movq	$GHCB_GPA, %rbx

	movq	$0, GHCB_VALID_BITMAP(%rbx)
	movq	$0, GHCB_VALID_BITMAP + 8(%rbx)

	movl	%esi, %eax
	movq	%rax, GHCB_RAX(%rbx)
	movq	$SVM_EXIT_IOIO, GHCB_SW_EXITCODE(%rbx)
	movl	%edi, %eax
	movq	%rax, GHCB_SW_EXITINFO1(%rbx)
	movq	$0, GHCB_SW_EXITINFO2(%rbx)

	orb	$GHCB_VALID_RAX_BIT, GHCB_VALID_RAX_BYTE(%rbx)
	orb	$GHCB_VALID_EXIT_BITS, GHCB_VALID_EXIT_BYTE(%rbx)

	movw	snp_dbg_version(%rip), %ax
	movw	%ax, GHCB_VERSION(%rbx)
	movl	$0, GHCB_USAGE(%rbx)

	movl	$MSR_AMD64_GHCB, %ecx
	movl	$GHCB_GPA, %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall			/* VMGEXIT */

	xorl	%eax, %eax
	xorl	%edx, %edx
	/* A non-zero SW_EXITINFO1 coming back is the host declining the
	 * request, in which case the RAX slot holds nothing meaningful.
	 */
	cmpq	$0, GHCB_SW_EXITINFO1(%rbx)
	jne	2f
	movl	GHCB_RAX(%rbx), %eax
	movl	$1, %edx
2:
	popq	%rcx
	popq	%rbx
	ret
END(snp_ghcb_ioio)

/**
 * Hand one MSR access to the host through the GHCB.
 *
 *   %edi  0 to read, 1 to write
 *   %esi  MSR index
 *   %rdx  value to write, as a single 64-bit quantity
 *
 * Returns the value read in %rax, and 1 or 0 in %edx according to whether the
 * host completed the request. Preserves every other register.
 *
 * The host answers these, so nothing an MSR returns can be trusted to be the
 * hardware's own view. That is tolerable for the MSRs a guest uses to arrange
 * its own execution, and is why the attestation report is fetched over a
 * measured, integrity-protected path instead.
 */
ENTRY(snp_ghcb_msr)
	pushq	%rbx
	pushq	%rcx
	pushq	%rsi
	pushq	%r8

	movq	%rdx, %r8		/* value to write */
	xorl	%eax, %eax
	xorl	%edx, %edx
	cmpb	$0, snp_dbg_ready(%rip)
	je	2f

	movq	$GHCB_GPA, %rbx

	movq	$0, GHCB_VALID_BITMAP(%rbx)
	movq	$0, GHCB_VALID_BITMAP + 8(%rbx)

	movl	%esi, %eax
	movq	%rax, GHCB_RCX(%rbx)	/* the index goes where RDMSR expects */
	movq	%r8, %rax
	movl	%eax, %eax
	movq	%rax, GHCB_RAX(%rbx)	/* low half */
	movq	%r8, %rax
	shrq	$32, %rax
	movq	%rax, GHCB_RDX(%rbx)	/* high half */

	movq	$SVM_EXIT_MSR, GHCB_SW_EXITCODE(%rbx)
	movl	%edi, %eax
	movq	%rax, GHCB_SW_EXITINFO1(%rbx)	/* 0 reads, 1 writes */
	movq	$0, GHCB_SW_EXITINFO2(%rbx)

	orb	$GHCB_VALID_RAX_BIT, GHCB_VALID_RAX_BYTE(%rbx)
	orb	$GHCB_VALID_RCXDX_BITS, GHCB_VALID_RCXDX_BYTE(%rbx)
	orb	$GHCB_VALID_EXIT_BITS, GHCB_VALID_EXIT_BYTE(%rbx)

	movw	snp_dbg_version(%rip), %ax
	movw	%ax, GHCB_VERSION(%rbx)
	movl	$0, GHCB_USAGE(%rbx)

	movl	$MSR_AMD64_GHCB, %ecx
	movl	$GHCB_GPA, %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall			/* VMGEXIT */

	xorl	%eax, %eax
	xorl	%edx, %edx
	cmpq	$0, GHCB_SW_EXITINFO1(%rbx)
	jne	2f
	movl	GHCB_RDX(%rbx), %eax
	shlq	$32, %rax
	movl	GHCB_RAX(%rbx), %ecx
	orq	%rcx, %rax
	movl	$1, %edx
2:
	popq	%r8
	popq	%rsi
	popq	%rcx
	popq	%rbx
	ret
END(snp_ghcb_msr)

/**
 * Hand one VMMCALL to the host through the GHCB.
 *
 *   %rdi  address of four consecutive quadwords holding, in order, the guest
 *         %rax, %rcx, %rdx and %r8. Overwritten with what the host returns.
 *
 * Returns 1 or 0 in %edx according to whether the host completed the request.
 *
 * VMMCALL is the instruction a hypercall is made of, and on an encrypted
 * partition it does not reach the hypervisor by itself: it leaves the guest as
 * a #VC and has to be re-presented here, with the registers the callee reads
 * copied into the GHCB where the host can see them. Which registers those are
 * is a property of the hypercall interface rather than of VMMCALL, so the
 * GHCB specification requires only %rax and CPL, and the four named above are
 * what the Microsoft hypervisor's calling convention adds: the control word in
 * %rcx, the input and output addresses in %rdx and %r8, the status in %rax.
 */
ENTRY(snp_ghcb_vmmcall)
	pushq	%rbx
	pushq	%rcx
	pushq	%rdi
	pushq	%r8

	xorl	%edx, %edx
	cmpb	$0, snp_dbg_ready(%rip)
	je	2f

	movq	$GHCB_GPA, %rbx

	movq	$0, GHCB_VALID_BITMAP(%rbx)
	movq	$0, GHCB_VALID_BITMAP + 8(%rbx)

	movq	0(%rdi), %rax
	movq	%rax, GHCB_RAX(%rbx)
	movq	8(%rdi), %rax
	movq	%rax, GHCB_RCX(%rbx)
	movq	16(%rdi), %rax
	movq	%rax, GHCB_RDX(%rbx)
	movq	24(%rdi), %rax
	movq	%rax, GHCB_R8(%rbx)

	/* The guest runs nothing but supervisor code, so this is a constant
	 * rather than something read back out of the interrupted frame.
	 */
	movb	$0, GHCB_CPL(%rbx)

	movq	$SVM_EXIT_VMMCALL, GHCB_SW_EXITCODE(%rbx)
	movq	$0, GHCB_SW_EXITINFO1(%rbx)
	movq	$0, GHCB_SW_EXITINFO2(%rbx)

	orb	$GHCB_VALID_RAX_BIT, GHCB_VALID_RAX_BYTE(%rbx)
	orb	$GHCB_VALID_RCXDX_BITS, GHCB_VALID_RCXDX_BYTE(%rbx)
	orb	$GHCB_VALID_R8_BIT, GHCB_VALID_R8_BYTE(%rbx)
	orb	$GHCB_VALID_CPL_BIT, GHCB_VALID_CPL_BYTE(%rbx)
	orb	$GHCB_VALID_EXIT_BITS, GHCB_VALID_EXIT_BYTE(%rbx)

	movw	snp_dbg_version(%rip), %ax
	movw	%ax, GHCB_VERSION(%rbx)
	movl	$0, GHCB_USAGE(%rbx)

	movl	$MSR_AMD64_GHCB, %ecx
	movl	$GHCB_GPA, %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall			/* VMGEXIT */

	xorl	%edx, %edx
	cmpq	$0, GHCB_SW_EXITINFO1(%rbx)
	jne	2f

	movq	GHCB_RAX(%rbx), %rax
	movq	%rax, 0(%rdi)
	movq	GHCB_RCX(%rbx), %rax
	movq	%rax, 8(%rdi)
	movq	GHCB_RDX(%rbx), %rax
	movq	%rax, 16(%rdi)
	movq	GHCB_R8(%rbx), %rax
	movq	%rax, 24(%rdi)
	movl	$1, %edx
2:
	popq	%r8
	popq	%rdi
	popq	%rcx
	popq	%rbx
	ret
END(snp_ghcb_vmmcall)

/**
 * Establish the GHCB and bring up COM1.
 *
 * Safe to call before the #VC handler exists: no step here can raise an NAE
 * event, because writes to the GHCB MSR are not intercepted and VMGEXIT is an
 * explicit instruction rather than a trap.
 *
 * Preserves all registers.
 */
ENTRY(snp_dbg_init)
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	pushq	%rsi
	pushq	%rdi

	/* Ask which GHCB protocol versions the host accepts. A request that
	 * declares a version outside that range is refused, and the refusal is
	 * silent, so the version is negotiated before anything depends on it.
	 *
	 * The same response also reports the C-bit position, but the boot page
	 * table already had to be corrected before reaching here, so that value
	 * is not needed a second time.
	 */
	movl	$MSR_AMD64_GHCB, %ecx
	movl	$GHCB_MSR_SEV_INFO_REQ, %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall
	movl	$MSR_AMD64_GHCB, %ecx
	rdmsr
	andl	$GHCB_MSR_INFO_MASK, %eax
	cmpl	$GHCB_MSR_SEV_INFO_RESP, %eax
	jne	.Ldbg_out

	movl	%edx, %eax
	shrl	$16, %eax		/* highest version the host accepts */
	cmpl	$GHCB_PROTOCOL_MAX, %eax
	jbe	3f
	movl	$GHCB_PROTOCOL_MAX, %eax
3:
	andl	$0xffff, %edx		/* lowest version the host accepts */
	cmpl	%edx, %eax
	jb	.Ldbg_out		/* no version in common */
	movw	%ax, snp_dbg_version(%rip)

	/* Withdraw the guest's claim on the page before offering it to the
	 * host. Doing it the other way round would leave the guest validated
	 * against memory the host has already been given.
	 *
	 * A refusal that only says the page was already in this state is not a
	 * failure; anything else means the page cannot be shared, and the
	 * console stays silent rather than risking a fault on first use.
	 */
	movq	$GHCB_GPA, %rax
	xorl	%ecx, %ecx		/* 4 KiB */
	xorl	%edx, %edx		/* withdraw validation */
	pvalidate
	jc	1f			/* already unvalidated */
	testl	%eax, %eax
	jnz	.Ldbg_out
1:

	/* Ask the host to move the page across the encryption boundary. */
	movl	$MSR_AMD64_GHCB, %ecx
	movl	$(GHCB_GPA | GHCB_MSR_PSC_REQ), %eax
	movl	$(SNP_PAGE_STATE_SHARED << (52 - 32)), %edx
	wrmsr
	rep; vmmcall
	movl	$MSR_AMD64_GHCB, %ecx
	rdmsr
	andl	$GHCB_MSR_INFO_MASK, %eax
	cmpl	$GHCB_MSR_PSC_RESP, %eax
	jne	.Ldbg_out
	testl	%edx, %edx		/* non-zero is the host declining */
	jnz	.Ldbg_out

	/* The page is the host's now, so the guest must stop treating it as
	 * private. Every entry was given the C-bit when the boot page table
	 * was adopted; this one has to lose it again.
	 */
	movq	%cr3, %rcx
	movabsq	$CBIT_WINDOW, %rax
	andq	%rax, %rcx
	notq	%rcx
	leaq	x86_bpt_pt0_0_0(%rip), %rbx
	andq	%rcx, GHCB_PTE_OFFSET(%rbx)
	movq	$GHCB_GPA, %rax
	invlpg	(%rax)

	/* Only now is the page safe to touch. */
	movq	$GHCB_GPA, %rdi
	xorl	%eax, %eax
	movl	$512, %ecx
2:
	movq	%rax, (%rdi)
	addq	$8, %rdi
	decl	%ecx
	jnz	2b

	/* An SNP guest must tell the host which page it will present, so that
	 * a later exchange cannot be redirected at a different one.
	 */
	movl	$MSR_AMD64_GHCB, %ecx
	movl	$(GHCB_GPA | GHCB_MSR_REG_GPA_REQ), %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall
	movl	$MSR_AMD64_GHCB, %ecx
	rdmsr
	movl	%eax, %ebx
	andl	$GHCB_MSR_INFO_MASK, %ebx
	cmpl	$GHCB_MSR_REG_GPA_RESP, %ebx
	jne	.Ldbg_out
	/* The host echoes the page it accepted; anything else is a refusal. */
	andl	$~GHCB_MSR_INFO_MASK, %eax
	cmpl	$GHCB_GPA, %eax
	jne	.Ldbg_out
	testl	%edx, %edx
	jnz	.Ldbg_out

	movb	$1, snp_dbg_ready(%rip)

	/* Clear DLAB so that writes reach the transmit register rather than
	 * the divisor, and silence interrupts we have no handler for.
	 */
	movl	$COM1_LCR, %esi
	movl	$0x03, %edi		/* 8 bits, no parity, one stop */
	call	snp_dbg_outb
	movl	$COM1_IER, %esi
	xorl	%edi, %edi
	call	snp_dbg_outb

.Ldbg_out:
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%rbx
	popq	%rax
	ret
END(snp_dbg_init)

/**
 * Write one character, expanding a newline to a carriage return pair so that
 * the output is readable on a terminal that does not do it for us.
 *
 *   %dil  character
 *
 * Preserves all registers.
 */
ENTRY(snp_dbg_putc)
	cmpb	$0, snp_dbg_ready(%rip)
	je	1f
	pushq	%rsi
	pushq	%rdi
	cmpb	$'\n', %dil
	jne	2f
	movl	$COM1_THR, %esi
	movl	$'\r', %edi
	call	snp_dbg_outb
	movl	$'\n', %edi
2:
	movl	$COM1_THR, %esi
	call	snp_dbg_outb
	popq	%rdi
	popq	%rsi
1:
	ret
END(snp_dbg_putc)

/**
 * Write a NUL-terminated string.
 *
 *   %rdi  string
 *
 * Preserves all registers.
 */
ENTRY(snp_dbg_puts)
	cmpb	$0, snp_dbg_ready(%rip)
	je	2f
	pushq	%rdi
	pushq	%rsi
	movq	%rdi, %rsi
1:
	movzbl	(%rsi), %edi
	testb	%dil, %dil
	jz	3f
	call	snp_dbg_putc
	incq	%rsi
	jmp	1b
3:
	popq	%rsi
	popq	%rdi
2:
	ret
END(snp_dbg_puts)

/**
 * Write a 64-bit value as sixteen hex digits.
 *
 *   %rdi  value
 *
 * Preserves all registers.
 */
ENTRY(snp_dbg_hex64)
	cmpb	$0, snp_dbg_ready(%rip)
	je	3f
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdi

	movq	%rdi, %rbx
	movl	$16, %ecx
1:
	rolq	$4, %rbx
	movl	%ebx, %eax
	andl	$0xf, %eax
	cmpl	$10, %eax
	jb	2f
	addl	$('a' - '0' - 10), %eax
2:
	addl	$'0', %eax
	movl	%eax, %edi
	call	snp_dbg_putc
	decl	%ecx
	jnz	1b

	popq	%rdi
	popq	%rcx
	popq	%rbx
	popq	%rax
3:
	ret
END(snp_dbg_hex64)
