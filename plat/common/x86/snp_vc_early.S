/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Minimal #VC handling for a SEV-SNP guest that boots straight into VTL0 with
 * no paravisor. Nothing else services NAE events for us, so the first CPUID in
 * lcpu_start64 would otherwise be fatal.
 *
 * Only CPUID is emulated. The values come from the CPUID page the launch
 * process left behind, which the boot parameters name through the
 * confidential-computing blob. That page is the right answer rather than
 * merely a convenient one: its contents are covered by the launch
 * measurement, so a host cannot alter what this guest believes about the
 * machine it is running on. A guest whose purpose is attestation must not
 * take its own description from the party it is attesting against.
 *
 * A leaf the page does not describe falls back to the GHCB MSR protocol. That
 * protocol is the one host channel usable this early: writes to the GHCB MSR
 * are not intercepted and VMGEXIT is an explicit instruction, so no GHCB page,
 * no allocator and no shared memory are required. Answers obtained that way
 * are the host's word alone, so the checks further down still apply to them.
 *
 * lcpu_start64 loads %rsp with the APIC id scaled by the lcpu size before its
 * second CPUID, which is 0 on the boot processor. An exception taken there
 * would push onto a non-canonical address, so the handler must run on an
 * interrupt stack. That is why this installs a GDT and TSS rather than only an
 * IDT.
 *
 * Written against the AMD GHCB specification (publication 56421); the request
 * and response encodings below are that architectural interface.
 */

#include <uk/config.h>
#include <uk/arch/limits.h>
#include <uk/asm.h>

#define MSR_AMD64_GHCB		0xc0010130
#define GHCB_MSR_CPUID_REQ	0x004
#define GHCB_MSR_CPUID_RESP	0x005

/* Termination request. The reason set and reason code sit above it; set zero
 * for both, which is the generic "the guest asked to stop" the host reports.
 */
#define GHCB_MSR_TERM_REQ	0x100
#define SVM_EXIT_CPUID		0x72
#define SVM_EXIT_IOIO		0x7b
#define SVM_EXIT_MSR		0x7c
#define SVM_EXIT_VMMCALL	0x81
#define SVM_EXIT_NPF		0x400

/* IOIO exit information, as the host expects to read it back. */
#define IOIO_TYPE_IN		(1 << 0)
#define IOIO_SZ8		(1 << 4)
#define IOIO_SZ16		(1 << 5)
#define IOIO_SZ32		(1 << 6)

#define SNP_VC_IST_SIZE		4096
#define SNP_VC_VECTORS		32
#define SNP_VC_VECTOR		29
#define TSS_IST1_OFFSET		0x24
#define TSS_LIMIT		103

/* The boot parameters, the chain they head, and the blob that chain names.
 * Offsets are the Linux boot protocol's, which the loader writes and
 * lxboot.h mirrors.
 */
#define BP_SETUP_DATA		0x250
#define SETUP_DATA_NEXT		0
#define SETUP_DATA_TYPE		8
#define SETUP_DATA_LEN		12
#define SETUP_DATA_CC_BLOB	7
#define CC_SETUP_BLOB_ADDR	16
#define CC_BLOB_MAGIC		0x45444d41
#define CC_BLOB_CPUID_PHYS	24
#define CC_BLOB_CPUID_LEN	32

/* The CPUID page: a count, then fixed-size entries pairing the inputs of a
 * leaf with the outputs the launch process recorded for it.
 */
#define CPUID_PAGE_COUNT	0
#define CPUID_PAGE_ENTRIES	16
#define CPUID_PAGE_COUNT_MAX	64
#define CPUID_LEAF_STRIDE	48
#define CPUID_LEAF_EAX_IN	0
#define CPUID_LEAF_ECX_IN	4
#define CPUID_LEAF_XFEM_IN	8
#define CPUID_LEAF_XSS_IN	16
#define CPUID_LEAF_EAX_OUT	24
#define CPUID_LEAF_EBX_OUT	28
#define CPUID_LEAF_ECX_OUT	32
#define CPUID_LEAF_EDX_OUT	36

/* CPUID.1:ECX. Masked so that nothing in the boot path enables XSAVE state:
 * the size and layout of that state comes from CPUID leaf 0xD, which is
 * XCR0-dependent and so must never be taken from the hypervisor. Refusing the
 * feature outright is coherent, whereas advertising it and then refusing the
 * leaf that describes it is not. XSETBV itself is not an NAE event, so this is
 * not about avoiding a second exit.
 */
#define CPUID_1_ECX_XSAVE	(1 << 26)
#define CPUID_1_ECX_AVX		(1 << 28)
/* CPUID.7:EBX bit 16, AVX512F, reaches XSETBV by the same route. */
#define CPUID_7_EBX_AVX512F	(1 << 16)

.section .data
.align 16
snp_vc_gdt:
	.quad	0x0000000000000000	/* 0x00 null */
	.quad	0x00af9b000000ffff	/* 0x08 64-bit code */
	.quad	0x00cf93000000ffff	/* 0x10 data */
snp_vc_gdt_tss:
	.quad	0			/* 0x18 TSS, completed at runtime */
	.quad	0
snp_vc_gdt_end:

.align 8
snp_vc_gdtptr:
	.word	snp_vc_gdt_end - snp_vc_gdt - 1
	.quad	0			/* base, filled at runtime */

.align 8
snp_vc_idtptr:
	.word	SNP_VC_VECTORS * 16 - 1
	.quad	0			/* base, filled at runtime */

.section .bss
.align 16
snp_vc_idt:
	.space	SNP_VC_VECTORS * 16
snp_vc_tss:
	.space	TSS_LIMIT + 1
.align 16
snp_vc_ist:
	.space	SNP_VC_IST_SIZE
snp_vc_ist_top:

.code64
.section .text.64.boot

/**
 * Install the GDT, TSS and IDT needed to survive an NAE event.
 *
 * Preserves every register the caller may still need, %rsi in particular,
 * which carries the boot parameters.
 */
ENTRY(snp_vc_early_init)
	pushq	%rax
	pushq	%rbx
	pushq	%rcx

	leaq	snp_vc_gdt(%rip), %rax
	leaq	snp_vc_gdtptr(%rip), %rbx
	movq	%rax, 2(%rbx)

	/* Build the 16-byte 64-bit TSS descriptor around the TSS. */
	leaq	snp_vc_tss(%rip), %rax
	leaq	snp_vc_gdt_tss(%rip), %rbx
	movw	$TSS_LIMIT, 0(%rbx)
	movw	%ax, 2(%rbx)
	shrq	$16, %rax
	movb	%al, 4(%rbx)
	movb	$0x89, 5(%rbx)		/* present, available 64-bit TSS */
	movb	$0x00, 6(%rbx)
	shrq	$8, %rax
	movb	%al, 7(%rbx)
	shrq	$8, %rax
	movl	%eax, 8(%rbx)
	movl	$0, 12(%rbx)

	leaq	snp_vc_ist_top(%rip), %rax
	leaq	snp_vc_tss(%rip), %rbx
	movq	%rax, TSS_IST1_OFFSET(%rbx)

	lgdt	snp_vc_gdtptr(%rip)

	/* Reload %cs so the descriptor just installed is the one in use. */
	pushq	$0x08
	leaq	1f(%rip), %rax
	pushq	%rax
	lretq
1:
	movl	$0x10, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss

	movw	$0x18, %ax
	ltr	%ax

	/* Point every vector at the spin stub first. Without this, any
	 * exception other than #VC would find an absent gate and escalate to a
	 * triple fault, which is indistinguishable from never having arrived.
	 * A hung guest, by contrast, is a fact.
	 */
	leaq	snp_vc_idt(%rip), %rbx
	movl	$SNP_VC_VECTORS, %ecx
2:
	leaq	snp_vc_spin(%rip), %rax
	movw	%ax, 0(%rbx)
	movw	$0x08, 2(%rbx)
	movb	$0x00, 4(%rbx)
	movb	$0x8e, 5(%rbx)		/* present, DPL 0, interrupt gate */
	shrq	$16, %rax
	movw	%ax, 6(%rbx)
	shrq	$16, %rax
	movl	%eax, 8(%rbx)
	movl	$0, 12(%rbx)
	addq	$16, %rbx
	decl	%ecx
	jnz	2b

	/* Vector 29 (#VC), taken on IST 1. */
	leaq	snp_vc_handler(%rip), %rax
	leaq	snp_vc_idt(%rip), %rbx
	addq	$(SNP_VC_VECTOR * 16), %rbx
	movw	%ax, 0(%rbx)
	movw	$0x08, 2(%rbx)
	movb	$0x01, 4(%rbx)		/* IST 1 */
	movb	$0x8e, 5(%rbx)
	shrq	$16, %rax
	movw	%ax, 6(%rbx)
	shrq	$16, %rax
	movl	%eax, 8(%rbx)
	movl	$0, 12(%rbx)

	leaq	snp_vc_idt(%rip), %rax
	leaq	snp_vc_idtptr(%rip), %rbx
	movq	%rax, 2(%rbx)
	lidt	snp_vc_idtptr(%rip)

	popq	%rcx
	popq	%rbx
	popq	%rax
	ret
END(snp_vc_early_init)

/**
 * Fetch one CPUID output register from the host.
 *
 *   %r8d  CPUID leaf
 *   %edi  register index, 0=eax 1=ebx 2=ecx 3=edx
 *
 * Returns the value in %eax. Clobbers %eax, %ecx, %edx.
 *
 * The MSR protocol carries no subleaf, so the host answers for subleaf 0,
 * which is what the early boot path asks for.
 */
snp_vc_cpuid_one:
	movl	%r8d, %edx		/* GHCBData[63:32] = leaf */
	movl	%edi, %eax
	shll	$30, %eax		/* GHCBData[31:30] = register */
	orl	$GHCB_MSR_CPUID_REQ, %eax
	movl	$MSR_AMD64_GHCB, %ecx
	wrmsr
	rep; vmmcall			/* VMGEXIT */
	movl	$MSR_AMD64_GHCB, %ecx
	rdmsr
	/* A response that is not the matching CPUID reply means the host did
	 * not honour the protocol, and its data cannot be used.
	 */
	andl	$0xfff, %eax
	cmpl	$GHCB_MSR_CPUID_RESP, %eax
	jne	1f
	movl	%edx, %eax		/* value is GHCBData[63:32] */
	ret
1:
	/* The host did not answer in the form the protocol requires. For a
	 * paravirtual discovery leaf that is itself an answer - a hypervisor
	 * that will not name itself is one this guest cannot use - so it
	 * reports zero and lets the caller conclude there is none. Refusing to
	 * answer must not be able to wedge the guest, which is the one outcome
	 * a host can always arrange.
	 *
	 * Every other leaf is architectural. An architectural leaf that cannot
	 * be answered is a broken platform rather than a negative answer, and
	 * inventing a value for it would be worse than stopping.
	 */
	movl	%r8d, %eax
	andl	$0xf0000000, %eax
	cmpl	$0x40000000, %eax
	jne	snp_vc_spin
	xorl	%eax, %eax
	ret

/**
 * Find the CPUID page the launch process left, and remember it.
 *
 *   %rdi  the boot parameters
 *
 * The chain walked here is host-supplied, so it is walked defensively: a
 * corrupt or circular list, a blob that does not identify itself, or a page
 * with an impossible entry count all end the search rather than the guest.
 * Finding nothing is survivable - the handler then asks the host - so there
 * is no reason to fault on a malformed chain.
 */
ENTRY(snp_vc_cpuid_page_init)
	pushq	%rax
	pushq	%rcx
	pushq	%rdx
	pushq	%rsi

	testq	%rdi, %rdi
	jz	9f

	movq	BP_SETUP_DATA(%rdi), %rsi
	movl	$64, %ecx		/* hop limit */
1:
	testq	%rsi, %rsi
	jz	9f
	cmpl	$SETUP_DATA_CC_BLOB, SETUP_DATA_TYPE(%rsi)
	je	2f
	movq	SETUP_DATA_NEXT(%rsi), %rsi
	decl	%ecx
	jnz	1b
	jmp	9f
2:
	cmpl	$4, SETUP_DATA_LEN(%rsi)
	jb	9f
	movl	CC_SETUP_BLOB_ADDR(%rsi), %eax
	testq	%rax, %rax
	jz	9f
	cmpl	$CC_BLOB_MAGIC, (%rax)
	jne	9f
	cmpl	$__PAGE_SIZE, CC_BLOB_CPUID_LEN(%rax)
	jb	9f

	movq	CC_BLOB_CPUID_PHYS(%rax), %rdx
	testq	%rdx, %rdx
	jz	9f
	movl	CPUID_PAGE_COUNT(%rdx), %eax
	testl	%eax, %eax
	jz	9f
	cmpl	$CPUID_PAGE_COUNT_MAX, %eax
	ja	9f

	movq	%rdx, snp_vc_cpuid_page(%rip)
9:
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%rax
	ret
END(snp_vc_cpuid_page_init)

/**
 * Look a leaf up in the CPUID page.
 *
 *   %r8d  leaf
 *   %r9d  subleaf
 *
 * Returns the entry in %rax, or zero if the page does not describe it.
 * Clobbers %rax, %rcx, %rdx.
 *
 * An entry recorded for extended state the guest does not run with does not
 * describe this guest, so the recorded XCR0 and XSS must both be zero to be
 * usable here. Nothing in the boot path enables either.
 */
snp_vc_cpuid_lookup:
	movq	snp_vc_cpuid_page(%rip), %rdx
	testq	%rdx, %rdx
	jz	9f
	movl	CPUID_PAGE_COUNT(%rdx), %ecx
	leaq	CPUID_PAGE_ENTRIES(%rdx), %rax
1:
	testl	%ecx, %ecx
	jz	9f
	cmpl	%r8d, CPUID_LEAF_EAX_IN(%rax)
	jne	2f
	cmpl	%r9d, CPUID_LEAF_ECX_IN(%rax)
	jne	2f
	cmpq	$0, CPUID_LEAF_XFEM_IN(%rax)
	jne	2f
	cmpq	$0, CPUID_LEAF_XSS_IN(%rax)
	jne	2f
	ret
2:
	addq	$CPUID_LEAF_STRIDE, %rax
	decl	%ecx
	jmp	1b
9:
	xorl	%eax, %eax
	ret

.globl snp_vc_handler
snp_vc_handler:
	pushq	%rbp
	movq	%rsp, %rbp		/* 8(%rbp) exit code, 16(%rbp) %rip */
	pushq	%rax			/*  -8(%rbp) guest %rax */
	pushq	%rbx			/* -16(%rbp) guest %rbx */
	pushq	%rcx			/* -24(%rbp) guest %rcx */
	pushq	%rdx			/* -32(%rbp) guest %rdx */
	pushq	%rsi
	pushq	%rdi
	pushq	%r8
	pushq	%r9

	cmpq	$SVM_EXIT_CPUID, 8(%rbp)
	je	snp_vc_do_cpuid
	cmpq	$SVM_EXIT_IOIO, 8(%rbp)
	je	snp_vc_do_ioio
	cmpq	$SVM_EXIT_MSR, 8(%rbp)
	je	snp_vc_do_msr
	cmpq	$SVM_EXIT_VMMCALL, 8(%rbp)
	je	snp_vc_do_vmmcall

#if CONFIG_X86_SNP_MMIO_MAPPED
	cmpq	$SVM_EXIT_NPF, 8(%rbp)
	je	snp_vc_do_npf
#endif

	/* Everything else is declined on purpose, and the nested page fault
	 * that carries MMIO is the one worth naming. Emulating it would mean
	 * decoding an arbitrary memory operand and moving guest data through
	 * a shared buffer, and this guest has no device it reaches that way:
	 * the console is port I/O and everything else is VMBus. An MMIO exit
	 * here therefore means a stray access to unbacked memory, which is a
	 * bug to be reported rather than a request to be served.
	 *
	 * A guest configured with mapped device MMIO does have such a device,
	 * and serves the fault above - but only for a range whose owner has
	 * registered it. Everything else still arrives here.
	 */
	jmp	snp_vc_spin

snp_vc_do_cpuid:
	/* Only a two-byte CPUID is emulated, and the RIP advance below assumes
	 * exactly that, so confirm the opcode rather than trusting the exit
	 * code alone.
	 */
	movq	16(%rbp), %rax
	cmpw	$0xa20f, (%rax)
	jne	snp_vc_spin

	movq	-8(%rbp), %r8		/* guest %rax holds the leaf */
	movq	-24(%rbp), %r9		/* guest %rcx holds the subleaf */

#if CONFIG_X86_SNP_EARLY_CON
	leaq	snp_vc_cpuid_msg(%rip), %rdi
	call	snp_dbg_puts
	movq	%r8, %rdi
	call	snp_dbg_hex64
#endif

	/* The recorded page answers first. A leaf that takes no subleaf is
	 * reached with whatever %rcx happened to hold, so a miss is retried
	 * against subleaf zero before giving up on the page.
	 */
	call	snp_vc_cpuid_lookup
	testq	%rax, %rax
	jnz	5f
	testl	%r9d, %r9d
	jz	6f
	xorl	%r9d, %r9d
	call	snp_vc_cpuid_lookup
	testq	%rax, %rax
	jz	6f
5:
#if CONFIG_X86_SNP_EARLY_CON
	leaq	snp_vc_from_page(%rip), %rdi
	call	snp_dbg_puts
#endif
	movl	CPUID_LEAF_EAX_OUT(%rax), %ecx
	movq	%rcx, -8(%rbp)
	movl	CPUID_LEAF_EBX_OUT(%rax), %ecx
	movq	%rcx, -16(%rbp)
	movl	CPUID_LEAF_ECX_OUT(%rax), %ecx
	cmpl	$1, %r8d
	jne	7f
	/* The recorded page describes the processor, not the partition, so it
	 * does not report that a hypervisor is present. It always is: a guest
	 * that reaches this handler is virtualised by definition. Without the
	 * bit, code that keys off it declines to look for the hypervisor's
	 * interface at all and falls back to legacy hardware the partition
	 * does not have.
	 */
	orl	$(1 << 31), %ecx
7:
	movq	%rcx, -24(%rbp)
	movl	CPUID_LEAF_EDX_OUT(%rax), %ecx
	movq	%rcx, -32(%rbp)
	jmp	7f
6:
#if CONFIG_X86_SNP_EARLY_CON
	leaq	snp_vc_from_host(%rip), %rdi
	call	snp_dbg_puts
#endif
	xorl	%edi, %edi
	call	snp_vc_cpuid_one
	movq	%rax, -8(%rbp)
	movl	$1, %edi
	call	snp_vc_cpuid_one
	movq	%rax, -16(%rbp)
	movl	$2, %edi
	call	snp_vc_cpuid_one
	movq	%rax, -24(%rbp)
	movl	$3, %edi
	call	snp_vc_cpuid_one
	movq	%rax, -32(%rbp)
7:

	cmpl	$1, %r8d
	jne	1f
	movq	-24(%rbp), %rax
	andl	$~(CPUID_1_ECX_XSAVE | CPUID_1_ECX_AVX), %eax
	movq	%rax, -24(%rbp)
	/* Force the initial APIC id to 0. This guest is single processor, and
	 * lcpu_start64 scales %rsp by that id.
	 */
	movq	-16(%rbp), %rax
	andl	$0x00ffffff, %eax
	movq	%rax, -16(%rbp)
	jmp	3f
1:
	cmpl	$7, %r8d
	jne	2f
	movq	-16(%rbp), %rax
	andl	$~CPUID_7_EBX_AVX512F, %eax
	movq	%rax, -16(%rbp)
	jmp	3f
2:
	/* A host that denies SEV-SNP is either not the platform this guest was
	 * measured for or is trying to talk it out of its own protections.
	 */
	cmpl	$0x8000001f, %r8d
	jne	3f
	movq	-8(%rbp), %rax
	testl	$0x2, %eax
	jz	snp_vc_spin
3:
	addq	$2, 16(%rbp)		/* step over the two-byte CPUID */
	jmp	snp_vc_ret

/* Emulate one port access.
 *
 * Unlike CPUID, a #VC for I/O arrives without the host being told what was
 * asked: the exit code says only that a port was touched. The port, the
 * width and the direction all live in the instruction itself, so the guest
 * has to read its own opcode back and describe the access to the host. Only
 * the eight non-string forms are emulated; the repeated string forms move a
 * buffer at a time and nothing in this guest uses them.
 */
snp_vc_do_ioio:
	movq	16(%rbp), %rsi		/* faulting %rip */
	xorl	%ecx, %ecx		/* bytes of prefix seen */
	xorl	%r8d, %r8d		/* set once 0x66 narrows the operand */
1:
	/* No instruction is longer than fifteen bytes, so a walk that gets
	 * that far is not looking at one.
	 */
	cmpl	$15, %ecx
	jae	snp_vc_spin
	movzbl	(%rsi,%rcx,1), %eax

	cmpb	$0x66, %al		/* operand size override */
	jne	2f
	movl	$1, %r8d
	incl	%ecx
	jmp	1b
2:
	cmpb	$0x67, %al		/* address size override */
	je	3f
	cmpb	$0x2e, %al		/* segment overrides, all ignorable */
	je	3f
	cmpb	$0x36, %al
	je	3f
	cmpb	$0x3e, %al
	je	3f
	cmpb	$0x26, %al
	je	3f
	cmpb	$0x64, %al
	je	3f
	cmpb	$0x65, %al
	je	3f
	movl	%eax, %edx
	andl	$0xf0, %edx
	cmpl	$0x40, %edx		/* REX; no effect on an I/O width */
	jne	4f
3:
	incl	%ecx
	jmp	1b
4:
	/* The eight forms are 0xE4..0xE7 and 0xEC..0xEF, which are exactly
	 * the bytes left when the three bits that select immediate/DX, width
	 * and direction are masked away.
	 */
	movl	%eax, %r9d		/* opcode */
	andl	$0xf4, %eax
	cmpl	$0xe4, %eax
	jne	snp_vc_spin

	/* An even opcode is the byte-wide form; an odd one is as wide as the
	 * operand size makes it.
	 */
	xorl	%edi, %edi
	testb	$1, %r9b
	jnz	5f
	orl	$IOIO_SZ8, %edi
	jmp	7f
5:
	testl	%r8d, %r8d
	jz	6f
	orl	$IOIO_SZ16, %edi
	jmp	7f
6:
	orl	$IOIO_SZ32, %edi
7:
	/* Bit 3 of the opcode chooses where the port comes from. */
	testb	$8, %r9b
	jnz	8f
	movzbl	1(%rsi,%rcx,1), %eax	/* immediate port follows the opcode */
	addl	$2, %ecx
	jmp	9f
8:
	movzwl	-32(%rbp), %eax		/* guest %rdx supplies the port */
	incl	%ecx
9:
	shll	$16, %eax
	orl	%eax, %edi

	/* Bit 1 of the opcode chooses the direction. */
	movl	%ecx, %r8d		/* instruction length */
	testb	$2, %r9b
	jnz	10f
	orl	$IOIO_TYPE_IN, %edi
	xorl	%esi, %esi
	jmp	11f
10:
	movl	-8(%rbp), %esi		/* guest %rax supplies the value */
11:
	call	snp_ghcb_ioio
	testl	%edx, %edx
	jz	snp_vc_spin

	/* A write leaves the guest's registers alone. A read updates as much
	 * of %rax as its width covers, which for the narrow forms means
	 * leaving the rest of the register standing.
	 */
	testb	$2, %r9b
	jnz	15f
	testl	$IOIO_SZ8, %edi
	jz	12f
	movq	-8(%rbp), %rdx
	movb	%al, %dl
	movq	%rdx, -8(%rbp)
	jmp	15f
12:
	testl	$IOIO_SZ16, %edi
	jz	14f
	movq	-8(%rbp), %rdx
	movw	%ax, %dx
	movq	%rdx, -8(%rbp)
	jmp	15f
14:
	movl	%eax, %eax		/* a 32-bit read zero extends */
	movq	%rax, -8(%rbp)
15:
	movl	%r8d, %ecx
	addq	%rcx, 16(%rbp)
	jmp	snp_vc_ret
/* Emulate one MSR access.
 *
 * Both forms are two bytes and take their operands in fixed registers, so
 * unlike I/O there is nothing to decode beyond telling the two opcodes apart.
 */
snp_vc_do_msr:
	movq	16(%rbp), %rsi		/* faulting %rip */
	xorl	%ecx, %ecx
snp_vc_msr_pfx:
	cmpl	$15, %ecx
	jae	snp_vc_spin
	movzbl	(%rsi,%rcx,1), %eax
	cmpb	$0x0f, %al
	je	snp_vc_msr_op
	/* Only the prefixes that may legally precede these opcodes are
	 * stepped over; anything else means this is not the instruction the
	 * exit code claims it is.
	 */
	movl	%eax, %edx
	andl	$0xf0, %edx
	cmpl	$0x40, %edx
	je	snp_vc_msr_skip
	cmpb	$0x66, %al
	je	snp_vc_msr_skip
	cmpb	$0x67, %al
	je	snp_vc_msr_skip
	jmp	snp_vc_spin
snp_vc_msr_skip:
	incl	%ecx
	jmp	snp_vc_msr_pfx
snp_vc_msr_op:
	movzbl	1(%rsi,%rcx,1), %eax
	addl	$2, %ecx		/* instruction length */
	movl	%ecx, %r8d

	movl	-24(%rbp), %esi		/* guest %rcx holds the MSR index */

	/* Linux answers a declined MSR access by injecting #GP, because a
	 * Linux guest probes registers it can do without. Nothing this early
	 * probes: every register reached from here is one the guest cannot
	 * continue without, and there is no handler installed yet that could
	 * take the fault. A refusal is therefore terminal, and is reported as
	 * one rather than turned into an exception nobody would catch.
	 */
	cmpb	$0x32, %al		/* RDMSR */
	je	snp_vc_msr_rd
	cmpb	$0x30, %al		/* WRMSR */
	jne	snp_vc_spin

	movl	-32(%rbp), %edx		/* guest %edx:%eax holds the value */
	shlq	$32, %rdx
	movl	-8(%rbp), %eax
	orq	%rax, %rdx
	movl	$1, %edi
	call	snp_ghcb_msr
	testl	%edx, %edx
	jz	snp_vc_spin
	jmp	snp_vc_msr_done
snp_vc_msr_rd:
	xorl	%edi, %edi
	xorl	%edx, %edx
	call	snp_ghcb_msr
	testl	%edx, %edx
	jz	snp_vc_spin

	/* RDMSR clears the top half of both registers rather than leaving it
	 * standing, so the full 64-bit slots are rewritten.
	 */
	movq	%rax, %rdx
	shrq	$32, %rdx
	movq	%rdx, -32(%rbp)
	movl	%eax, %eax
	movq	%rax, -8(%rbp)
snp_vc_msr_done:
	movl	%r8d, %ecx
	addq	%rcx, 16(%rbp)
	jmp	snp_vc_ret

/* Forward a hypercall to the hypervisor.
 *
 * A hypercall is a VMMCALL, and on an encrypted partition VMMCALL leaves the
 * guest as a #VC instead of reaching the hypervisor, so the instruction has to
 * be re-presented through the GHCB with its argument registers copied where
 * the host can read them. This is the whole reason a partition without a
 * paravisor can dispense with the hypercall page: the page exists so that the
 * hypervisor can choose the instruction, and here there is only one choice and
 * the guest can make it itself.
 */
snp_vc_do_vmmcall:
	/* VMMCALL is three bytes and takes no prefixes, and the RIP advance
	 * below assumes exactly that, so confirm the opcode rather than
	 * trusting the exit code alone.
	 */
	movq	16(%rbp), %rsi
	cmpb	$0x0f, (%rsi)
	jne	snp_vc_spin
	cmpb	$0x01, 1(%rsi)
	jne	snp_vc_spin
	cmpb	$0xd9, 2(%rsi)
	jne	snp_vc_spin

	/* %rax, %rcx, %rdx and %r8, in the order the helper reads them. */
	subq	$32, %rsp
	movq	-8(%rbp), %rax
	movq	%rax, 0(%rsp)
	movq	-24(%rbp), %rax
	movq	%rax, 8(%rsp)
	movq	-32(%rbp), %rax
	movq	%rax, 16(%rsp)
	movq	-56(%rbp), %rax
	movq	%rax, 24(%rsp)

	movq	%rsp, %rdi
	call	snp_ghcb_vmmcall
	testl	%edx, %edx
	jz	snp_vc_spin

	movq	0(%rsp), %rax
	movq	%rax, -8(%rbp)
	movq	8(%rsp), %rax
	movq	%rax, -24(%rbp)
	movq	16(%rsp), %rax
	movq	%rax, -32(%rbp)
	movq	24(%rsp), %rax
	movq	%rax, -56(%rbp)
	addq	$32, %rsp

	addq	$3, 16(%rbp)

#if CONFIG_X86_SNP_MMIO_MAPPED
	jmp	snp_vc_ret

/* Serve one access to a mapped device register.
 *
 * A nested page fault is the only exit whose operands are not named by the
 * exit code at all: what was read or written, how wide it was and where it
 * was going are all in the instruction, so the instruction has to be read
 * back and taken apart. That is too much to do here, so it is done in C, and
 * this establishes what C needs: every general register in one array, in the
 * order the instruction encoding numbers them, so that a ModRM field indexes
 * it directly.
 *
 * The handler runs on the interrupted stack rather than an IST entry, so the
 * alignment the ABI requires is whatever the interrupted code happened to
 * leave, and is established here rather than assumed. Nothing below writes
 * the stack pointer back: the decoder refuses to name it as a destination,
 * and the frame this returns through owns it.
 */
snp_vc_do_npf:
	pushq	%r10			/* -72(%rbp) */
	pushq	%r11			/* -80(%rbp) */
	pushq	%r12			/* -88(%rbp) */
	pushq	%r13			/* -96(%rbp) */
	pushq	%r14			/* -104(%rbp) */
	pushq	%r15			/* -112(%rbp) */

	subq	$128, %rsp
	movq	-8(%rbp), %rax
	movq	%rax, 0(%rsp)		/* 0 rax */
	movq	-24(%rbp), %rax
	movq	%rax, 8(%rsp)		/* 1 rcx */
	movq	-32(%rbp), %rax
	movq	%rax, 16(%rsp)		/* 2 rdx */
	movq	-16(%rbp), %rax
	movq	%rax, 24(%rsp)		/* 3 rbx */
	movq	40(%rbp), %rax		/* the interrupted stack pointer, which
					 * the processor pushes for every
					 * interrupt in long mode */
	movq	%rax, 32(%rsp)		/* 4 rsp */
	movq	0(%rbp), %rax
	movq	%rax, 40(%rsp)		/* 5 rbp */
	movq	-40(%rbp), %rax
	movq	%rax, 48(%rsp)		/* 6 rsi */
	movq	-48(%rbp), %rax
	movq	%rax, 56(%rsp)		/* 7 rdi */
	movq	-56(%rbp), %rax
	movq	%rax, 64(%rsp)		/* 8 r8 */
	movq	-64(%rbp), %rax
	movq	%rax, 72(%rsp)		/* 9 r9 */
	movq	-72(%rbp), %rax
	movq	%rax, 80(%rsp)		/* 10 r10 */
	movq	-80(%rbp), %rax
	movq	%rax, 88(%rsp)		/* 11 r11 */
	movq	-88(%rbp), %rax
	movq	%rax, 96(%rsp)		/* 12 r12 */
	movq	-96(%rbp), %rax
	movq	%rax, 104(%rsp)		/* 13 r13 */
	movq	-104(%rbp), %rax
	movq	%rax, 112(%rsp)		/* 14 r14 */
	movq	-112(%rbp), %rax
	movq	%rax, 120(%rsp)		/* 15 r15 */

	movq	%rsp, %rdi		/* the registers */
	movq	%rsp, %rbx		/* survives the call in a saved reg */
	leaq	16(%rbp), %rsi		/* the instruction pointer to advance */
	andq	$-16, %rsp
	call	snp_vc_mmio_emulate
	movq	%rbx, %rsp

	/* A refusal is terminal. The decoder has recorded which access it was
	 * and why, because this handler cannot use a console that is itself
	 * port I/O, and the guest stops the way every unserviceable exit here
	 * always has.
	 */
	testl	%eax, %eax
	jz	snp_vc_spin

	movq	0(%rsp), %rax
	movq	%rax, -8(%rbp)
	movq	8(%rsp), %rax
	movq	%rax, -24(%rbp)
	movq	16(%rsp), %rax
	movq	%rax, -32(%rbp)
	movq	24(%rsp), %rax
	movq	%rax, -16(%rbp)
	movq	40(%rsp), %rax
	movq	%rax, 0(%rbp)
	movq	48(%rsp), %rax
	movq	%rax, -40(%rbp)
	movq	56(%rsp), %rax
	movq	%rax, -48(%rbp)
	movq	64(%rsp), %rax
	movq	%rax, -56(%rbp)
	movq	72(%rsp), %rax
	movq	%rax, -64(%rbp)
	movq	80(%rsp), %rax
	movq	%rax, -72(%rbp)
	movq	88(%rsp), %rax
	movq	%rax, -80(%rbp)
	movq	96(%rsp), %rax
	movq	%rax, -88(%rbp)
	movq	104(%rsp), %rax
	movq	%rax, -96(%rbp)
	movq	112(%rsp), %rax
	movq	%rax, -104(%rbp)
	movq	120(%rsp), %rax
	movq	%rax, -112(%rbp)
	addq	$128, %rsp

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%r11
	popq	%r10
#endif /* CONFIG_X86_SNP_MMIO_MAPPED */

snp_vc_ret:
	popq	%r9
	popq	%r8
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%rbx
	popq	%rax
	popq	%rbp
	addq	$8, %rsp		/* discard the exit code */
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	jmp	uk_plat_native_hv_thunk_redo
#else
	iretq
#endif

/* Report and then ask to be stopped.
 *
 * Anything this handler cannot serve leaves the guest with no way to continue.
 * Spinning here would be indistinguishable from never having arrived at all,
 * so the reason is written out first if the early console came up - which
 * event was declined, and where the guest was when it took it - and then the
 * host is asked to terminate the guest through the GHCB MSR, which is what
 * Linux does in the same position. That turns an unserviceable exit into an
 * event the host records rather than a machine that has stopped responding.
 *
 * The frame set up on entry to the handler is still intact here, and the
 * console preserves every register, so both values can be read back out.
 */
snp_vc_spin:
#if CONFIG_X86_SNP_EARLY_CON
	leaq	snp_vc_unhandled(%rip), %rdi
	call	snp_dbg_puts
	movq	8(%rbp), %rdi		/* exit code */
	call	snp_dbg_hex64
	leaq	snp_vc_at(%rip), %rdi
	call	snp_dbg_puts
	movq	16(%rbp), %rdi		/* faulting %rip */
	call	snp_dbg_hex64
	movl	$'\n', %edi
	call	snp_dbg_putc
#endif
	movl	$MSR_AMD64_GHCB, %ecx
	movl	$GHCB_MSR_TERM_REQ, %eax
	xorl	%edx, %edx
	wrmsr
	rep; vmmcall			/* VMGEXIT */

	/* A host that declines to stop the guest leaves nothing else to do. */
1:
	hlt
	jmp	1b

#if CONFIG_X86_SNP_EARLY_CON
.section .rodata
snp_vc_unhandled:
	.asciz	"#VC: unhandled exit "
snp_vc_at:
	.asciz	" at rip "
snp_vc_asking:
	.asciz	"#VC: asking host for leaf "
snp_vc_cpuid_msg:
	.asciz	"cpuid "
snp_vc_from_page:
	.asciz	" page\n"
snp_vc_from_host:
	.asciz	" host\n"
#endif

/* The CPUID page, once found: zero until then, and zero for good if the boot
 * parameters never named one. Read on every emulated CPUID, so it is kept
 * where a fault cannot be taken reading it.
 */
.section .data
.align 8
snp_vc_cpuid_page:
	.quad	0
