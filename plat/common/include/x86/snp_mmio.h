/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Mapped MMIO for a SEV-SNP guest that runs with no paravisor.
 *
 * A load or store against a device BAR does not reach the device: the page is
 * not backed, so the access leaves the guest as a nested page fault, which
 * arrives as #VC. Serving it means reading the instruction back, working out
 * which memory operand it names and how wide it is, carrying that one access
 * over the GHCB, and putting the answer where the instruction would have put
 * it. That is what turns an ordinary pointer dereference into a device
 * access, and it is the only thing that lets code written against a mapped
 * BAR - a driver that lives outside this kernel, and knows nothing about the
 * GHCB - run here unchanged.
 *
 * Emulation is deliberately not offered for memory in general. Only ranges
 * registered here are served; a nested page fault anywhere else is still the
 * bug it always was and still stops the guest. Registration is what an owner
 * of a device mapping does after it has mapped the BAR, and withdrawing it is
 * part of giving the device up.
 */
#ifndef __UK_PLAT_COMMON_X86_SNP_MMIO_H__
#define __UK_PLAT_COMMON_X86_SNP_MMIO_H__

#include <uk/arch/types.h>

/** Why an access could not be served. Ordered so that zero means "served". */
enum snp_mmio_reason {
	SNP_MMIO_OK = 0,
	/** The handler was entered while already serving an access */
	SNP_MMIO_REENTERED,
	/** A prefix this decoder does not serve, or too many of them */
	SNP_MMIO_PREFIX,
	/** Not one of the MOV forms that carry a device access */
	SNP_MMIO_OPCODE,
	/** The operand is a register, or the encoding names no memory */
	SNP_MMIO_OPERAND,
	/** A register the decoder will not read or write in this form */
	SNP_MMIO_REGISTER,
	/** The address is not inside any registered mapping */
	SNP_MMIO_UNREGISTERED,
	/** The access runs past the end of the mapping that holds its start */
	SNP_MMIO_SPAN,
	/** The GHCB refused the access */
	SNP_MMIO_TRANSPORT,
};

/**
 * What the handler saw the last time it declined an access.
 *
 * The handler cannot report anything itself: the console is port I/O, and a
 * port access from inside #VC would raise a second #VC on top of the first.
 * So it records, and whoever asks reports. Declining is terminal, so this is
 * read by the failure path rather than polled.
 */
struct snp_mmio_fault {
	__u64 count;
	__u64 rip;
	__u64 address;
	__u32 reason;
	__u32 width;
	__u8 insn[16];
};

/** Counters for served accesses, per registered owner rather than global. */
struct snp_mmio_stats {
	__u64 reads;
	__u64 writes;
	__u64 errors;
};

/**
 * Serve device accesses made against a mapped range.
 *
 * @param va
 *   Page-aligned start of the mapping, as the owner will dereference it
 * @param len
 *   Length in bytes, a whole number of pages
 * @param gpa
 *   Guest physical address the first page of the mapping names, without the
 *   shared boundary bit - the same address ukplat_confidential_mmio() takes
 * @param stats
 *   Counters to attribute served accesses to, or NULL
 *
 * @return 0 on success, or a negative errno
 */
int snp_mmio_region_register(__vaddr_t va, __sz len, __paddr_t gpa,
			     struct snp_mmio_stats *stats);

/**
 * Stop serving a range.
 *
 * After this returns, an access to the range stops the guest rather than
 * reaching the device, so the caller must unmap it as well; the two together
 * are what makes a withdrawn mapping unreachable rather than merely wrong.
 *
 * @param va
 *   The start address the range was registered with
 *
 * @return 0 on success, or a negative errno
 */
int snp_mmio_region_unregister(__vaddr_t va);

/** Whether any range is currently served. */
int snp_mmio_active(void);

/** The last declined access, for a caller that is able to report it. */
const struct snp_mmio_fault *snp_mmio_last_fault(void);

/**
 * Serve one access. Called from the #VC handler, not from ordinary code.
 *
 * @param regs
 *   The interrupted general registers, in instruction-encoding order
 * @param rip
 *   The interrupted instruction pointer, advanced past the instruction when
 *   the access is served
 *
 * @return non-zero if the access was served
 */
int snp_vc_mmio_emulate(unsigned long *regs, unsigned long *rip);

#endif /* __UK_PLAT_COMMON_X86_SNP_MMIO_H__ */
