/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_INTCTLR_APIC_H__
#define __UK_INTCTLR_APIC_H__

#include <uk/arch/types.h>
#include <uk/arch/util.h>
#include <uk/arch/x86_64.h>
#include <uk/config.h>
#include <uk/essentials.h>

#if CONFIG_LIBUKINTCTLR_APIC

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The local APIC is reachable in one of two ways, and which one it is depends
 * on the machine rather than on us.
 *
 * x2APIC exposes the registers as MSRs 0x800..0x83f. It is the mode this
 * driver prefers, and the mode a QEMU guest with a modern CPU model comes up
 * in. xAPIC exposes the same registers as 32-bit memory-mapped registers, 16
 * bytes apart, based at the address in IA32_APIC_BASE. Hyper-V Generation 2
 * machines present the local APIC this way unless the host configuration
 * enables x2APIC, so both modes have to work.
 *
 * Registers are named throughout by their x2APIC MSR number
 * (UK_ARCH_X86_64_APIC_MSR_*); the corresponding xAPIC offset is derived from
 * it, so there is only ever one register table.
 */

/** No usable local APIC */
#define UK_INTCTLR_APIC_MODE_NONE	0
/** Local APIC registers are memory-mapped */
#define UK_INTCTLR_APIC_MODE_XAPIC	1
/** Local APIC registers are MSRs */
#define UK_INTCTLR_APIC_MODE_X2APIC	2

/** Base of the x2APIC MSR window */
#define UK_INTCTLR_APIC_MSR_FIRST	0x800U

/**
 * The xAPIC memory-mapped offset of a register named by its x2APIC MSR
 * number. The two windows hold the same registers in the same order, one MSR
 * apart and 16 bytes apart respectively.
 */
#define UK_INTCTLR_APIC_MMIO_OFF(reg)					\
	(((reg) - UK_INTCTLR_APIC_MSR_FIRST) << 4)

/** Which of UK_INTCTLR_APIC_MODE_* the local APIC is in */
extern int uk_intctlr_apic_mode;

/** Register window when in xAPIC mode, otherwise __NULL */
extern volatile __u8 *uk_intctlr_apic_base;

/**
 * Bring the local APIC into a usable state.
 *
 * Switches to x2APIC when the processor supports it, and otherwise sets up
 * access to the memory-mapped xAPIC window. In both cases the APIC is left
 * software-enabled, so that LVT entries are delivered.
 *
 * @return 0 on success, or a negative errno. On failure the APIC mode is
 *   UK_INTCTLR_APIC_MODE_NONE and no register access must be attempted.
 */
int uk_intctlr_apic_enable(void);

/**
 * Re-establish the xAPIC register window after the active page table has been
 * replaced.
 *
 * The interrupt controller is probed before the paging subsystem builds the
 * kernel page table, so the mapping uk_intctlr_apic_enable() relied on -- the
 * static boot page table's identity map of the first 4 GiB -- does not
 * survive into the table that is active for the rest of the kernel's life.
 * The platform calls this once paging is up; it also makes the window
 * uncacheable, which the boot page table's mapping is not.
 *
 * A no-op unless the APIC is in xAPIC mode.
 *
 * @return 0 on success, or a negative errno. On failure the APIC mode is
 *   reset to UK_INTCTLR_APIC_MODE_NONE rather than left pointing at an
 *   unmapped window.
 */
int uk_intctlr_apic_remap(void);

/**
 * Read a local APIC register.
 *
 * @param reg
 *   The register, named by its x2APIC MSR number
 *
 * @return the register's low 32 bits, or 0 if there is no usable APIC
 */
static inline __u32 uk_intctlr_apic_read(__u32 reg)
{
	__u32 eax, edx;

	if (uk_intctlr_apic_mode == UK_INTCTLR_APIC_MODE_X2APIC) {
		uk_arch_x86_64_rdmsr(reg, &eax, &edx);

		return eax;
	}

	if (unlikely(uk_intctlr_apic_mode != UK_INTCTLR_APIC_MODE_XAPIC))
		return 0;

	return *(volatile __u32 *)(uk_intctlr_apic_base +
				   UK_INTCTLR_APIC_MMIO_OFF(reg));
}

/**
 * Write a local APIC register.
 *
 * Does nothing when there is no usable APIC; in particular it never issues
 * the x2APIC MSR write, which raises a general protection fault while the
 * APIC is in xAPIC mode.
 *
 * @param reg
 *   The register, named by its x2APIC MSR number
 * @param val
 *   The value to write
 */
static inline void uk_intctlr_apic_write(__u32 reg, __u32 val)
{
	if (uk_intctlr_apic_mode == UK_INTCTLR_APIC_MODE_X2APIC) {
		uk_arch_x86_64_wrmsr(reg, val, 0);

		return;
	}

	if (unlikely(uk_intctlr_apic_mode != UK_INTCTLR_APIC_MODE_XAPIC))
		return;

	*(volatile __u32 *)(uk_intctlr_apic_base +
			    UK_INTCTLR_APIC_MMIO_OFF(reg)) = val;
}

/** Signal end of interrupt to the local APIC. */
static inline void uk_intctlr_apic_eoi(void)
{
	uk_intctlr_apic_write(UK_ARCH_X86_64_APIC_MSR_EOI, 0);
}

#if CONFIG_LIBVIRTIO_PCI_MODERN
static inline __u64 uk_intctlr_apic_read_cr8(void)
{
	__u64 value;

	__asm__ __volatile__("mov %%cr8, %0" : "=r"(value) : : "memory", "cc");
	return value;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_LIBUKINTCTLR_APIC */
#endif /* __UK_INTCTLR_APIC_H__ */
