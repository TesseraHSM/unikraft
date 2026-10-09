/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Local APIC access, in whichever of the two register windows the machine
 * happens to present.
 *
 * x2APIC is preferred where the processor has it, because the MSR window
 * needs no mapping and no serialisation. Where it is absent -- Hyper-V
 * Generation 2 partitions are the case that matters here -- the same
 * registers are reached through the memory-mapped xAPIC window instead. The
 * distinction is confined to this file: every other caller names registers by
 * their x2APIC MSR number and goes through uk_intctlr_apic_read()/_write().
 */

#include <errno.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/intctlr/apic.h>
#include <uk/print.h>

#include <x86/mmio.h>

/* The spurious-interrupt vector to install when the firmware left an
 * architecturally illegal one behind. Vectors below 0x10 are reserved, and a
 * value of zero is what a register that was never programmed reads as.
 */
#define APIC_SVR_DEFAULT_VECTOR		0xFFU
#define APIC_SVR_MIN_VECTOR		0x20U

int uk_intctlr_apic_mode = UK_INTCTLR_APIC_MODE_NONE;
volatile __u8 *uk_intctlr_apic_base;

/** Physical base of the xAPIC register window, when that is the mode */
static __paddr_t apic_paddr;

int uk_intctlr_apic_remap(void)
{
	__vaddr_t vaddr;
	int rc;

	if (uk_intctlr_apic_mode != UK_INTCTLR_APIC_MODE_XAPIC)
		return 0;

	rc = x86_mmio_map_uc(apic_paddr, &vaddr);
	if (unlikely(rc)) {
		/* Every later register access would fault, and a fault in the
		 * interrupt path is not recoverable. Say so loudly and give
		 * up on the APIC rather than take that access.
		 */
		uk_pr_err("Cannot remap the xAPIC window at 0x%lx: %d\n",
			  (unsigned long)apic_paddr, rc);

		uk_intctlr_apic_mode = UK_INTCTLR_APIC_MODE_NONE;
		uk_intctlr_apic_base = __NULL;

		return rc;
	}

	uk_intctlr_apic_base = (volatile __u8 *)vaddr;

	return 0;
}

int uk_intctlr_apic_enable(void)
{
	__u32 eax, ebx, ecx, edx;
	__vaddr_t vaddr;
	__paddr_t paddr;
	__u32 svr, vector;
	int rc;

	uk_intctlr_apic_mode = UK_INTCTLR_APIC_MODE_NONE;
	uk_intctlr_apic_base = __NULL;

	/* IA32_APIC_BASE always exists on any processor with a local APIC,
	 * and its EN bit says whether the APIC is hardware-enabled. Nothing
	 * below is safe if it is not.
	 */
	uk_arch_x86_64_rdmsr(UK_ARCH_X86_64_APIC_MSR_BASE, &eax, &edx);
	if (unlikely(!(eax & UK_ARCH_X86_64_APIC_BASE_EN))) {
		uk_pr_err("Local APIC is disabled\n");

		return -ENODEV;
	}

	/* Switch to x2APIC where it exists and the firmware has not already
	 * done so. On a machine without it the EXTD bit is not merely unset
	 * but unsettable, so the mode is re-read rather than assumed.
	 */
	if (!(eax & UK_ARCH_X86_64_APIC_BASE_EXTD)) {
		uk_arch_x86_64_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

		if (ecx & UK_ARCH_X86_64_CPUID1_ECX_X2APIC) {
			uk_arch_x86_64_rdmsr(UK_ARCH_X86_64_APIC_MSR_BASE,
					     &eax, &edx);
			uk_arch_x86_64_wrmsr(UK_ARCH_X86_64_APIC_MSR_BASE,
					     eax | UK_ARCH_X86_64_APIC_BASE_EXTD,
					     edx);
		}

		uk_arch_x86_64_rdmsr(UK_ARCH_X86_64_APIC_MSR_BASE, &eax, &edx);
	}

	if (eax & UK_ARCH_X86_64_APIC_BASE_EXTD) {
		uk_intctlr_apic_mode = UK_INTCTLR_APIC_MODE_X2APIC;
	} else {
		paddr = (__paddr_t)((((__u64)edx << 32) | (__u64)eax) &
				    UK_ARCH_X86_64_APIC_BASE_ADDR_MASK);

		/* The window is device memory outside every memory region the
		 * boot info describes, so it is neither mapped nor uncacheable
		 * by default. Both have to be arranged before the first
		 * dereference; a fault here would be a silent hang.
		 */
		rc = x86_mmio_map_uc(paddr, &vaddr);
		if (unlikely(rc)) {
			uk_pr_err("Cannot map the xAPIC window at 0x%lx: %d\n",
				  (unsigned long)paddr, rc);

			return rc;
		}

		uk_intctlr_apic_base = (volatile __u8 *)vaddr;
		uk_intctlr_apic_mode = UK_INTCTLR_APIC_MODE_XAPIC;
		apic_paddr = paddr;
	}

#if CONFIG_LIBVIRTIO_PCI_MODERN
	if (uk_intctlr_apic_mode == UK_INTCTLR_APIC_MODE_X2APIC) {
		__u64 cr8;
		__u32 tpr, requested, readback;

		uk_pr_info("SNP_CR8_READ_BEGIN phase=before-apic-init\n");
		cr8 = uk_intctlr_apic_read_cr8();
		tpr = uk_intctlr_apic_read(UK_ARCH_X86_64_APIC_MSR_TPR);
		uk_pr_info("SNP_APIC_PRIORITY phase=before-init cr8=0x%llx tpr=0x%x\n",
			   (unsigned long long)cr8, tpr);
		/* Accept external vectors without admitting exception vectors. */
		requested = (tpr & ~0xffU) | 0x10U;
		uk_intctlr_apic_write(UK_ARCH_X86_64_APIC_MSR_TPR, requested);
		readback = uk_intctlr_apic_read(UK_ARCH_X86_64_APIC_MSR_TPR);
		uk_pr_info("SNP_APIC_PRIORITY_WRITE requested=0x%x readback=0x%x before_svr_enable=1\n",
			   requested, readback);
		if ((readback & 0xffU) != 0x10U) {
			uk_intctlr_apic_mode = UK_INTCTLR_APIC_MODE_NONE;
			return -EIO;
		}
	}
#endif

	/* Hardware-enabled is not enough: with the software-enable bit of the
	 * spurious interrupt vector register clear, the APIC accepts no LVT
	 * configuration and delivers nothing.
	 */
	svr = uk_intctlr_apic_read(UK_ARCH_X86_64_APIC_MSR_SVR);

	vector = svr & UK_ARCH_X86_64_APIC_SVR_VECTOR_MASK;
	if (vector < APIC_SVR_MIN_VECTOR) {
		svr &= ~(__u32)UK_ARCH_X86_64_APIC_SVR_VECTOR_MASK;
		svr |= APIC_SVR_DEFAULT_VECTOR;
	}

	uk_intctlr_apic_write(UK_ARCH_X86_64_APIC_MSR_SVR,
			      svr | UK_ARCH_X86_64_APIC_SVR_EN);

#if CONFIG_LIBVIRTIO_PCI_MODERN
	if (uk_intctlr_apic_mode == UK_INTCTLR_APIC_MODE_X2APIC) {
		__u64 cr8;

		uk_pr_info("SNP_CR8_READ_BEGIN phase=after-apic-init\n");
		cr8 = uk_intctlr_apic_read_cr8();
		uk_pr_info("SNP_APIC_PRIORITY phase=after-init cr8=0x%llx\n",
			   (unsigned long long)cr8);
	}
#endif

	if (uk_intctlr_apic_mode == UK_INTCTLR_APIC_MODE_X2APIC)
		uk_pr_info("Local APIC in x2APIC mode\n");
	else
		uk_pr_info("Local APIC in xAPIC mode, registers at 0x%lx\n",
			   (unsigned long)uk_intctlr_apic_base);

	return 0;
}
