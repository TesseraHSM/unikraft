/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __PLAT_COMMON_X86_MMIO_H__
#define __PLAT_COMMON_X86_MMIO_H__

#include <errno.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/config.h>
#include <uk/essentials.h>

#if CONFIG_LIBUKPAGING
#include <uk/paging.h>
#endif /* CONFIG_LIBUKPAGING */
#if CONFIG_X86_SNP_MMIO_MAPPED
#include <x86/snp_mmio.h>
#endif /* CONFIG_X86_SNP_MMIO_MAPPED */

/*
 * Access to memory-mapped device registers that live outside any memory
 * region the boot info describes, such as the local APIC window or an ACPI
 * register block placed in system memory.
 *
 * Two things have to be true before such a window may be dereferenced, and
 * neither can be assumed:
 *
 *  - It must be mapped. The static boot page table maps the first 4 GiB, but
 *    uk_paging_init() replaces it with a table built solely from the boot
 *    info memory regions, and a device window is not one of those. Faulting
 *    on the access instead presents as a silent hang this early in boot.
 *
 *  - It must be uncacheable. Device registers have side effects on access and
 *    must not be served from, or combined in, a cache.
 */

/** PAT selector bit of a leaf PTE that maps a smallest-size page */
#define X86_MMIO_PTE_PAT_L0	UK_ARCH_X86_64_PTE_PSE		/* bit 7 */
/** PAT selector bit of a leaf PTE that maps a large page */
#define X86_MMIO_PTE_PAT_Lx	(1UL << 12)

/**
 * Make a physical device register window accessible through an uncacheable
 * mapping.
 *
 * The window is identity-mapped: the returned virtual address equals @paddr.
 * Device windows sit in physical address holes that carry no RAM, so no
 * memory region can already claim the same virtual address.
 *
 * Cacheability is forced by selecting PAT slot 3 (PCD and PWT set, the PAT
 * bit clear), which the default PAT contents map to strong uncacheable. That
 * is the same slot Linux selects for its own ioremap_uc().
 *
 * @param paddr
 *   Physical base address of the window. Must be page-aligned.
 * @param[out] vaddr
 *   Receives the virtual address of the window. May be __NULL.
 *
 * @return 0 on success, or a negative errno
 */
static inline int x86_mmio_map_uc(__paddr_t paddr, __vaddr_t *vaddr)
{
	__vaddr_t va = (__vaddr_t)paddr;
#if CONFIG_LIBUKPAGING
	struct uk_pagetable *pt;
	__vaddr_t pt_vaddr;
	unsigned int lvl;
	__pte_t pte, pat_bit;
	int rc;

	if (unlikely(!UK_PAGING_PAGE_ALIGNED(paddr)))
		return -EINVAL;

	pt = uk_paging_pt_get_active();
	if (!pt) {
		/* Paging has not been initialised yet, so the static boot page
		 * table is still active. It identity-maps the first 4 GiB,
		 * which covers architectural device windows, but the mapping
		 * is cacheable and will be replaced wholesale by
		 * uk_paging_init(). Callers that outlive that point must map
		 * again afterwards.
		 */
		if (unlikely(paddr >= (1ULL << 32)))
			return -ENOTSUP;

		if (vaddr)
			*vaddr = va;

		return 0;
	}

	lvl = UK_PAGING_PAGE_LEVEL;
	rc = uk_paging_pt_walk(pt, va, &lvl, &pt_vaddr, &pte);
	if (rc || !(pte & UK_ARCH_X86_64_PTE_PRESENT)) {
		rc = uk_paging_page_map(pt, va, paddr, 1,
					UK_PAGING_PAGE_ATTR_PROT_RW |
					UK_PAGING_PAGE_ATTR_SHARED, 0);
		if (unlikely(rc && rc != -EEXIST))
			return rc;

		lvl = UK_PAGING_PAGE_LEVEL;
		rc = uk_paging_pt_walk(pt, va, &lvl, &pt_vaddr, &pte);
		if (unlikely(rc))
			return rc;

		if (unlikely(!(pte & UK_ARCH_X86_64_PTE_PRESENT)))
			return -EFAULT;
	}

	/* The PAT selector bit moves depending on the size of the page the
	 * leaf entry maps.
	 */
	pat_bit = (lvl == UK_PAGING_PAGE_LEVEL) ? X86_MMIO_PTE_PAT_L0
						: X86_MMIO_PTE_PAT_Lx;

	/* An entry that was already present may have been established by an
	 * earlier, coarser mapping that left the window read-only. Device
	 * registers have to be writable, so the write bit is folded into the
	 * same update as the cache attributes rather than being left to the
	 * uk_paging_page_map() call above, which only runs for absent entries.
	 */
	if ((pte & (UK_ARCH_X86_64_PTE_PCD | UK_ARCH_X86_64_PTE_PWT |
		    UK_ARCH_X86_64_PTE_RW | pat_bit)) !=
	    (UK_ARCH_X86_64_PTE_PCD | UK_ARCH_X86_64_PTE_PWT |
	     UK_ARCH_X86_64_PTE_RW)) {
		pte &= ~pat_bit;
		pte |= UK_ARCH_X86_64_PTE_PCD | UK_ARCH_X86_64_PTE_PWT |
		       UK_ARCH_X86_64_PTE_RW;

		rc = uk_paging_pte_write(pt_vaddr, lvl,
					 UK_PAGING_PT_Lx_IDX(va, lvl), pte);
		if (unlikely(rc))
			return rc;

		uk_paging_tlb_flush_entry(va);
	}
#else /* !CONFIG_LIBUKPAGING */
	/* Without the paging library the static boot page table stays active
	 * for the lifetime of the kernel, and it identity-maps the first 4 GiB
	 * where architectural device windows live.
	 */
	if (unlikely(paddr >= (1ULL << 32)))
		return -ENOTSUP;
#endif /* !CONFIG_LIBUKPAGING */

	if (vaddr)
		*vaddr = va;

	return 0;
}

/**
 * Map and, on an SNP guest, register a complete device MMIO range.
 */
static inline int x86_mmio_map_uc_range(__paddr_t paddr, __sz len,
					__vaddr_t *vaddr)
{
	__vaddr_t va;
	__sz off;
	int rc;

	if (!len || !UK_PAGING_PAGE_ALIGNED(paddr) ||
	    !UK_PAGING_PAGE_ALIGNED(len) || paddr > ~(__paddr_t)0 - len)
		return -EINVAL;

	for (off = 0; off < len; off += UK_PAGING_PAGE_SIZE) {
		rc = x86_mmio_map_uc(paddr + off, __NULL);
		if (rc)
			return rc;
	}
	va = (__vaddr_t)paddr;

#if CONFIG_X86_SNP_MMIO_MAPPED
	rc = snp_mmio_region_register(va, len, paddr, __NULL);
	if (rc)
		return rc;
#endif /* CONFIG_X86_SNP_MMIO_MAPPED */

	if (vaddr)
		*vaddr = va;
	return 0;
}

#endif /* __PLAT_COMMON_X86_MMIO_H__ */
