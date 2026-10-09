/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Host-visible memory for hardware-isolated (confidential) partitions.
 *
 * On an ordinary partition every guest page is readable by the hypervisor, so
 * a buffer shared with the host is just a buffer. On an AMD SEV-SNP or Intel
 * TDX partition it is not: guest memory is encrypted with a key the host does
 * not hold, and a page becomes host-readable only if the guest deliberately
 * places it in the shared aperture.
 *
 * Microsoft's hardware-isolated partitions express that aperture as a *shared
 * GPA boundary*, which AMD documentation calls vTOM. It is a single power of
 * two: a guest physical address below it names private, encrypted memory, and
 * the same address with the boundary bit set names the identical DRAM in the
 * clear. Sharing a page therefore does not move it - it is accessed through
 * its aliased address instead of its native one.
 *
 * That is what this file provides. mshv_alloc_shared() allocates normally,
 * then maps a second virtual window onto the aliased physical addresses and
 * hands back a pointer into that window. Everything the guest and the host
 * both look at goes through the alias, so the two see the same bytes.
 *
 * The boundary bit is a property of the guest's own view and not part of the
 * name of the page: the hypervisor is told where a buffer is in the same
 * terms either way. Since uk_paging_virt_to_phys() resolves an address by
 * walking the page table, it returns the aliased address for a pointer from
 * this allocator, so an address that is about to leave the guest goes through
 * mshv_gpa(), which takes the bit back off.
 *
 * When the partition is not isolated this degrades to a plain aligned
 * allocation and no alias is created, which leaves the ordinary MSHV path
 * exactly as it was.
 *
 * The isolation configuration is read from the Microsoft hypervisor's
 * isolation CPUID leaf as defined by the Hypervisor Top-Level Functional
 * Specification. Note that CPUID 0x8000001F, the architectural AMD SEV leaf,
 * reports nothing on these partitions - SEV is deliberately hidden from the
 * guest - so it must not be used to detect isolation.
 */

#include <errno.h>
#include <uk/alloc.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/paging.h>
#include <uk/plat/isolation.h>
#include <uk/plat/shmem.h>
#include <uk/plat/memory.h>
#include <uk/print.h>
#include <string.h>

#include <uk/plat/mshv.h>
#include <x86/snp.h>

/*
 * Base of the virtual window the aliases are mapped into.
 *
 * The window has to be somewhere nothing else will ever claim. This sits far
 * above every region the boot info describes yet still below the 47-bit
 * canonical limit, so the addresses need no sign extension and cannot collide
 * with the kernel's own direct map, which lives in the upper half.
 */
#define MSHV_SHARED_VA_BASE		0x0000700000000000UL

/*
 * Size of the window, in pages. The demand is known and small: the NetVSC
 * receive and sending buffers dominate it at a megabyte each, with the VMBus
 * event and monitor pages, one ring pair per channel and a handful of control
 * buffers behind them. Sixteen megabytes leaves substantial headroom and
 * costs only the bitmap below.
 */
#define MSHV_SHARED_VA_PAGES		4096

/*
 * Concurrently live allocations. Each ring pair, buffer and control page is
 * one; the count is bounded by the device topology, not by traffic.
 */
#define MSHV_SHARED_MAX_ALLOCS	64

#define MSHV_BITS_PER_LONG		(sizeof(unsigned long) * 8)

/*
 * A region of guest physical memory to carve host visible buffers out of,
 * used instead of the heap when one is configured.
 *
 * A VTL2 payload cannot share heap memory with the host at all. Its image is
 * described by the IGVM file as VTL2 protectable and the loader protects the
 * whole of it, so any attempt by the host to acquire access to a page inside
 * it is denied by the hypervisor; a channel whose ring buffers live there is
 * refused with STATUS_VID_VTL_ACCESS_DENIED when the host tries to map them.
 * The hypercall that would publish a page is no help either: it is defined
 * only for hardware isolated partitions and is rejected here.
 *
 * What is left is memory outside the region the IGVM describes. It carries no
 * VTL protection, so the host can map it, and it belongs to VTL0, which this
 * payload leaves empty. Buffers are bump allocated from it and mapped into
 * the same virtual window the aliases use, so callers see no difference.
 *
 * Where that region starts is never hardcoded. The loader hands the payload a
 * memory map describing exactly the RAM it protected, so the arena simply
 * begins above the highest address that map accounts for.
 */
#if CONFIG_MSHV_SHARED_GPA_PAGES != 0
#define MSHV_SHARED_GPA_ARENA		1
#define MSHV_SHARED_GPA_PAGES		CONFIG_MSHV_SHARED_GPA_PAGES

static unsigned long shared_gpa_used;
static __paddr_t shared_gpa_base;

/* Locate the arena just past every region the boot memory map accounts for.
 * Device regions are skipped: they are MMIO apertures far above RAM and say
 * nothing about how much memory the loader described.
 */
static __paddr_t mshv_shared_gpa_base(void)
{
	struct ukplat_memregion_desc *mrd;
	__paddr_t top = 0;

	if (shared_gpa_base)
		return shared_gpa_base;

	ukplat_memregion_foreach(&mrd, UKPLAT_MEMRT_ANY & ~UKPLAT_MEMRT_DEVICE,
				 0, 0) {
		__paddr_t end = mrd->pbase + mrd->pg_count * __PAGE_SIZE;

		if (end > top)
			top = end;
	}

	shared_gpa_base = (top + __PAGE_SIZE - 1)
			  & ~((__paddr_t)__PAGE_SIZE - 1);

	return shared_gpa_base;
}
#endif

/* Microsoft hypervisor isolation configuration leaf */
#define HV_CPUID_ISOLATION_CONFIG	0x4000000C

/* EAX: a paravisor at VMPL0 is servicing this partition */
#define HV_ISOLATION_PARAVISOR_PRESENT	(1UL << 0)

/* EBX[3:0]: how the partition is isolated */
#define HV_ISOLATION_TYPE_MASK		0xfUL
#define HV_ISOLATION_TYPE_NONE		0
#define HV_ISOLATION_TYPE_VBS		1
#define HV_ISOLATION_TYPE_SNP		2
#define HV_ISOLATION_TYPE_TDX		3

/* EBX[5]: a shared GPA boundary is in effect */
#define HV_ISOLATION_SHARED_GPA_ACTIVE	(1UL << 5)

/* EBX[11:6]: which bit of a guest physical address the boundary is */
#define HV_ISOLATION_SHARED_GPA_SHIFT	6
#define HV_ISOLATION_SHARED_GPA_BITS	0x3fUL

static int isolation_probed;
static int isolation_rc = -EAGAIN;
static __u32 isolation_type;
static int isolation_paravisor;
static __u64 shared_gpa_boundary;

/*
 * Set when the partition is isolated but shares in place.
 *
 * A VBS partition is isolated from the host without being encrypted
 * against it, so there is no aperture to re-address a buffer into and
 * no boundary bit to carry. A page is published where it already is,
 * by moving it from private to host visible. The guest's own view of
 * it never changes, which is why this is deliberately not folded into
 * mshv_isolated(): that predicate means "reached through an alias",
 * and the SNP and TDX paths keyed off it must stay unreachable here.
 */
static int isolation_inplace;

/* Set when a page is published by moving it across the encryption boundary
 * and clearing the encryption bit in its mapping, rather than by aliasing it
 * above a vTOM boundary. This is what a paravisor-less SNP partition does.
 */
static int isolation_cbit;

/* One bit per page of the window, set when the page is in use */
static unsigned long shared_va_bitmap[MSHV_SHARED_VA_PAGES
				      / MSHV_BITS_PER_LONG];

/*
 * What has to be undone to release an allocation: the window pages to unmap,
 * and the private allocation that actually backs them, which the alias
 * deliberately says nothing about.
 */
struct mshv_shared_alloc {
	__vaddr_t va;
	void *backing;
	unsigned long pages;
	/* Published in place, so va aliases backing and there is no
	 * window reservation or mapping to undo.
	 */
	int inplace;
	/* Taken from the host visible region rather than the heap, so the
	 * frames belong to nobody and only the mapping is the allocator's
	 * to undo.
	 */
	int arena;
};

static struct mshv_shared_alloc shared_allocs[MSHV_SHARED_MAX_ALLOCS];

int mshv_isolation_init(void)
{
	__u32 eax, ebx, ecx, edx;

	if (isolation_probed)
		return isolation_rc;

	isolation_probed = 1;
	isolation_rc = 0;
	isolation_type = HV_ISOLATION_TYPE_NONE;

	if (!mshv_available())
		return 0;

	/* Leaves beyond the advertised maximum return whatever the highest
	 * implemented leaf returns, so a partition that predates the isolation
	 * leaf would otherwise be misread as isolated.
	 */
	if (mshv_max_cpuid_leaf() < HV_CPUID_ISOLATION_CONFIG)
		return 0;

	uk_arch_x86_64_cpuid(HV_CPUID_ISOLATION_CONFIG, 0,
			     &eax, &ebx, &ecx, &edx);

	isolation_type = ebx & HV_ISOLATION_TYPE_MASK;
	isolation_paravisor = !!(eax & HV_ISOLATION_PARAVISOR_PRESENT);

	if (isolation_type == HV_ISOLATION_TYPE_NONE)
		return 0;

	if (ebx & HV_ISOLATION_SHARED_GPA_ACTIVE) {
		__u32 bit = (ebx >> HV_ISOLATION_SHARED_GPA_SHIFT)
			    & HV_ISOLATION_SHARED_GPA_BITS;

		if (bit)
			shared_gpa_boundary = 1ULL << bit;
	}

	uk_pr_info("mshv: isolation type %u (%s), paravisor %s, shared GPA boundary 0x%lx\n",
		   isolation_type,
		   isolation_type == HV_ISOLATION_TYPE_SNP ? "SNP"
		   : isolation_type == HV_ISOLATION_TYPE_TDX ? "TDX"
		   : isolation_type == HV_ISOLATION_TYPE_VBS ? "VBS"
		   : "unknown",
		   isolation_paravisor ? "present" : "absent",
		   (unsigned long)shared_gpa_boundary);

	/* A VBS partition publishes in place and has no boundary by
	 * construction. Nothing further needs to be checked: the page
	 * table is not involved, so there is no address width to satisfy.
	 */
	if (isolation_type == HV_ISOLATION_TYPE_VBS) {
		isolation_inplace = 1;
		return 0;
	}

	/* For the encrypted types a boundary is the only way to publish a
	 * buffer at all, and without one every VMBus buffer would be
	 * silently invisible to the host. Say so here rather than let it
	 * surface much later as a protocol fault.
	 */
	/* An encrypted partition with a paravisor above it is launched with
	 * vTOM, so publishing is an address-bit alias and no page table work
	 * is needed. Without a paravisor the guest owns the encryption bit
	 * itself, there is no boundary to alias through, and a page is
	 * published by moving it across the boundary and mapping it without
	 * the bit. Both are normal; only an encrypted partition that is
	 * neither is not.
	 */
	if (!shared_gpa_boundary && isolation_type == HV_ISOLATION_TYPE_SNP &&
	    !isolation_paravisor) {
		isolation_cbit = 1;

		uk_pr_info("mshv: publishing pages by page state change, no vTOM alias\n");

		return 0;
	}

	if (unlikely(!shared_gpa_boundary)) {
		uk_pr_err("mshv: isolated partition without a shared GPA boundary\n");
		isolation_rc = -ENOTSUP;
		return isolation_rc;
	}

	/* The alias carries a physical address bit that the boundary implies
	 * the hardware must implement. If it does not, that bit is a reserved
	 * bit in every page table entry and the first access through an alias
	 * would fault, so refuse now while the reason is still visible.
	 */
	if (unlikely(!uk_paging_paddr_isvalid(shared_gpa_boundary))) {
		uk_pr_err("mshv: shared GPA boundary 0x%lx exceeds the physical address width\n",
			  (unsigned long)shared_gpa_boundary);
		isolation_rc = -ENOTSUP;
		return isolation_rc;
	}

	return 0;
}

int mshv_paravisor(void)
{
	return isolation_paravisor;
}

/*
 * Which isolation technology, if any, covers this partition.
 *
 * mshv_isolated() answers whether memory has to be shared explicitly, which
 * is what the rest of the platform code needs; this reports the technology
 * itself, including the isolated-but-boundary-less case that the former
 * deliberately treats as not isolated.
 */
__u32 mshv_isolation_type(void)
{
	return isolation_type;
}

/*
 * The isolation configuration is only readable once it has been probed, and
 * this is reachable from application code that has no reason to know that, so
 * the probe happens here. mshv_isolation_init() is cheap after the first
 * call, and every wrapper below reads the state it leaves behind.
 */
int ukplat_shmem_init(void)
{
	return mshv_isolation_init();
}

int ukplat_shmem_required(void)
{
	/* Type 2 is the encrypted partition that moves its own pages across
	 * the boundary, which is the one where a device cannot be handed an
	 * ordinary allocation.
	 */
	return mshv_isolation_type() == 2;
}

void *ukplat_shmem_alloc(__sz size, unsigned long attr)
{
	return mshv_alloc_shared(size, attr);
}

void ukplat_shmem_free(void *ptr)
{
	mshv_free_shared(ptr);
}

__paddr_t ukplat_shmem_gpa(const void *addr)
{
	return mshv_gpa(addr);
}

enum uk_isolation_type uk_isolation_type(void)
{
	mshv_isolation_init();

	switch (isolation_type) {
	case HV_ISOLATION_TYPE_VBS:
		return UK_ISOLATION_VBS;
	case HV_ISOLATION_TYPE_SNP:
		return UK_ISOLATION_SNP;
	case HV_ISOLATION_TYPE_TDX:
		return UK_ISOLATION_TDX;
	default:
		return UK_ISOLATION_NONE;
	}
}

int mshv_isolated(void)
{
	/* An encrypted partition is isolated whether it publishes through a
	 * vTOM alias or by moving pages across the boundary itself.
	 */
	return isolation_type != HV_ISOLATION_TYPE_NONE
	       && (shared_gpa_boundary != 0 || isolation_cbit);
}

int mshv_hypercall_direct(void)
{
	return isolation_cbit;
}

__u64 mshv_shared_gpa_boundary(void)
{
	return shared_gpa_boundary;
}

__paddr_t mshv_gpa(const void *addr)
{
	return uk_paging_virt_to_phys((__vaddr_t)addr) & ~shared_gpa_boundary;
}

static inline int shared_va_test(unsigned long i)
{
	return !!(shared_va_bitmap[i / MSHV_BITS_PER_LONG]
		  & (1UL << (i % MSHV_BITS_PER_LONG)));
}

static long shared_va_reserve(unsigned long pages)
{
	unsigned long run = 0;

	for (unsigned long i = 0; i < MSHV_SHARED_VA_PAGES; i++) {
		if (shared_va_test(i)) {
			run = 0;
			continue;
		}

		if (++run < pages)
			continue;

		/* i is the last page of the run, so step back to the first */
		for (unsigned long j = i + 1 - pages; j <= i; j++)
			shared_va_bitmap[j / MSHV_BITS_PER_LONG] |=
				1UL << (j % MSHV_BITS_PER_LONG);

		return (long)(i + 1 - pages);
	}

	return -1;
}

static void shared_va_release(unsigned long idx, unsigned long pages)
{
	for (unsigned long j = idx; j < idx + pages; j++)
		shared_va_bitmap[j / MSHV_BITS_PER_LONG] &=
			~(1UL << (j % MSHV_BITS_PER_LONG));
}

/*
 * Retire a range from the cache before it is handed over to its alias.
 *
 * Private and shared addresses for the same DRAM differ in the boundary bit,
 * so they occupy different cache lines but the same memory. A line still held
 * dirty from the private mapping would therefore be written back over data the
 * host had already been shown. Flushing the private range first removes that
 * possibility.
 *
 * CLFLUSH is used rather than WBINVD because it is not an intercepted
 * instruction: it needs no assistance from the hypervisor or the paravisor,
 * and it touches only the range that is actually changing hands.
 */
static void shared_flush_private(void *addr, __sz size)
{
	const __sz line = 64;
	__u8 *p = (__u8 *)((__uptr)addr & ~(__uptr)(line - 1));
	__u8 *end = (__u8 *)addr + size;

	__asm__ __volatile__("mfence" ::: "memory");

	for (; p < end; p += line)
		__asm__ __volatile__("clflush (%0)" :: "r"(p) : "memory");

	__asm__ __volatile__("mfence" ::: "memory");
}

static void *shared_alloc(__sz size, unsigned long attr)
{
	struct uk_alloc *a = uk_alloc_get_default();
	struct mshv_shared_alloc *rec = __NULL;
	struct uk_pagetable *pt;
	unsigned long pages;
	void *backing;
	__vaddr_t va;
	long idx;
	int rc;

	if (unlikely(!a || !size))
		return __NULL;

	pages = (size + __PAGE_SIZE - 1) / __PAGE_SIZE;

#ifdef MSHV_SHARED_GPA_ARENA
	{
		__paddr_t gpa;

		for (int i = 0; i < MSHV_SHARED_MAX_ALLOCS; i++) {
			if (!shared_allocs[i].backing) {
				rec = &shared_allocs[i];
				break;
			}
		}

		if (unlikely(!rec)) {
			uk_pr_err("mshv: no free shared allocation record\n");
			return __NULL;
		}

		if (unlikely(pages > MSHV_SHARED_GPA_PAGES - shared_gpa_used)) {
			uk_pr_err("mshv: the host visible region cannot fit %lu more page(s)\n",
				  pages);
			return __NULL;
		}

		gpa = mshv_shared_gpa_base()
		      + (__paddr_t)shared_gpa_used * __PAGE_SIZE;

		idx = shared_va_reserve(pages);
		if (unlikely(idx < 0)) {
			uk_pr_err("mshv: the shared window cannot fit %lu more pages\n",
				  pages);
			return __NULL;
		}

		va = MSHV_SHARED_VA_BASE + (__vaddr_t)idx * __PAGE_SIZE;
		pt = uk_paging_pt_get_active();

		/* The region is contiguous by construction, so unlike the
		 * alias path this needs no per page lookup; each page is
		 * still mapped individually because that is the only
		 * granularity the mapper offers here.
		 */
		for (unsigned long i = 0; i < pages; i++) {
			rc = uk_paging_page_map(pt, va + i * __PAGE_SIZE,
						gpa + i * __PAGE_SIZE,
						1, attr, 0);
			if (unlikely(rc)) {
				uk_pr_err("mshv: cannot map a host visible page: %d\n",
					  rc);
				if (i)
					uk_paging_page_unmap(pt, va, i,
						UK_PAGING_PAGE_FLAG_KEEP_FRAMES);

				shared_va_release((unsigned long)idx, pages);
				return __NULL;
			}
		}

		shared_gpa_used += pages;
		rec->va = va;
		rec->backing = (void *)va;
		rec->pages = pages;
		rec->arena = 1;

		/* The frames come from a region nothing has written, but the
		 * ring buffer protocol reads the indices before it writes
		 * any, so they have to start out saying the ring is empty.
		 */
		memset((void *)va, 0, pages * __PAGE_SIZE);

		return (void *)va;
	}
#endif /* MSHV_SHARED_GPA_ARENA */

	backing = uk_memalign(a, __PAGE_SIZE, pages * __PAGE_SIZE);
	if (unlikely(!backing))
		return __NULL;

	if (!mshv_isolated()) {
		memset(backing, 0, pages * __PAGE_SIZE);

		/* On a VBS partition the buffer is where it will stay and the
		 * caller's pointer is final; only the host's access to it has
		 * to be arranged.
		 */
		if (isolation_inplace) {
			struct mshv_shared_alloc *rec = __NULL;

			for (int i = 0; i < MSHV_SHARED_MAX_ALLOCS; i++) {
				if (!shared_allocs[i].backing) {
					rec = &shared_allocs[i];
					break;
				}
			}

			if (unlikely(!rec)) {
				uk_pr_err("mshv: no free shared allocation record\n");
				uk_free(a, backing);
				return __NULL;
			}

			/* Under VBS the paravisor is protected from the VTL0
			 * guest, not from the host: memory is hidden only by
			 * the VTL protections VTL2 applies to it, and this
			 * payload applies none. Its pages are therefore
			 * already host visible and the hypercall has nothing
			 * to do, so a rejection is recorded and ignored
			 * rather than failing the allocation. The encrypted
			 * types keep the strict behaviour above, where a
			 * refusal really does mean the host cannot see the
			 * buffer.
			 */
			{
				int vrc = mshv_set_range_visibility(
						(__vaddr_t)backing, pages, 1);

				if (vrc)
					uk_pr_debug("mshv: in-place publish of %lu page(s) refused, already visible\n",
						    pages);
			}

			rec->va = (__vaddr_t)backing;
			rec->backing = backing;
			rec->pages = pages;
			rec->inplace = 1;
		}

		/* An ordinary partition still has to honour a request for an
		 * executable buffer; only the sharing is unnecessary.
		 */
		if (attr != UK_PAGING_PAGE_ATTR_PROT_RW) {
			rc = uk_paging_page_set_attr(uk_paging_pt_get_active(),
						     (__vaddr_t)backing,
						     pages, attr, 0);
			if (unlikely(rc)) {
				uk_pr_err("mshv: cannot set buffer attributes: %d\n",
					  rc);
				uk_free(a, backing);
				return __NULL;
			}
		}

		return backing;
	}

	/* Paravisor-less SNP: there is no alias to map, because there is no
	 * boundary to alias through. The page is published where it lies, by
	 * handing it to the hypervisor and then dropping the encryption bit
	 * from its mapping.
	 *
	 * The order is not free. While the mapping still claims the page as
	 * private nothing can be read out of it in the clear, and the RMP
	 * still records the guest as its owner; clearing the encryption bit
	 * first would open a window in which the processor accesses the page
	 * unencrypted while the RMP still calls it guest-owned, which faults.
	 * Withdrawing validation has to come first for the same reason from
	 * the other side: the hypervisor cannot be given a page the guest
	 * still holds a validated claim on. snp_set_page_state() performs
	 * those two steps in that order; the mapping change follows here.
	 */
	if (isolation_cbit) {
		uk_pr_info("mshv: publishing %lu page(s) at va 0x%lx\n",
			   pages, (unsigned long)backing);

		/* Scrub whatever the allocator handed back before the page
		 * leaves the guest's sole ownership. This is not what makes
		 * the buffer read as zero afterwards -- the bytes written
		 * here go through the private view and survive the handover
		 * as ciphertext -- it only ensures that what the host
		 * inherits is the ciphertext of zeros rather than of whatever
		 * the heap last held.
		 */
		memset(backing, 0, pages * __PAGE_SIZE);

		/* Nothing of the private view may be written back after the
		 * host starts reading the page.
		 */
		shared_flush_private(backing, pages * __PAGE_SIZE);
		rc = snp_set_page_state((__vaddr_t)backing, pages,
					SNP_PAGE_STATE_SHARED);
		if (unlikely(rc)) {
			uk_pr_err("mshv: cannot publish %lu page(s): %d\n",
				  pages, rc);
			/* A failed range transition can leave some pages shared. */
			return __NULL;
		}

		uk_pr_info("mshv: %lu page(s) handed over, dropping the encryption bit\n",
			   pages);

		rc = uk_paging_page_set_attr(uk_paging_pt_get_active(),
					     (__vaddr_t)backing, pages,
					     attr | UK_PAGING_PAGE_ATTR_SHARED,
					     0);
		if (unlikely(rc)) {
			uk_pr_err("mshv: cannot drop the encryption bit from %lu page(s): %d\n",
				  pages, rc);
			/* The pages are shared; never recycle them as private. */
			return __NULL;
		}

		/* Only now does zeroing mean anything to the host. A page
		 * moved from private to shared keeps the bytes it held, and
		 * read back without the encryption bit those bytes are the
		 * old ciphertext. A caller that asked for a zeroed buffer is
		 * asking for one the host also sees as zero, which is a
		 * property of the shared view and can only be established
		 * through it.
		 */
		memset(backing, 0, pages * __PAGE_SIZE);

		for (int i = 0; i < MSHV_SHARED_MAX_ALLOCS; i++) {
			if (!shared_allocs[i].backing) {
				rec = &shared_allocs[i];
				break;
			}
		}

		if (likely(rec)) {
			rec->va = (__vaddr_t)backing;
			rec->backing = backing;
			rec->pages = pages;
			rec->inplace = 1;
		}

		return backing;
	}

	/* Retire the private view now, while it is still mapped, so that no
	 * line of it can be written back after the host starts reading the
	 * shared alias.
	 */
	shared_flush_private(backing, pages * __PAGE_SIZE);

	/* The buffer has to be published here, before the alias is mapped, or
	 * the first access through it faults on a page the host has no mapping
	 * for.
	 */
	rc = mshv_set_range_visibility((__vaddr_t)backing, pages, 1);
	if (unlikely(rc)) {
		uk_pr_err("mshv: cannot publish %lu page(s): %d\n",
			  pages, rc);
		goto err_free;
	}

	for (int i = 0; i < MSHV_SHARED_MAX_ALLOCS; i++) {
		if (!shared_allocs[i].backing) {
			rec = &shared_allocs[i];
			break;
		}
	}

	if (unlikely(!rec)) {
		uk_pr_err("mshv: no free shared allocation record\n");
		goto err_free;
	}

	idx = shared_va_reserve(pages);
	if (unlikely(idx < 0)) {
		uk_pr_err("mshv: the shared window cannot fit %lu more pages\n",
			  pages);
		goto err_free;
	}

	va = MSHV_SHARED_VA_BASE + (__vaddr_t)idx * __PAGE_SIZE;
	pt = uk_paging_pt_get_active();

	/* The backing allocation is contiguous in virtual address space but
	 * says nothing about physical contiguity, so each page is aliased
	 * individually. The window is contiguous either way, which is what
	 * lets callers treat the result as one buffer.
	 */
	for (unsigned long i = 0; i < pages; i++) {
		__paddr_t pa = uk_paging_virt_to_phys((__vaddr_t)backing
						      + i * __PAGE_SIZE);

		rc = uk_paging_page_map(pt, va + i * __PAGE_SIZE,
					pa | shared_gpa_boundary, 1, attr, 0);
		if (unlikely(rc)) {
			uk_pr_err("mshv: cannot map a shared alias: %d\n",
				  rc);

			if (i)
				uk_paging_page_unmap(pt, va, i,
						UK_PAGING_PAGE_FLAG_KEEP_FRAMES);

			shared_va_release((unsigned long)idx, pages);
			goto err_free;
		}
	}

	rec->va = va;
	rec->backing = backing;
	rec->pages = pages;

	uk_pr_info("mshv: alias 0x%lx mapped over %lu page(s) at pa 0x%lx\n",
		   (unsigned long)va, pages,
		   (unsigned long)uk_paging_virt_to_phys((__vaddr_t)backing));

	/* Zero through the alias rather than through the backing pointer. The
	 * two views of the page differ in their encryption state, so only what
	 * is written through the alias is what the host will read.
	 */
	memset((void *)va, 0, pages * __PAGE_SIZE);

	uk_pr_info("mshv: alias 0x%lx ready\n", (unsigned long)va);

	return (void *)va;

err_free:
	uk_free(a, backing);

	return __NULL;
}

void *mshv_map_shared_gpa(__paddr_t gpa, unsigned long pages,
			    unsigned long attr)
{
	struct uk_pagetable *pt;
	__vaddr_t va;
	long idx;
	int rc;

	UK_ASSERT(pages > 0);
	UK_ASSERT(!(gpa & (__PAGE_SIZE - 1)));

	if (!shared_gpa_boundary) {
		if (unlikely(!isolation_cbit)) {
			uk_pr_err("mshv: no supported sharing mode for a foreign page\n");
			return __NULL;
		}
		/* Foreign MMIO is already shared: keep the device GPA and
		 * clear the PTE encryption bit, without changing page state.
		 */
		attr |= UK_PAGING_PAGE_ATTR_SHARED;
	}

	idx = shared_va_reserve(pages);
	if (unlikely(idx < 0)) {
		uk_pr_err("mshv: the shared window cannot fit %lu more pages\n",
			  pages);
		return __NULL;
	}

	va = MSHV_SHARED_VA_BASE + (__vaddr_t)idx * __PAGE_SIZE;
	pt = uk_paging_pt_get_active();

	for (unsigned long i = 0; i < pages; i++) {
		rc = uk_paging_page_map(pt, va + i * __PAGE_SIZE,
					(gpa + i * __PAGE_SIZE)
						| shared_gpa_boundary,
					1, attr, 0);
		if (unlikely(rc)) {
			uk_pr_err("mshv: cannot map a foreign shared page: %d\n",
				  rc);

			if (i) {
				rc = uk_paging_page_unmap(pt, va, i,
						UK_PAGING_PAGE_FLAG_KEEP_FRAMES);
				if (unlikely(rc)) {
					uk_pr_err("mshv: cannot roll back foreign mapping 0x%lx: %d; retaining %lu-page VA reservation\n",
						  (unsigned long)va, rc, pages);
					return __NULL;
				}
			}

			shared_va_release((unsigned long)idx, pages);
			return __NULL;
		}
	}

	return (void *)va;
}

/**
 * Withdraw a mapping made by mshv_map_shared_gpa() or
 * mshv_map_private_gpa().
 *
 * The frames are not this window's to give back - they belong to a device or
 * to whoever placed the page - so only the aliases and the window's own
 * address space are released.
 *
 * @param ptr
 *   The pointer that was returned
 * @param pages
 *   How many pages were mapped
 *
 * @return 0 on success, or a negative errno
 */
int mshv_unmap_gpa(void *ptr, unsigned long pages)
{
	__vaddr_t va = (__vaddr_t)ptr;
	unsigned long idx;
	int rc;

	if (unlikely(!ptr || !pages || (va & (__PAGE_SIZE - 1))))
		return -EINVAL;
	if (unlikely(va < MSHV_SHARED_VA_BASE))
		return -EINVAL;

	idx = (unsigned long)((va - MSHV_SHARED_VA_BASE) / __PAGE_SIZE);
	if (unlikely(idx >= MSHV_SHARED_VA_PAGES
		     || pages > MSHV_SHARED_VA_PAGES - idx))
		return -EINVAL;

	rc = uk_paging_page_unmap(uk_paging_pt_get_active(), va, pages,
				  UK_PAGING_PAGE_FLAG_KEEP_FRAMES);
	if (unlikely(rc)) {
		/* The window stays reserved: an address whose translation may
		 * still be live must not be handed to anyone else.
		 */
		uk_pr_err("mshv: cannot unmap 0x%lx: %d\n",
			  (unsigned long)va, rc);
		return rc;
	}

	shared_va_release(idx, pages);
	return 0;
}

/* Map a page that lives inside the guest's own encryption domain.
 *
 * A page the privileged layer beneath places for this partition is
 * private memory: it is reached at the address it is reported at, with
 * no boundary bit added. Reaching the same page through the shared
 * aperture instead yields the untranslated bytes, which never change and
 * never say anything.
 */
void *mshv_map_private_gpa(__paddr_t gpa, unsigned long pages,
			    unsigned long attr)
{
	struct uk_pagetable *pt;
	__vaddr_t va;
	long idx;
	int rc;

	UK_ASSERT(pages > 0);
	UK_ASSERT(!(gpa & (__PAGE_SIZE - 1)));

	if (unlikely(!shared_gpa_boundary)) {
		uk_pr_err("mshv: no shared aperture to map a foreign page in\n");
		return __NULL;
	}

	idx = shared_va_reserve(pages);
	if (unlikely(idx < 0)) {
		uk_pr_err("mshv: the shared window cannot fit %lu more pages\n",
			  pages);
		return __NULL;
	}

	va = MSHV_SHARED_VA_BASE + (__vaddr_t)idx * __PAGE_SIZE;
	pt = uk_paging_pt_get_active();

	for (unsigned long i = 0; i < pages; i++) {
		rc = uk_paging_page_map(pt, va + i * __PAGE_SIZE,
					gpa + i * __PAGE_SIZE,
					1, attr, 0);
		if (unlikely(rc)) {
			uk_pr_err("mshv: cannot map a foreign shared page: %d\n",
				  rc);

			if (i)
				uk_paging_page_unmap(pt, va, i,
						UK_PAGING_PAGE_FLAG_KEEP_FRAMES);

			shared_va_release((unsigned long)idx, pages);
			return __NULL;
		}
	}

	return (void *)va;
}

void *mshv_alloc_shared(__sz size, unsigned long attr)
{
	return shared_alloc(size, attr);
}

void mshv_free_shared(void *ptr)
{
	struct uk_alloc *a = uk_alloc_get_default();
	unsigned long idx;

	if (!ptr)
		return;

	for (int i = 0; i < MSHV_SHARED_MAX_ALLOCS; i++) {
		struct mshv_shared_alloc *rec = &shared_allocs[i];

		if (!rec->backing || rec->va != (__vaddr_t)ptr)
			continue;

		/* Taken from the host visible region: the frames are not the
		 * allocator's and the region is never reused, so only the
		 * mapping and the window reservation come back.
		 */
		if (rec->arena) {
			uk_paging_page_unmap(uk_paging_pt_get_active(),
					     rec->va, rec->pages,
					     UK_PAGING_PAGE_FLAG_KEEP_FRAMES);

			idx = (unsigned long)((rec->va - MSHV_SHARED_VA_BASE)
					      / __PAGE_SIZE);
			shared_va_release(idx, rec->pages);

			rec->backing = __NULL;
			rec->va = 0;
			rec->pages = 0;
			rec->arena = 0;

			return;
		}

		/* Published in place: take the pages back and hand them
		 * straight to the allocator. There is no alias to unmap and
		 * no window reservation to release, and the private and
		 * shared views are the same cache lines, so nothing needs
		 * flushing.
		 *
		 * The mechanism has to be the one publishing used, in the
		 * opposite order. Publishing changes the page state first and
		 * the mapping second; reclaiming restores the encryption bit
		 * first and validates second, because a page may not be
		 * validated for a guest that is still naming it in the clear.
		 * Nothing may touch the range in between, which is why the
		 * two steps sit next to each other here.
		 */
		if (rec->inplace) {
			int prc;

			prc = uk_paging_page_set_attr(uk_paging_pt_get_active(),
						      (__vaddr_t)rec->backing,
						      rec->pages,
						      UK_PAGING_PAGE_ATTR_PROT_RW,
						      0);
			if (unlikely(prc))
				uk_pr_err("mshv: cannot restore the encryption bit on %lu page(s): %d\n",
					  rec->pages, prc);

			prc = snp_set_page_state((__vaddr_t)rec->backing,
						 rec->pages,
						 SNP_PAGE_STATE_PRIVATE);
			if (unlikely(prc)) {
				/* The pages are in a state neither side owns
				 * outright. Returning them to the allocator
				 * would hand that state to the next caller,
				 * so they are leaked instead.
				 */
				uk_pr_err("mshv: cannot reclaim %lu page(s): %d, leaking them\n",
					  rec->pages, prc);

				rec->backing = __NULL;
				rec->va = 0;
				rec->pages = 0;
				rec->inplace = 0;

				return;
			}

			uk_free(a, rec->backing);

			rec->backing = __NULL;
			rec->va = 0;
			rec->pages = 0;
			rec->inplace = 0;

			return;
		}

		/* Symmetrically to allocation, retire the shared view before
		 * the alias goes away, so that the frames carry nothing back
		 * into the private mapping the allocator will reuse.
		 */
		shared_flush_private((void *)rec->va, rec->pages * __PAGE_SIZE);

		/* Withdraw the host's access before the frames go back to the
		 * allocator, which will hand them out as ordinary private
		 * memory to someone who does not expect to be observed.
		 */
		mshv_set_range_visibility((__vaddr_t)rec->backing,
					    rec->pages, 0);

		/* The frames belong to the backing allocation, which is
		 * released through the allocator below. The alias only ever
		 * borrowed them, and its page table entries name an address
		 * above the boundary that the frame allocator knows nothing
		 * about, so they must not be handed back here.
		 */
		uk_paging_page_unmap(uk_paging_pt_get_active(), rec->va,
				     rec->pages,
				     UK_PAGING_PAGE_FLAG_KEEP_FRAMES);

		idx = (unsigned long)((rec->va - MSHV_SHARED_VA_BASE)
				      / __PAGE_SIZE);
		shared_va_release(idx, rec->pages);

		uk_free(a, rec->backing);

		rec->backing = __NULL;
		rec->va = 0;
		rec->pages = 0;

		return;
	}

	/* Not aliased, so the pointer is the allocation itself */
	uk_free(a, ptr);
}
