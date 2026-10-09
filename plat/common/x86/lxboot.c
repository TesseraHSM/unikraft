/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2022, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <uk/essentials.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/paging.h>
#include <uk/pm.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/lcpu.h>
#include <uk/plat/common/memory.h>
#include <uk/plat/common/sections.h>
#include <x86/lxboot.h>
#include <x86/snp.h>

#define lxboot_crash(rc, msg, ...) uk_pm_syscrash()

void _ukplat_entry(struct ukplat_bootinfo *bi);

static void
lxboot_init_cmdline(struct ukplat_bootinfo *bi, struct lxboot_params *bp)
{
	__u64 cmdline_addr;
	__sz cmdline_size;

	cmdline_addr = bp->ext_cmd_line_ptr;
	cmdline_addr <<= 32;
	cmdline_addr |= bp->hdr.cmd_line_ptr;

	cmdline_size = bp->hdr.cmd_line_size;

	if (unlikely(cmdline_addr == 0))
		lxboot_crash(-EINVAL, "Command line address is zero");

	if (cmdline_size == 0)
		return;

	bi->cmdline = cmdline_addr;
	bi->cmdline_len = cmdline_size;
}

static void
lxboot_init_initrd(struct ukplat_bootinfo *bi, struct lxboot_params *bp)
{
	__u64 initrd_addr;
	__sz initrd_size;
	struct ukplat_memregion_desc mrd = {0};
	int rc;

	initrd_addr = bp->ext_ramdisk_image;
	initrd_addr <<= 32;
	initrd_addr |= bp->hdr.ramdisk_image;

	initrd_size = bp->ext_ramdisk_size;
	initrd_size <<= 32;
	initrd_size |= bp->hdr.ramdisk_size;

	if (initrd_addr == 0 || initrd_size == 0)
		return;

	mrd.pbase = UK_PAGING_PAGE_ALIGN_DOWN(initrd_addr);
	mrd.vbase = mrd.pbase;
	mrd.pg_off = initrd_addr - mrd.pbase;
	mrd.len = initrd_size;
	mrd.type = UKPLAT_MEMRT_INITRD;
	mrd.pg_count = UK_PAGING_PAGE_COUNT(mrd.pg_off + initrd_size);
	mrd.flags = UKPLAT_MEMRF_READ;
#ifdef CONFIG_UKPLAT_MEMRNAME
	memcpy(mrd.name, "initrd", sizeof("initrd"));
#endif /* CONFIG_UKPLAT_MEMRNAME */

	rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
	if (unlikely(rc < 0))
		lxboot_crash(rc, "Unable to add ram mapping");
}

/* Where the IGVM loader publishes the VM's real memory map. This must match
 * MEMORY_MAP_GPA in igvmfilegen's Linux-direct generator; it is the one number
 * about memory the image is allowed to know.
 */
#define LXBOOT_IGVM_MEMMAP_GPA		0x200000UL
#define LXBOOT_IGVM_MEMMAP_PAGES	2
#define LXBOOT_IGVM_PAGE_SIZE		0x1000ULL

/* IgvmFileFormat.h:557. The page numbers are always 4 KiB, independent of the
 * paging granularity the guest goes on to use.
 */
struct lxboot_igvm_memmap_entry {
	__u64 start_pfn;
	__u64 pages;
	__u16 type;
	__u16 flags;
	__u32 reserved;
} __packed;

#define LXBOOT_IGVM_MEMMAP_TYPE_MEMORY	0

#define LXBOOT_IGVM_MEMMAP_MAX_ENTRIES					\
	((LXBOOT_IGVM_MEMMAP_PAGES * LXBOOT_IGVM_PAGE_SIZE)		\
	 / sizeof(struct lxboot_igvm_memmap_entry))

#ifdef CONFIG_MSHV_IGVM_MEMMAP
/* Adopt the memory map the loader wrote, if it wrote one.
 *
 * The e820 table carried in boot params describes the RAM named in the IGVM
 * manifest at the time the file was generated. An image that ships to an
 * unknown fleet cannot know that number, so it must not trust it. MSHV
 * fills a parameter area with the VM's actual topology instead
 * (WorkerHclLoader.cpp:BuildHclMemoryMap), which is authoritative and costs
 * nothing to read.
 *
 * Anything that is not conventional memory becomes a reserved region. That is
 * what keeps the VTL2 range holding the return trampoline
 * (IGVM_VHF_MEMORY_MAP_ENTRY_TYPE_VTL2_PROTECTABLE) out of the allocator
 * without the image having to know where it is.
 *
 * Returns the number of entries adopted, or 0 if the area is empty, in which
 * case the caller falls back to the e820 table.
 */
static int
lxboot_init_mem_igvm(struct ukplat_bootinfo *bi)
{
	const struct lxboot_igvm_memmap_entry *map =
		(const struct lxboot_igvm_memmap_entry *)
			LXBOOT_IGVM_MEMMAP_GPA;
	struct ukplat_memregion_desc mrd = {0};
	__u64 start, end;
	int rc, i, used = 0;

	for (i = 0; i < (int)LXBOOT_IGVM_MEMMAP_MAX_ENTRIES; i++) {
		/* A zero-length entry terminates the list. An area the loader
		 * never touched therefore reads as "no entries" on the first
		 * pass, which is exactly the fallback signal.
		 */
		if (map[i].pages == 0)
			break;

		/* Same kludge as the e820 path: address zero is not handled
		 * well by the platform code.
		 */
		start = MAX(map[i].start_pfn * LXBOOT_IGVM_PAGE_SIZE,
			    UK_PAGING_PAGE_SIZE);
		end = (map[i].start_pfn + map[i].pages) * LXBOOT_IGVM_PAGE_SIZE;

		used++;

		if (end <= start)
			continue;

		mrd.pbase = UK_PAGING_PAGE_ALIGN_DOWN(start);
		mrd.vbase = mrd.pbase; /* 1:1 mapping */
		mrd.pg_off = start - mrd.pbase;
		mrd.len = end - start;
		mrd.pg_count = UK_PAGING_PAGE_COUNT(mrd.pg_off + mrd.len);

		if (map[i].type == LXBOOT_IGVM_MEMMAP_TYPE_MEMORY) {
			mrd.type = UKPLAT_MEMRT_FREE;
			mrd.flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;
			mrd.len = UK_PAGING_PAGE_ALIGN_UP(mrd.len + mrd.pg_off);
		} else {
			mrd.type = UKPLAT_MEMRT_RESERVED;
			mrd.flags = UKPLAT_MEMRF_READ;
		}

		rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
		if (unlikely(rc < 0))
			lxboot_crash(rc, "Unable to add ram mapping");
	}

	return used;
}
#else /* !CONFIG_MSHV_IGVM_MEMMAP */
static int
lxboot_init_mem_igvm(struct ukplat_bootinfo *bi __unused)
{
	return 0;
}
#endif /* !CONFIG_MSHV_IGVM_MEMMAP */

static void
lxboot_init_mem(struct ukplat_bootinfo *bi, struct lxboot_params *bp)
{
	struct ukplat_memregion_desc mrd = {0};
	struct lxboot_e820_entry *entry;
	__u64 start, end;
	int rc;
	__s8 i;

	/* The loader's map wins when present; the built-in e820 describes only
	 * whatever RAM the manifest happened to name.
	 */
	if (lxboot_init_mem_igvm(bi) > 0)
		goto mem_done;

	for (i = 0; i < bp->e820_entries; i++) {
		entry = &bp->e820_table[i];

		/* Kludge: Don't add zero-page, because the platform code does
		 * not handle address zero well.
		 */
		start = MAX(entry->addr, UK_PAGING_PAGE_SIZE);
		end = entry->addr + entry->size;

		if (end <= start)
			continue;

		mrd.pbase = UK_PAGING_PAGE_ALIGN_DOWN(start);
		mrd.vbase = mrd.pbase; /* 1:1 mapping */
		mrd.pg_off = start - mrd.pbase;
		mrd.len = end - start;
		mrd.pg_count = UK_PAGING_PAGE_COUNT(mrd.pg_off + mrd.len);

		if (entry->type == LXBOOT_E820_TYPE_RAM) {
			mrd.type = UKPLAT_MEMRT_FREE;
			mrd.flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE;

			/* Free memory regions have
			 * mrd.len == mrd.pg_count * UK_PAGING_PAGE_SIZE
			 */
			mrd.len = UK_PAGING_PAGE_ALIGN_UP(mrd.len + mrd.pg_off);
		} else {
			mrd.type = UKPLAT_MEMRT_RESERVED;
			mrd.flags = UKPLAT_MEMRF_READ;

			/* We assume that reserved regions cannot
			 * overlap with loaded modules.
			 */
		}

		rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
		if (unlikely(rc < 0))
			lxboot_crash(rc, "Unable to add ram mapping");

	}

mem_done:
	rc = ukplat_memregion_list_insert_legacy_hi_mem(&bi->mrds);
	if (unlikely(rc < 0))
		lxboot_crash(rc,
			     "Failed to insert legacy high memory region\n");

#ifdef CONFIG_X86_SNP_VC_EARLY
	/* The GHCB page is plain guest RAM as far as the loader's e820 map is
	 * concerned, so it is reported free. It is shared with the host in the
	 * RMP, though, and any private access to it faults, so it must never
	 * reach the frame allocator, and it must keep its 1:1 mapping when
	 * ukplat_mem_init() replaces the boot page table -- both the debug
	 * console and the #VC handler talk through it.
	 */
	memset(&mrd, 0, sizeof(mrd));
	mrd.pbase = SNP_GHCB_GPA;
	mrd.vbase = mrd.pbase;
	mrd.pg_off = 0;
	mrd.len = SNP_GHCB_SIZE;
	mrd.pg_count = UK_PAGING_PAGE_COUNT(mrd.len);
	mrd.type = UKPLAT_MEMRT_RESERVED;
	mrd.flags = UKPLAT_MEMRF_READ | UKPLAT_MEMRF_WRITE |
		    UKPLAT_MEMRF_SHARED;
#ifdef CONFIG_UKPLAT_MEMRNAME
	memcpy(mrd.name, "ghcb", sizeof("ghcb"));
#endif /* CONFIG_UKPLAT_MEMRNAME */

	rc = ukplat_memregion_list_insert(&bi->mrds, &mrd);
	if (unlikely(rc < 0))
		lxboot_crash(rc, "Unable to reserve the GHCB page");
#endif /* CONFIG_X86_SNP_VC_EARLY */

}

void lxboot_entry(struct lxboot_params *bp)
{
	struct ukplat_bootinfo *bi;

	bi = ukplat_bootinfo_get();
	if (unlikely(!bi))
		lxboot_crash(-EINVAL, "Incompatible or corrupted bootinfo");

	/* MSHV's Linux direct loader builds the boot parameters itself when
	 * it loads an ELF kernel, and leaves the setup header zeroed. A zero
	 * header magic is therefore a valid arrival, not a corrupt one.
	 */
	if (unlikely(bp->hdr.header != 0 && bp->hdr.boot_flag != 0xAA55))
		lxboot_crash(-EINVAL, "Invalid magic number");

	/* The trail to the secrets page starts here and is followed later.
	 * The boot parameters sit in memory the guest may reuse once it is
	 * running, so the address is taken while it is still valid.
	 */
	snp_note_setup_data(bp->hdr.setup_data);

	lxboot_init_cmdline(bi, bp);

	lxboot_init_initrd(bi, bp);

	lxboot_init_mem(bi, bp);

	memcpy(bi->bootprotocol, "lxboot", sizeof("lxboot"));

	_ukplat_entry(bi);
}
