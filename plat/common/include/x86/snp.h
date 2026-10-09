/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/* SEV-SNP on a partition that has no paravisor.
 *
 * With a paravisor above it, a guest is spared almost all of this: some
 * other level validates its memory, fields its #VC exceptions and holds
 * the keys that talk to the security processor. Running without one, the
 * guest is the highest privilege level inside its own encryption domain
 * and every one of those duties falls to it.
 *
 * Three of them are described here. Memory has to be validated before it
 * can be touched, which the guest does itself with PVALIDATE rather than
 * by asking anyone. Anything the host must be able to read has to be
 * moved out of the encryption domain first, which is a negotiation with
 * the hypervisor and not merely a page-table edit. And the key that
 * authenticates requests to the security processor is not handed over on
 * request - it was measured into a page at launch, and the guest reads it
 * from there.
 */

#ifndef __UK_PLAT_COMMON_X86_SNP_H__
#define __UK_PLAT_COMMON_X86_SNP_H__

/* Guest physical address of the GHCB. The page is shared with the host, so it
 * cannot live in the image: the image is mapped with 2 MiB pages and clearing
 * the C-bit for a single page would mean splitting one. The first 2 MiB is
 * already mapped with 4 KiB pages and holds nothing of ours, so a page is
 * taken from there instead.
 *
 * The page must stay out of the frame allocator and keep its 1:1 mapping: it
 * is shared in the RMP, and any private access to it faults.
 */
#define SNP_GHCB_GPA			0x100000
#define SNP_GHCB_SIZE			0x1000

#ifndef __ASSEMBLY__

#include <uk/arch/types.h>
#include <uk/essentials.h>

static inline void snp_vmgexit(void)
{
	__asm__ __volatile__("rep; vmmcall" : : : "memory");
}

/* Tells the guest what the hardware is doing on its behalf. Bit 2 is the
 * one that matters here: it distinguishes SNP, where memory carries
 * ownership state the guest must maintain, from plain encryption, where
 * it does not.
 */
#define SNP_MSR_SEV_STATUS		0xc0010131
#define SNP_SEV_STATUS_SEV		(1UL << 0)
#define SNP_SEV_STATUS_SEV_ES		(1UL << 1)
#define SNP_SEV_STATUS_SEV_SNP		(1UL << 2)
#define SNP_SEV_STATUS_VTOM		(1UL << 3)
#define SNP_SEV_STATUS_REFLECT_VC	(1UL << 4)
#define SNP_SEV_STATUS_RESTRICT_INJ	(1UL << 5)
#define SNP_SEV_STATUS_ALT_INJ		(1UL << 6)
#define SNP_SEV_STATUS_DEBUG_SWAP	(1UL << 7)
#define SNP_SEV_STATUS_SECURE_AVIC	(1UL << 18)

/* Which page-table bit marks a page as encrypted. This is a property of
 * the part, reported rather than assumed, because building page tables
 * around the wrong bit yields memory the guest can address but not read.
 */
#define SNP_CPUID_SEV_INFO		0x8000001f
#define SNP_CPUID_SEV_INFO_CBIT_MASK	0x3f

/* The GHCB's own address register, and the request codes that can be sent
 * through it before a GHCB page exists. Establishing a shared page is
 * itself an operation that needs the hypervisor, so the first exchanges
 * travel in this register alone.
 */
#define SNP_MSR_GHCB			0xc0010130
#define SNP_GHCB_MSR_INFO_MASK		0xfffUL
#define SNP_GHCB_MSR_GPA_REQ		0x012
#define SNP_GHCB_MSR_GPA_RESP		0x013
#define SNP_GHCB_MSR_PSC_REQ		0x014
#define SNP_GHCB_MSR_PSC_RESP		0x015
#define SNP_GHCB_MSR_TERM_REQ		0x100

/* Which side of the encryption boundary a page sits on. "Private" is the
 * guest's own memory, unreadable by the host; "shared" is the exception
 * made for buffers the host has to see, such as the rings a synthetic
 * device is driven through.
 */
#define SNP_PAGE_STATE_PRIVATE		1
#define SNP_PAGE_STATE_SHARED		2

/* PVALIDATE reports this when a page is already in the state asked for.
 * Requesting a state a page already holds is not an error - it is the
 * ordinary outcome of validating a range whose beginning the loader has
 * already covered - so it is told apart from a genuine refusal.
 */
#define SNP_PVALIDATE_FAIL_INPUT	1
#define SNP_PVALIDATE_FAIL_SIZE_MISMATCH 6
#define SNP_PVALIDATE_NO_CHANGE		255

/* How the launch process leaves the secrets page behind.
 *
 * The page is not at a fixed address and is not something the guest may
 * choose, because its contents are measured: a guest that read a key from
 * a page of its own choosing would be reading whatever the host put
 * there. The trail starts in the boot parameters, which name a blob, and
 * the blob names the page.
 */
#define SNP_SETUP_DATA_CC_BLOB		7
#define SNP_CC_BLOB_MAGIC		0x45444d41 /* 'AMDE' */

struct snp_setup_data_hdr {
	__u64 next;
	__u32 type;
	__u32 len;
} __packed;

struct snp_cc_setup_data {
	struct snp_setup_data_hdr header;
	__u32 cc_blob_address;
} __packed;

struct snp_cc_blob_info {
	__u32 magic;
	__u16 version;
	__u16 reserved;
	__u64 secrets_phys;
	__u32 secrets_len;
	__u32 reserved1;
	__u64 cpuid_phys;
	__u32 cpuid_len;
	__u32 reserved2;
} __packed;

#define SNP_VMPCK_LEN			32

/* The sequence numbers live beside the keys because both sides have to
 * agree on them. A number may never be reused under the same key, so it
 * is carried forward from whatever the launch process left rather than
 * restarted, and it is written back after every message.
 */
struct snp_secrets_os_area {
	__u32 msg_seqno_0;
	__u32 msg_seqno_1;
	__u32 msg_seqno_2;
	__u32 msg_seqno_3;
	__u64 ap_jump_table_pa;
	__u8 rsvd[40];
	__u8 sev_es_reserved[32];
} __packed;

struct snp_secrets_page {
	__u32 version;
	__u32 imien_rsvd;
	__u32 fms;
	__u32 rsvd2;
	__u8 gosvw[16];
	__u8 vmpck[4][SNP_VMPCK_LEN];
	struct snp_secrets_os_area os_area;
	__u8 vmsa_tweak_bitmap[64];
} __packed;

/* Whether this guest is running under SNP with no paravisor above it,
 * which is what makes all of the above the guest's own responsibility.
 */
int snp_no_paravisor(void);
__u64 snp_sev_status_raw(void);

/* The GHCB protocol version the guest's early startup settled on with the
 * hypervisor. Zero until that exchange has happened.
 *
 * The exchange, and the variable holding its result, belong to the early
 * console. A guest built without it never performs one.
 */
#if CONFIG_X86_SNP_EARLY_CON
extern volatile __u16 snp_dbg_version;

/* Matches the assembly helper's SysV %rax/%rdx return convention.
 * Callers must disable interrupts while using the shared GHCB.
 */
struct snp_ghcb_msr_result {
	__u64 value;
	__u64 completed;
};

struct snp_ghcb_msr_result snp_ghcb_msr(__u32 write, __u32 msr, __u64 value);

static inline __u16 snp_ghcb_version(void)
{
	return snp_dbg_version;
}
#else
static inline __u16 snp_ghcb_version(void)
{
	return 0;
}
#endif /* CONFIG_X86_SNP_EARLY_CON */

/* The page-table bit that marks memory as encrypted on this part. */
__u64 snp_c_bit_mask(void);

/* Hand over the key that authenticates requests to the security
 * processor, read from the measured secrets page, together with the index
 * naming which key it is. Returns 0, or a negative error if this guest
 * has no secrets page to read.
 */
int snp_secrets_vmpck(__u8 key[SNP_VMPCK_LEN], __u8 *index);

/* Take the message sequence number to use for the next request, and
 * record it as spent in the same step.
 *
 * Two numbers are spent per exchange, not one: the firmware answers under
 * the number following the request's, so both sides step by two. They are
 * spent before the request goes out rather than after a reply arrives,
 * because what makes a number unusable is the firmware having seen it,
 * which the guest cannot take back and cannot always observe.
 */
int snp_secrets_seqno_reserve(__u8 index, __u64 *seqno);

/* Record where the boot parameters left the trail to the secrets page.
 * Called from the boot path, before the page that holds them may be
 * reused for anything else.
 */
void snp_note_setup_data(__u64 setup_data_pa);

/* Bring a range of virtually contiguous pages into the state named, both
 * telling the hypervisor and recording the change in the RMP. Returns 0,
 * or a negative error if the hypervisor declined.
 *
 * The range is named by virtual address alone. PVALIDATE names its page that
 * way and walks the guest's own page tables to reach the frame; the physical
 * address the hypervisor is given is read back out of the same mapping, one
 * page at a time, because a run of virtual pages is not in general a run of
 * physical ones.
 */
int snp_set_page_state(__vaddr_t va, unsigned long pages, int state);

#endif /* !__ASSEMBLY__ */

#endif /* __UK_PLAT_COMMON_X86_SNP_H__ */
