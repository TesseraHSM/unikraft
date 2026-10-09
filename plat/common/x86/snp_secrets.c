/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/* Standing on its own inside an SNP partition.
 *
 * See x86/snp.h for what a guest without a paravisor has to do for
 * itself. This file does three of those things: it works out whether the
 * guest is in that position at all, it maintains the ownership state of
 * its memory, and it recovers the key that lets it speak to the security
 * processor.
 *
 * The order matters more than it looks. The key is read from a page whose
 * address arrives in the boot parameters, and the boot parameters sit in
 * memory that the guest is free to reuse once it is running. The address
 * is therefore noted during boot and the page read later, rather than
 * finding the page on demand and discovering the trail has been paved
 * over.
 */

#include <string.h>
#include <errno.h>

#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/lcpu/except.h>
#include <uk/paging.h>
#include <uk/print.h>

#include <x86/snp.h>

static __u64 snp_setup_data_pa;
static int snp_status_read;
static __u64 snp_sev_status;
static __u64 snp_cbit_mask;

static const struct snp_secrets_page *snp_secrets;
static int snp_secrets_searched;

/* Which of the four keys belongs to this guest. Without a paravisor the
 * guest occupies the most privileged level in its own domain, and the key
 * for that level is the first.
 */
#define SNP_SELF_VMPL			0

/* The architectural helpers split a model-specific register into halves.
 * Every register touched here is naturally a single 64-bit quantity - an
 * address, or a status word - so they are joined once rather than at each
 * use.
 */
static inline __u64 snp_rdmsr(unsigned int msr)
{
	__u32 lo, hi;

	uk_arch_x86_64_rdmsr(msr, &lo, &hi);

	return ((__u64)hi << 32) | lo;
}

static inline void snp_wrmsr(unsigned int msr, __u64 val)
{
	uk_arch_x86_64_wrmsr(msr, (__u32)val, (__u32)(val >> 32));
}

static void snp_read_status(void)
{
	__u32 eax, ebx, ecx, edx;

	snp_status_read = 1;
	snp_sev_status = snp_rdmsr(SNP_MSR_SEV_STATUS);

	if (!(snp_sev_status & SNP_SEV_STATUS_SEV_SNP))
		return;

#if !CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	if (snp_sev_status & SNP_SEV_STATUS_RESTRICT_INJ)
		UK_CRASH("Restricted-injection launch requires guest RI support\n");
#endif

	/* The encryption bit is reported by the part rather than fixed by
	 * the architecture, so it is read once and kept.
	 */
	uk_arch_x86_64_cpuid(SNP_CPUID_SEV_INFO, 0, &eax, &ebx, &ecx, &edx);
	snp_cbit_mask = 1ULL << (ebx & SNP_CPUID_SEV_INFO_CBIT_MASK);

	uk_pr_info("snp: hardware isolation is active; memory is encrypted at bit %u\n",
		   (unsigned int)(ebx & SNP_CPUID_SEV_INFO_CBIT_MASK));
}

int snp_no_paravisor(void)
{
	if (!snp_status_read)
		snp_read_status();

	/* A guest underneath a paravisor does not see SNP in this register
	 * at all - the paravisor owns the isolation and presents an
	 * ordinary partition downwards. Seeing it set is therefore the same
	 * statement as being alone at the top.
	 */
	return !!(snp_sev_status & SNP_SEV_STATUS_SEV_SNP);
}

/* The SEV_STATUS MSR mirrors the SEV_FEATURES the VMSA was launched with, so
 * this is the guest's own view of what the launch actually asked for. The two
 * injection bits decide whether the hypervisor is allowed to deliver anything
 * to us at all.
 */
__u64 snp_sev_status_raw(void)
{
	if (!snp_status_read)
		snp_read_status();

	return snp_sev_status;
}

__u64 snp_c_bit_mask(void)
{
	if (!snp_status_read)
		snp_read_status();

	return snp_cbit_mask;
}

void snp_note_setup_data(__u64 setup_data_pa)
{
	snp_setup_data_pa = setup_data_pa;
}

/* Walk the chain the boot parameters start, looking for the entry that
 * names the confidential-computing blob. The chain is host-supplied, so
 * it is walked defensively: a corrupt or circular list must end the search
 * rather than the guest.
 */
static const struct snp_cc_blob_info *snp_find_cc_blob(void)
{
	const struct snp_setup_data_hdr *hdr;
	const struct snp_cc_blob_info *blob;
	const struct snp_cc_setup_data *cc;
	unsigned int hops = 0;
	__u64 pa = snp_setup_data_pa;

	while (pa && hops++ < 64) {
		hdr = (const struct snp_setup_data_hdr *)(__uptr)pa;

		if (hdr->type == SNP_SETUP_DATA_CC_BLOB &&
		    hdr->len >= sizeof(__u32)) {
			cc = (const struct snp_cc_setup_data *)hdr;
			blob = (const struct snp_cc_blob_info *)
				(__uptr)(__u64)cc->cc_blob_address;

			if (blob && blob->magic == SNP_CC_BLOB_MAGIC)
				return blob;

			uk_pr_warn("snp: the boot parameters name a blob that does not identify itself as one\n");
			return __NULL;
		}

		pa = hdr->next;
	}

	return __NULL;
}

static void snp_find_secrets(void)
{
	const struct snp_cc_blob_info *blob;

	snp_secrets_searched = 1;

	if (!snp_no_paravisor())
		return;

	if (!snp_setup_data_pa) {
		uk_pr_warn("snp: the boot parameters carried no confidential-computing data, so there is no secrets page to find\n");
		return;
	}

	blob = snp_find_cc_blob();
	if (!blob)
		return;

	if (blob->secrets_len < sizeof(struct snp_secrets_page)) {
		uk_pr_warn("snp: the secrets page named is too short to be one (%u bytes)\n",
			   (unsigned int)blob->secrets_len);
		return;
	}

	snp_secrets = (const struct snp_secrets_page *)
		(__uptr)blob->secrets_phys;

	uk_pr_info("snp: the launch process left a secrets page at 0x%lx\n",
		   (unsigned long)blob->secrets_phys);
}

/* An untouched page reads as zeroes and so would a key of all zeroes. The
 * two mean different things - one says the launch process wrote nothing
 * here, the other would be a usable key - so they are told apart rather
 * than both accepted.
 */
static int snp_key_present(const __u8 *key)
{
	__u8 seen = 0;

	for (unsigned int i = 0; i < SNP_VMPCK_LEN; i++)
		seen |= key[i];

	return seen != 0;
}

int snp_secrets_vmpck(__u8 key[SNP_VMPCK_LEN], __u8 *index)
{
	if (!snp_secrets_searched)
		snp_find_secrets();

	if (!snp_secrets)
		return -ENOTSUP;

	if (!snp_key_present(snp_secrets->vmpck[SNP_SELF_VMPL])) {
		uk_pr_warn("snp: the secrets page holds no key for this level\n");
		return -ENOENT;
	}

	memcpy(key, snp_secrets->vmpck[SNP_SELF_VMPL], SNP_VMPCK_LEN);

	if (index)
		*index = SNP_SELF_VMPL;

	return 0;
}

static volatile __u32 *snp_seqno_slot(__u8 index)
{
	/* The counters are reached by offset rather than by taking the
	 * address of a field: the page is a packed layout fixed by the
	 * firmware, and a pointer into it carries no alignment guarantee
	 * the compiler is willing to assume.
	 */
	return (volatile __u32 *)((__u8 *)snp_secrets
				  + __offsetof(struct snp_secrets_page, os_area)
				  + index * sizeof(__u32));
}

int snp_secrets_seqno_reserve(__u8 index, __u64 *seqno)
{
	volatile __u32 *slot;
	__u32 last;

	if (unlikely(!seqno || index > 3))
		return -EINVAL;

	if (!snp_secrets_searched)
		snp_find_secrets();

	if (!snp_secrets)
		return -ENOTSUP;

	slot = snp_seqno_slot(index);
	last = *slot;

	/* Running out is not recoverable. A number may not authenticate a
	 * second message under the same key, and the guest cannot mint a
	 * new key - only another launch can.
	 */
	if (unlikely(last + 2 < last)) {
		uk_pr_err("snp: the message counter for key %u has wrapped; this key can no longer be used\n",
			  (unsigned int)index);
		return -EOVERFLOW;
	}

	/* Starting over at one would be the obvious thing to do and is
	 * exactly wrong: the firmware remembers what it has accepted under
	 * this key and refuses to see any of it again. The count carries on
	 * from whatever the launch process left behind.
	 */
	*seqno = (__u64)last + 1;
	*slot = last + 2;

	return 0;
}

/* Tell the RMP that a page may be touched at this level.
 *
 * PVALIDATE reports two different kinds of outcome. A non-zero return is a
 * refusal by the firmware. The carry flag is separate: it says the RMP entry
 * already held the state being asked for, so nothing was written.
 *
 * That second outcome is only ever benign in one direction, and the asymmetry
 * matters. Withdrawing validation from a page that is already invalid leaves
 * the guest holding no claim, which is where it wanted to end up. Validating a
 * page that is already validated means the guest's idea of what it owns has
 * diverged from the RMP, which is exactly the shape of a replayed-page attack,
 * so Linux terminates the guest on it and so does this. The caller therefore
 * gets the no-change result reported distinctly and decides.
 */
static int snp_pvalidate_page(__vaddr_t va, int validate)
{
	__u8 carry;
	unsigned int rc;

	asm volatile("pvalidate\n\t"
		     "setc %[carry]\n\t"
		     : "=a"(rc), [carry] "=rm"(carry)
		     : "a"(va), "c"(0), "d"(validate)
		     : "memory", "cc");

	if (rc == 0 && carry)
		return SNP_PVALIDATE_NO_CHANGE;

	return (int)rc;
}

/* Ask the hypervisor to move pages across the encryption boundary.
 *
 * This is the short form of the request, carried entirely in the GHCB's
 * address register. It handles one page per exchange, which is enough for
 * the handful of buffers a synthetic device needs and avoids depending on
 * a GHCB page that may not exist yet - the page used to make longer
 * requests is itself established this way.
 *
 * The register is a single mailbox shared with everything else that talks to
 * the hypervisor, the #VC handler above all: an emulated instruction anywhere
 * in an interrupt handler will put its own request there. The sequence below
 * spans four accesses to it and cannot survive that, so it runs with
 * interrupts held off. The reference guest for this platform does the same
 * for the same reason.
 */
static int snp_msr_psc_page(__paddr_t pa, int state)
{
	unsigned long flags;
	__u64 saved, req, resp;

	req = (pa & ~(__u64)(__PAGE_SIZE - 1)) |
	      ((__u64)state << 52) | SNP_GHCB_MSR_PSC_REQ;

	flags = uk_lcpu_save_irqf();

	saved = snp_rdmsr(SNP_MSR_GHCB);

	snp_wrmsr(SNP_MSR_GHCB, req);
	asm volatile("rep; vmmcall" ::: "memory");
	resp = snp_rdmsr(SNP_MSR_GHCB);

	snp_wrmsr(SNP_MSR_GHCB, saved);

	uk_lcpu_restore_irqf(flags);

	if ((resp & SNP_GHCB_MSR_INFO_MASK) != SNP_GHCB_MSR_PSC_RESP)
		return -EIO;

	/* The upper half carries the error code; anything non-zero means
	 * the hypervisor declined the move.
	 */
	if (resp >> 32)
		return -EIO;

	return 0;
}

int snp_set_page_state(__vaddr_t va, unsigned long pages, int state)
{
	__vaddr_t vaddr;
	__paddr_t pa;
	int rc;

	if (!snp_no_paravisor())
		return 0;

	for (unsigned long i = 0; i < pages; i++) {
		vaddr = va + i * __PAGE_SIZE;

		/* PVALIDATE names its page by virtual address and the page
		 * state change names the same page by physical address, so
		 * the two have to describe one page. Nothing here may assume
		 * that a run of virtual pages is a run of physical ones: the
		 * heap these buffers come from is assembled out of whatever
		 * frames were free, and a thirty-two page ring buffer is
		 * routinely scattered across memory. Deriving each address
		 * from the mapping is the only way the two agree; computing
		 * one from a base would withdraw the guest's claim on one
		 * page and hand the host a different one, which reads as
		 * memory corruption and surfaces much later as a triple
		 * fault.
		 */
		pa = uk_paging_virt_to_phys(vaddr);

		/* Order matters and is not symmetric. A page leaving the
		 * guest's domain must lose its validation first, or the
		 * guest would be left holding a claim on memory the host
		 * has been given. A page arriving must be moved first and
		 * validated after, for the same reason in reverse.
		 */
		if (state == SNP_PAGE_STATE_SHARED) {
			rc = snp_pvalidate_page(vaddr, 0);
			if (unlikely(rc && rc != SNP_PVALIDATE_NO_CHANGE)) {
				uk_pr_err("snp: could not withdraw validation of 0x%lx (%d)\n",
					  (unsigned long)pa, rc);
				return -EIO;
			}
		}

		rc = snp_msr_psc_page(pa, state);
		if (unlikely(rc)) {
			uk_pr_err("snp: the hypervisor declined to move 0x%lx %s\n",
				  (unsigned long)pa,
				  state == SNP_PAGE_STATE_SHARED
					  ? "out of the guest's memory"
					  : "into the guest's memory");
			return rc;
		}

		if (state == SNP_PAGE_STATE_PRIVATE) {
			rc = snp_pvalidate_page(vaddr, 1);

			/* Deliberately stricter than the withdrawal above.
			 * A page that was already validated is a page the
			 * guest believed it had given away, so the RMP and
			 * the guest disagree about who owns it.
			 */
			if (unlikely(rc == SNP_PVALIDATE_NO_CHANGE)) {
				uk_pr_crit("snp: 0x%lx was already validated; the RMP disagrees with this guest\n",
					   (unsigned long)pa);
				return -EIO;
			}

			if (unlikely(rc)) {
				uk_pr_err("snp: could not validate 0x%lx (%d)\n",
					  (unsigned long)pa, rc);
				return -EIO;
			}
		}
	}

	return 0;
}
