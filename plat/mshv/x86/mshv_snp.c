/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/* Talking to the security processor from inside an isolated partition.
 *
 * A guest that owns its own partition reaches the firmware the way the
 * hardware specification describes: the launch process leaves a secrets
 * page among the firmware tables, the guest reads its communication key
 * out of that page, and it authenticates every request to the security
 * processor under that key. None of it is optional - the processor will
 * not answer a request it cannot authenticate.
 *
 * Underneath a paravisor none of that is present. The firmware tables
 * carry no secrets page, so there is no key to read and no sequence number
 * to continue from, and this is not an oversight: the page belongs to the
 * privilege level the paravisor occupies, not to the guest. What the guest
 * gets instead is a way to ask for the key, answered by the paravisor
 * alone - the hypervisor declines to implement that request precisely so
 * that the key cannot be made to leave the guest. The caller does not say
 * which key it wants; the paravisor derives that from which level asked.
 *
 * Both doors are shut unless the hypervisor is willing to carry a request
 * from a level below the paravisor's, and that willingness is announced in
 * CPUID. Where it is absent, asking for the key is refused and making the
 * request faults, so the announcement is worth reading before either - but
 * it is not worth trusting on its own. The two doors and the announcement
 * were built at different times, and there is a window in which the doors
 * stand open while the announcement is silent. Only knocking settles it.
 */

#include <string.h>
#include <errno.h>

#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/essentials.h>
#include <uk/print.h>
#include <uk/paging.h>
#include <uk/plat/snp.h>

#include <uk/plat/mshv.h>
#include <x86/snp.h>

/* Where the paravisor is asked to write the key. It must not be a page the
 * host can read: the whole reason this request goes to the paravisor
 * rather than the hypervisor is that the key stays inside the guest, and
 * naming a shared page here would hand it out at the last step. Private
 * memory is no obstacle to the answer - the paravisor sits above this
 * guest and can write to it.
 */
static __u8 __align(__PAGE_SIZE) vmpck_page[__PAGE_SIZE];

static __u8 snp_vmpck[UK_SNP_VMPCK_LEN];
static __u8 snp_vmpck_index;
static int snp_have_vmpck;
static int snp_asked;

/* Whether the hypervisor says a level below the paravisor may ask the
 * security processor anything at all.
 */
static int snp_lower_vtl_requests(void)
{
	__u32 eax, ebx, ecx, edx;

	if (mshv_max_cpuid_leaf() < MSHV_CPUID_ENLIGHTENMENTS)
		return 0;

	uk_arch_x86_64_cpuid(MSHV_CPUID_ENLIGHTENMENTS, 0,
			     &eax, &ebx, &ecx, &edx);

	uk_pr_info("mshv: the enlightenments this partition is offered read 0x%08x\n",
		   (unsigned int)eax);

	return !!(eax & MSHV_ENLIGHTENMENT_LOWER_VTL_GUEST_REQUEST);
}

/* Say whether a key arrived without saying what it is. An untouched page
 * reads as zeroes, and so would a key of all zeroes, so the two have to be
 * told apart: a success reported over an untouched page means the answer
 * went somewhere this guest is not looking, which is a different fault
 * from being refused and needs a different fix.
 */
static int key_looks_present(const __u8 *key)
{
	__u8 seen = 0;

	for (unsigned int i = 0; i < UK_SNP_VMPCK_LEN; i++)
		seen |= key[i];

	return seen != 0;
}

static void snp_ask_for_key(void)
{
	__paddr_t out_pa;
	__u64 blank = 0;
	__u64 status;
	const char *why;

	snp_asked = 1;

	if (!mshv_isolated()) {
		uk_pr_info("mshv: not an isolated partition, so there is no security processor to ask\n");
		return;
	}

	uk_pr_info("mshv: guest requests from below the paravisor are %s\n",
		   snp_lower_vtl_requests() ? "offered" : "not offered");

	memset(vmpck_page, 0, sizeof(vmpck_page));
	out_pa = (__paddr_t)uk_paging_virt_to_phys((__vaddr_t)vmpck_page);

	/* Keep the key's destination private. Use the negotiated GHCB path:
	 * a bare VMMCALL for this optional service can inject #GP instead of
	 * returning an unsupported-call status on SNP EFI guests.
	 */
	if (!mshv_ghcb_ready()) {
		uk_pr_warn("mshv: no negotiated GHCB path for the optional SNP key request\n");
		goto out;
	}
	status = mshv_ghcb_hypercall_out(HV_HYPERCALL_GET_SNP_VMPCK,
					   &blank, 0, out_pa)
		 & HV_HYPERCALL_STATUS_MASK;

	if (status == HV_STATUS_SUCCESS) {
		if (!key_looks_present(vmpck_page)) {
			uk_pr_warn("mshv: the paravisor reported success but wrote nothing; the answer went somewhere this guest is not reading\n");
			goto out;
		}

		memcpy(snp_vmpck, vmpck_page, UK_SNP_VMPCK_LEN);

		/* The paravisor answers for the level that asked, and the
		 * level below its own is the one this guest runs at. The
		 * index has to match, because it travels in the clear in
		 * every message and tells the firmware which key to verify
		 * against - a message naming the wrong one is rejected as
		 * unauthenticated rather than as misaddressed.
		 */
		snp_vmpck_index = MSHV_SNP_GUEST_VMPL;
		snp_have_vmpck = 1;

		uk_pr_info("mshv: the paravisor handed over a communication key for this level, named %u\n",
			   (unsigned int)snp_vmpck_index);
		goto out;
	}

	switch (status) {
	case HV_STATUS_ACCESS_DENIED:
		why = "the paravisor refused - the hypervisor has not agreed to carry these requests";
		break;
	case HV_STATUS_NOT_FOUND:
		why = "the paravisor holds no key for this level";
		break;
	case HV_STATUS_INVALID_HYPERCALL_CODE:
		why = "nothing answered - this paravisor does not implement the call";
		break;
	default:
		why = "unexpected";
		break;
	}

	uk_pr_info("mshv: asking the paravisor for a communication key: status 0x%lx, %s\n",
		   (unsigned long)status, why);

out:
	/* The key is not left lying in a second place. */
	memset(vmpck_page, 0, sizeof(vmpck_page));
}

int uk_snp_vmpck(__u8 key[UK_SNP_VMPCK_LEN], __u8 *index)
{
	/* Where the key comes from depends on what is above this guest.
	 * Alone at the top of its own encryption domain, the guest reads
	 * the key the launch process measured into the secrets page. Under
	 * a paravisor there is no such page, and the key must be asked for
	 * instead. Reading is tried first because it settles the question
	 * without a round trip, and because a guest that has a secrets page
	 * has no paravisor to ask.
	 */
	if (snp_secrets_vmpck(key, index) == 0)
		return 0;

	if (!snp_asked)
		snp_ask_for_key();

	if (!snp_have_vmpck)
		return -ENOTSUP;

	memcpy(key, snp_vmpck, UK_SNP_VMPCK_LEN);

	if (index)
		*index = snp_vmpck_index;

	return 0;
}

int uk_snp_available(void)
{
	__u8 key[UK_SNP_VMPCK_LEN];

	if (snp_secrets_vmpck(key, __NULL) == 0) {
		memset(key, 0, sizeof(key));
		return 1;
	}

	if (!snp_asked)
		snp_ask_for_key();

	return snp_have_vmpck;
}

int uk_snp_seqno_reserve(__u8 index, __u64 *seqno)
{
	return snp_secrets_seqno_reserve(index, seqno);
}

/* The pages the firmware is actually handed.
 *
 * The caller's request and answer live in ordinary private memory, which the
 * host cannot read - and the host is the one that has to carry the message to
 * the security processor. So the message is copied through a pair of pages
 * the host can see, exactly as Linux's sev-guest driver does. Nothing is lost
 * by this: the payload is already sealed under the communication key before
 * it is copied out, and the answer is sealed until it is copied back.
 */
static void *snp_req_shared;
static void *snp_resp_shared;

static int snp_bounce_ready(void)
{
	if (snp_req_shared && snp_resp_shared)
		return 1;

	if (!snp_req_shared)
		snp_req_shared = mshv_alloc_shared(__PAGE_SIZE,
						     UK_PAGING_PAGE_ATTR_PROT_RW);

	if (!snp_resp_shared)
		snp_resp_shared = mshv_alloc_shared(__PAGE_SIZE,
						     UK_PAGING_PAGE_ATTR_PROT_RW);

	return snp_req_shared && snp_resp_shared;
}

int uk_snp_guest_request(const void *req, void *resp, __u64 *fw_err)
{
	__paddr_t req_gpa, resp_gpa;
	int rc;

	if (fw_err)
		*fw_err = 0;

	if (unlikely(!req || !resp))
		return -EINVAL;

	/* The firmware is handed whole pages, not addresses within them, so
	 * a buffer that straddles a boundary would have the request read
	 * from one page and the rest of it ignored.
	 */
	if (unlikely(((__vaddr_t)req & (__PAGE_SIZE - 1)) ||
		     ((__vaddr_t)resp & (__PAGE_SIZE - 1))))
		return -EINVAL;

	/* Only make the request once a key has actually been handed over.
	 * One permission governs both, so a key in hand is evidence the
	 * request will be carried; without it the exit is answered with an
	 * invalid-opcode fault, which is not something a caller can catch
	 * and recover from.
	 */
	if (!uk_snp_available())
		return -ENODEV;

	if (unlikely(!snp_bounce_ready())) {
		uk_pr_err("snp: no host-visible page to carry the message\n");
		return -ENOMEM;
	}

	memcpy(snp_req_shared, req, __PAGE_SIZE);
	memset(snp_resp_shared, 0, __PAGE_SIZE);

	req_gpa = mshv_gpa(snp_req_shared);
	resp_gpa = mshv_gpa(snp_resp_shared);

	rc = mshv_ghcb_guest_request(req_gpa, resp_gpa, fw_err);

	memcpy(resp, snp_resp_shared, __PAGE_SIZE);

	/* The request carried a sealed payload and the answer will be read
	 * out of private memory from here on; neither is left where the host
	 * can still see it.
	 */
	memset(snp_req_shared, 0, __PAGE_SIZE);
	memset(snp_resp_shared, 0, __PAGE_SIZE);

	return rc;
}

int mshv_snp_attest_probe(void)
{
	return uk_snp_available() ? 0 : -ENOTSUP;
}
