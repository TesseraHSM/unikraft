/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/* #HV, the doorbell a guest under restricted injection is woken by.
 *
 * With restricted injection the hypervisor loses the ability to inject a
 * vector into the guest. The one thing it may still raise is #HV, vector 28,
 * which carries nothing: no error code, no indication of what it is for. The
 * vector it wanted to deliver is written into a page the guest hands over
 * beforehand, so the exception says only "look at the page" and the page says
 * what happened.
 *
 * That split is the whole point. A vector the hypervisor writes into memory
 * the guest chose, and reads back under the guest's own rules, cannot be used
 * to enter the guest at an arbitrary handler - which is exactly what direct
 * injection into an encrypted guest would allow.
 */

#include <errno.h>
#include <string.h>

#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/print.h>
#include <uk/essentials.h>
#include <uk/paging.h>

#include <uk/plat/mshv.h>
#include <x86/snp.h>

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
#include <uk/init.h>
#include <uk/intctlr/apic.h>
#endif

/* Defined by the secrets-page code, which reads the launch configuration
 * once at boot; declared here because the doorbell is its only other caller.
 */
__u64 snp_sev_status_raw(void);

/* The events one #HV stands for.
 *
 * Laid out by the GHCB protocol, not by us: a vector in the low byte, then
 * flags. no_further_signal is the hypervisor saying it will not raise #HV
 * again until the guest has consumed what is already here, which is what
 * keeps the doorbell from ringing once per event.
 */
union hv_pending_events {
	__u16 events;
	struct {
		__u8 vector;
		__u8 nmi : 1;
		__u8 mc : 1;
		__u8 reserved : 5;
		__u8 no_further_signal : 1;
	};
};

/* The page itself is a full 4 KiB even though only the first three bytes
 * carry anything, because that is the granularity the guest can share.
 */
struct hv_doorbell_page {
	union hv_pending_events pending_events;
	__u8 no_eoi_required;
	__u8 reserved[61];
	__u8 padding[4032];
};

static volatile struct hv_doorbell_page *doorbell;
static int doorbell_ready;

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
volatile __u16 *mshv_hv_pending_word;
static unsigned int spurious_vector;

__isr void mshv_hv_doorbell_note(void)
{
}

__isr unsigned int mshv_hv_spurious_vector(void)
{
	return spurious_vector;
}
#endif

__isr int mshv_hv_doorbell_ready(void)
{
	return doorbell_ready;
}

/* Re-arm the doorbell, and report that it rang.
 *
 * no_further_signal is the hypervisor saying it will not raise #HV again
 * until the guest has consumed what is already there, which is what keeps one
 * exception from arriving per event. Clearing it before anything is read is
 * deliberate: an event that races with the drain below then rings the
 * doorbell again rather than being silently absorbed.
 */
#if !CONFIG_MSHV_SNP_RESTRICTED_INJECTION
void mshv_hv_doorbell_rearm(void)
{
	if (unlikely(!doorbell))
		return;

	__atomic_and_fetch(&doorbell->pending_events.events, 0x7fff,
			   __ATOMIC_SEQ_CST);
}
#endif

/* GHCB 5.4.3 acknowledges all pending bits, including NoFurtherSignal,
 * in one exchange. Retain the event flags for the dispatcher's policy.
 */
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
__isr __u16 mshv_hv_doorbell_take(void)
#else
unsigned int mshv_hv_doorbell_next(void)
#endif
{
	union hv_pending_events pending;

	if (unlikely(!doorbell))
		return 0;

	pending.events = __atomic_exchange_n(&doorbell->pending_events.events,
					     0, __ATOMIC_SEQ_CST);

	if (!pending.events)
		return 0;

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	return pending.events;
#else
	return pending.vector;
#endif
}

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
unsigned int mshv_hv_doorbell_next(void)
{
	union hv_pending_events pending;

	pending.events = mshv_hv_doorbell_take();
	return pending.vector;
}
#endif

/* Whether an EOI is still owed after an event delivered this way.
 *
 * The hypervisor sets no_eoi_required when it has already retired the
 * interrupt on the guest's behalf. GHCB 5.4.3 consumes this byte at handler
 * completion, separately from acknowledging the pending event.
 */
__isr int mshv_hv_no_eoi_required(void)
{
	if (unlikely(!doorbell))
		return 0;

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	return __atomic_exchange_n(&doorbell->no_eoi_required, 0,
				   __ATOMIC_SEQ_CST) != 0;
#else
	return __atomic_exchange_n(&doorbell->no_eoi_required, 0,
				   __ATOMIC_SEQ_CST) & 1;
#endif
}

int mshv_hv_doorbell_init(void)
{
	__paddr_t gpa;
	void *page;
	int rc;
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	__u64 features;
#endif

	if (doorbell_ready)
		return 0;

	/* A guest launched with normal injection is delivered interrupts the
	 * ordinary way and has nothing to register. Asking anyway would be a
	 * request the hypervisor is right to refuse.
	 */
	if (!(snp_sev_status_raw() & SNP_SEV_STATUS_RESTRICT_INJ))
		return 0;

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	rc = mshv_isolation_init();
	if (rc) {
		uk_pr_err("mshv: #HV isolation setup failed: %d\n", rc);
		return rc;
	}
	rc = mshv_ghcb_init();
	if (rc) {
		uk_pr_err("mshv: #HV GHCB setup failed: %d\n", rc);
		return rc;
	}
	rc = mshv_ghcb_hv_features(&features);
	if (rc) {
		uk_pr_err("mshv: #HV feature negotiation failed: %d\n", rc);
		return rc;
	}
	/* Bit 5 is only needed for the separate restricted-injection Timer NAE. */
	if (!(features & (1ULL << 4))) {
		uk_pr_err("mshv: host lacks #HV doorbell support: 0x%lx\n",
			  (unsigned long)features);
		return -ENOTSUP;
	}
	spurious_vector = uk_intctlr_apic_read(UK_ARCH_X86_64_APIC_MSR_SVR) & 0xff;
#endif

	/* The host writes this page directly, with nothing in between that
	 * shares the guest's encryption domain, so it has to be shared.
	 */
	page = mshv_alloc_shared(__PAGE_SIZE, 0);
	if (unlikely(!page)) {
		uk_pr_err("mshv: cannot allocate the #HV doorbell page\n");
		return -ENOMEM;
	}

	memset(page, 0, __PAGE_SIZE);

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	gpa = mshv_gpa(page);
#else
	gpa = uk_paging_virt_to_phys((__vaddr_t)page);
#endif

	doorbell = (volatile struct hv_doorbell_page *)page;
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	/* SET may deliver #HV before the registration call returns. */
	mshv_hv_pending_word = &doorbell->pending_events.events;
#endif

	rc = mshv_ghcb_set_doorbell(gpa);
	if (unlikely(rc)) {
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
		mshv_hv_pending_word = __NULL;
#endif
		uk_pr_err("mshv: the #HV doorbell page was refused: %d\n",
			  rc);
		doorbell = __NULL;
		return rc;
	}

	doorbell_ready = 1;

	uk_pr_info("mshv: #HV doorbell page at gpa 0x%lx\n",
		   (unsigned long)gpa);

	return 0;
}

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
static int mshv_hv_initcall(struct uk_init_ctx *ctx __unused)
{
	int rc = mshv_hv_doorbell_init();

	if (rc)
		UK_CRASH("Restricted-injection initialization failed: %d\n", rc);
	return 0;
}

uk_early_initcall_prio(mshv_hv_initcall, 0, UK_PRIO_EARLIEST);
#endif
