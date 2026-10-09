/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Microsoft hypervisor synthetic interrupt controller (SynIC) and hypercall
 * page.
 *
 * This is the substrate VMBus sits on. Three things have to be true before a
 * guest can talk to the host over VMBus: the hypervisor must know who the
 * guest is, the guest must have a page it can call into to issue hypercalls,
 * and the guest must have somewhere for the hypervisor to deposit messages
 * and event flags. This file arranges all three.
 *
 * Written against the Hypervisor Top-Level Functional Specification, which
 * defines the MSR numbers, the bit layouts, the hypercall calling convention
 * and the message format used here. Constants were cross-checked against the
 * FreeBSD and Linux implementations; no code was taken from either.
 */

#include <errno.h>
#include <uk/alloc.h>
#include <uk/arch.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/init.h>
#include <uk/intctlr.h>
#include <uk/paging.h>
#include <uk/plat/time.h>
#include <uk/print.h>
#include <string.h>

#include <uk/plat/mshv.h>

/*
 * Guest OS identity, as required before the hypercall page may be enabled.
 *
 * The open-source encoding is: bit 63 set, the OS type in bits 62:56, the
 * major version in 55:48, the minor in 47:40, and a build number in 39:16.
 * The host treats the value as opaque and only requires that it is non-zero;
 * it surfaces in host-side diagnostics, so it is worth making it identifiable.
 * The OS type is not centrally assigned - Linux uses 1 and FreeBSD 2 - so we
 * take an unused value rather than impersonate either.
 */
#define HV_GUEST_OS_ID_OPENSOURCE	(1ULL << 63)
#define HV_GUEST_OS_ID_OSTYPE_UNIKRAFT	(0x0eULL << 56)
#define HV_GUEST_OS_ID_UNIKRAFT				\
	(HV_GUEST_OS_ID_OPENSOURCE			\
	 | HV_GUEST_OS_ID_OSTYPE_UNIKRAFT		\
	 | (0ULL << 48)	/* major */			\
	 | (21ULL << 40) /* minor */)

/* HvPostMessage takes a 256-byte input block whose payload is the message. */
struct mshv_postmsg_in {
	__u32 connid;
	__u32 rsvd;
	__u32 msgtype;
	__u32 dsize;
	__u8 data[HV_MESSAGE_PAYLOAD_SIZE];
} __packed;

/*
 * The hypervisor may report that it has no buffer to accept a message right
 * now, which is a transient condition and not an error. Back off and retry.
 */
#define HV_POST_MESSAGE_RETRIES		20
#define HV_POST_MESSAGE_BACKOFF_NSEC	1000000ULL	/* 1 ms */

/*
 * The eight-byte input block HvSignalEvent reads. One is prepared per open
 * channel and then reused on every transmit, so it is laid out here rather
 * than inside the caller's structure: the hypervisor reads it from guest
 * memory, which on an isolated partition means it has to be shared.
 */
struct mshv_sigevt_in {
	__u32 connid;
	__u16 evtflag;
	__u16 rsvd;
} __packed __align8;

/* Slots carved out of a single shared page. VMBus opens one channel per
 * synthetic device, so a page's worth is far more than can be used.
 */
#define MSHV_SIGEVT_SLOTS	(__PAGE_SIZE / sizeof(struct mshv_sigevt_in))

/* Which synthetic interrupt source VMBus traffic is delivered on. The build
 * time value is the one the protocol names; a redirected control plane moves
 * it at run time. See mshv_synic_set_vmbus_sint().
 */
__u8 mshv_vmbus_sint = CONFIG_MSHV_VMBUS_SINT;

static int synic_ready;
static int synic_rc = -EAGAIN;
static unsigned int synic_irq;

/* The hypervisor writes a call trampoline into this page and we call into it */
static void *hypercall_page;

/* The reused HvPostMessage input block, and where the hypervisor reads it */
#define VMBUS_CONNID_MESSAGE_PROBE	1

static struct mshv_postmsg_in *postmsg_in;
static __paddr_t postmsg_in_pa;

/* The pool of HvSignalEvent input blocks, and the next free one */
static struct mshv_sigevt_in *sigevt_slots;
static __paddr_t sigevt_slots_pa;
static unsigned int sigevt_next;

/* Per-virtual-processor message and event flag pages */
static struct mshv_message *synic_msg_page;
static void *synic_evt_page;

static mshv_msg_handler_t synic_msg_handler;
static mshv_evt_handler_t synic_evt_handler;

/* The synthetic interrupt controller's registers, which are the ones that
 * have to be reached through the GHCB when the partition is isolated.
 */
static inline int mshv_is_synic_msr(__u32 msr)
{
	/* The synthetic timers belong to the same controller as the message
	 * page: a timer configured on one and a page owned by another would
	 * never be seen to expire.
	 */
	return (msr >= HV_X64_MSR_SCONTROL && msr <= HV_X64_MSR_SINT(15))
	       || (msr >= HV_X64_MSR_STIMER0_CONFIG
		   && msr <= HV_X64_MSR_STIMER3_COUNT);
}

static inline __u64 mshv_rdmsr(__u32 msr)
{
	__u32 eax, edx;
	__u64 val;

	if (mshv_is_synic_msr(msr) && mshv_ghcb_ready()
	    && !mshv_ghcb_rdmsr(msr, &val))
		return val;

	uk_arch_x86_64_rdmsr(msr, &eax, &edx);

	return ((__u64)edx << 32) | (__u64)eax;
}

static inline void mshv_wrmsr(__u32 msr, __u64 val)
{
	if (mshv_is_synic_msr(msr) && mshv_ghcb_ready()) {
		/* The hypervisor's copy never carries the forwarding request:
		 * that request describes an arrangement between the guest and
		 * the paravisor and the hypervisor refuses it.
		 */
		int rc = mshv_ghcb_wrmsr(msr, val & ~HV_SYNIC_SINT_PROXY);

		if (unlikely(rc))
			uk_pr_err("mshv: MSR 0x%x write rejected: %d\n",
				  msr, rc);

		/* An interrupt source register lives in two places when a
		 * paravisor is present, and the two copies do not hold the
		 * same value. The hypervisor's copy, written above, is what
		 * decides that this partition is signalled at all, and it
		 * describes a source the hypervisor delivers itself. The
		 * paravisor's copy describes the same source as one whose
		 * signal is forwarded, which is what makes the paravisor let
		 * that vector through to the guest rather than filter it.
		 *
		 * Writing either value to both is wrong in both directions:
		 * the hypervisor refuses a source it is told to forward, and
		 * the paravisor filters out a source it is not told to.
		 */
		if (msr >= HV_X64_MSR_SINT(0) && msr <= HV_X64_MSR_SINT(15)) {
			__u64 reflected = val | HV_SYNIC_SINT_PROXY;

			uk_arch_x86_64_wrmsr(msr, (__u32)reflected,
					     (__u32)(reflected >> 32));
		}

		return;
	}

	uk_arch_x86_64_wrmsr(msr, (__u32)val, (__u32)(val >> 32));
}

/*
 * Issue a hypercall through the hypervisor-provided trampoline.
 *
 * The trampoline follows the Microsoft x64 convention - the control word in
 * RCX, the input block's guest physical address in RDX and the output block's
 * in R8 - which is not the System V convention the rest of Unikraft is
 * compiled for, hence the explicit register placement. RAX, RCX, RDX and
 * R8-R11 are volatile across the call.
 */
/*
 * HvCallModifySparseGpaPageHostVisibility, the call that grants or revokes the
 * host's access to a guest page on an isolated partition. It is a rep
 * hypercall: the repetition count goes in the control word and the input block
 * carries that many guest page numbers.
 */
#define HV_CALL_MODIFY_GPA_VISIBILITY	0x00dbULL
#define HV_HYPERCALL_REP_SHIFT		32
#define HV_HYPERCALL_REP_COMP_SHIFT	32
#define HV_HYPERCALL_REP_COMP_MASK	0xfffULL
#define HV_GPA_NOT_HOST_VISIBLE		0
#define HV_GPA_HOST_VISIBLE_RW		3

struct hv_gpa_visibility_in {
	__u64 partition_id;
	__u32 visibility;
	__u32 reserved;
	__u64 gpa_page[];
} __packed;

#define HV_GPA_VISIBILITY_MAX						\
	((__PAGE_SIZE - sizeof(struct hv_gpa_visibility_in))		\
	 / sizeof(__u64))

static struct hv_gpa_visibility_in *vis_in;
static __paddr_t vis_in_pa;

/* Issue a hypercall through the hypercall page.
 *
 * This is the route the paravisor can see. Under SEV-SNP the HCL intercepts a
 * fixed set of call codes on their way from this level to the hypervisor and
 * answers them itself; a request made any other way reaches the hypervisor
 * directly, and for a call code only the paravisor implements the hypervisor
 * answers HV_STATUS_INVALID_HYPERCALL_CODE.
 */
__u64 mshv_hypercall(__u64 control, __paddr_t in_pa, __paddr_t out_pa)
{
	register __u64 r8 __asm__("r8") = (__u64)out_pa;
	__u64 status, scratch_cx, scratch_dx;

	/* Without a hypercall page the instruction the page would have held
	 * is issued here instead. It leaves the guest as a #VC, and the
	 * handler forwards it through the GHCB with the argument registers
	 * the calling convention names.
	 */
	if (mshv_hypercall_direct()) {
		__asm__ __volatile__(
			"vmmcall"
			: "=a"(status), "+c"(control), "+d"(in_pa), "+r"(r8)
			:
			: "r9", "r10", "r11", "memory", "cc"
		);

		return status;
	}

	UK_ASSERT(hypercall_page);

	__asm__ __volatile__(
		"call *%[hcpage]"
		: "=a"(status), "=c"(scratch_cx), "=d"(scratch_dx), "+r"(r8)
		: "1"(control), "2"((__u64)in_pa), [hcpage]"r"(hypercall_page)
		: "r9", "r10", "r11", "memory", "cc"
	);

	return status;
}

/*
 * The same request, for a range named by virtual address.
 *
 * An allocation from the heap is a run of virtual addresses; its frames may be
 * scattered anywhere. Publishing such a range as though it began at one frame
 * and continued for `pages` names frames belonging to somebody else, and -
 * worse - leaves the frames actually being published still private. The alias
 * is then mapped over pages the host was never given, and the first write
 * through it fails the memory integrity check: on SEV-SNP that surfaces as a
 * machine check, not a page fault, because nothing about it is recoverable.
 *
 * So the page table is consulted per page, exactly as the aliasing loop does.
 * The hypercall carries an explicit page list rather than a base, so scattered
 * frames still travel together in one rep batch.
 */
int mshv_set_range_visibility(__vaddr_t va, unsigned long pages, int visible)
{
	unsigned long done = 0;

	UK_ASSERT(!(va & (__PAGE_SIZE - 1)));

	if (unlikely((!hypercall_page && !mshv_hypercall_direct()) || !vis_in))
		return -ENODEV;

	while (done < pages) {
		unsigned long n = pages - done;
		__paddr_t first;
		__u64 control, status;

		if (n > HV_GPA_VISIBILITY_MAX)
			n = HV_GPA_VISIBILITY_MAX;

		vis_in->partition_id = HV_PARTITION_ID_SELF;
		vis_in->visibility = visible ? HV_GPA_HOST_VISIBLE_RW
					     : HV_GPA_NOT_HOST_VISIBLE;
		vis_in->reserved = 0;

		first = uk_paging_virt_to_phys(va + done * __PAGE_SIZE);
		vis_in->gpa_page[0] = first >> __PAGE_SHIFT;

		for (unsigned long i = 1; i < n; i++) {
			__paddr_t pa = uk_paging_virt_to_phys(va + (done + i)
							      * __PAGE_SIZE);

			vis_in->gpa_page[i] = pa >> __PAGE_SHIFT;
		}

		control = (__u64)HV_CALL_MODIFY_GPA_VISIBILITY
			  | ((__u64)n << HV_HYPERCALL_REP_SHIFT);

		status = mshv_hypercall(control, vis_in_pa, 0);
		if (unlikely((status & HV_HYPERCALL_STATUS_MASK)
			     != HV_STATUS_SUCCESS)) {
			uk_pr_err("mshv: making %lu page(s) of 0x%lx %s failed, status 0x%lx\n",
				  n, (unsigned long)va,
				  visible ? "host visible" : "private",
				  (unsigned long)(status
						  & HV_HYPERCALL_STATUS_MASK));
			return -EIO;
		}

		if (unlikely(((status >> HV_HYPERCALL_REP_COMP_SHIFT)
			      & HV_HYPERCALL_REP_COMP_MASK) != n)) {
			uk_pr_err("mshv: only %lu of %lu page(s) of 0x%lx changed hands, status 0x%lx\n",
				  (unsigned long)((status
						   >> HV_HYPERCALL_REP_COMP_SHIFT)
						  & HV_HYPERCALL_REP_COMP_MASK),
				  n, (unsigned long)va, (unsigned long)status);
			return -EIO;
		}

		done += n;
	}

	uk_pr_info("mshv: %lu page(s) of 0x%lx are now %s the host\n",
		   pages, (unsigned long)va,
		   visible ? "visible to" : "hidden from");

	return 0;
}

/*
 * Allocate one page the hypervisor can reach, and report where it should look

 * for it.
 *
 * The page is private - that is, it stays inside the guest's encryption
 * domain - even on an isolated partition. Everything allocated here is read or
 * written by the hypervisor through a hypercall, and on a partition with a
 * paravisor the hypercall is serviced by the paravisor, which runs at a more
 * privileged VMPL inside the same encryption domain and can therefore see
 * private memory. Only memory the *host* reaches directly, without the
 * paravisor in between - monitor pages, ring buffers, the network buffers -
 * has to be shared above the GPA boundary.
 *
 * The hypervisor is handed a guest physical address, so the page table has to
 * be consulted: the heap the allocator draws from is not necessarily identity
 * mapped.
 */
static void *mshv_alloc_page(__paddr_t *pa, unsigned long attr)
{
	struct uk_alloc *a = uk_alloc_get_default();
	void *page;
	int rc;

	/* Every page reached through here is one the hypervisor reads or
	 * writes: a hypercall argument block, a SynIC overlay, a page list.
	 * With a paravisor those stay private, because the paravisor shares
	 * the guest's encryption domain and can see them. Without one the
	 * reader is the hypervisor itself, which sees only ciphertext until
	 * the page is published, and a hypercall whose input block was never
	 * published is rejected as malformed.
	 */
	if (mshv_hypercall_direct()) {
		page = mshv_alloc_shared(__PAGE_SIZE, attr);
		if (unlikely(!page))
			return __NULL;

		*pa = uk_paging_virt_to_phys((__vaddr_t)page);

		return page;
	}

	if (unlikely(!a))
		return __NULL;

	page = uk_memalign(a, __PAGE_SIZE, __PAGE_SIZE);
	if (unlikely(!page))
		return __NULL;

	memset(page, 0, __PAGE_SIZE);

	rc = uk_paging_page_set_attr(uk_paging_pt_get_active(),
				     (__vaddr_t)page, 1, attr, 0);
	if (unlikely(rc)) {
		uk_pr_err("mshv: cannot set page attributes: %d\n", rc);
		return __NULL;
	}

	*pa = uk_paging_virt_to_phys((__vaddr_t)page);

	return page;
}

static int mshv_hypercall_init(void)
{
	__paddr_t pa;
	__u64 val;

	/* The identity of the guest must be known before the hypervisor will
	 * accept a hypercall by any route, so this comes first and applies
	 * to both.
	 */
	mshv_wrmsr(HV_X64_MSR_GUEST_OS_ID, HV_GUEST_OS_ID_UNIKRAFT);

	if (mshv_hypercall_direct()) {
		uk_pr_info("mshv: no hypercall page, issuing hypercalls directly\n");
		goto skip_hypercall_page;
	}

	/* The hypervisor writes instructions into this page and we execute
	 * them, so it has to be executable. Heap pages are not, by default.
	 *
	 * The page is private even on an isolated partition. It is the
	 * paravisor, not the host, that emulates the hypercall MSR and writes
	 * the trampoline, and the paravisor can see private memory. Handing
	 * the MSR a guest physical address above the shared GPA boundary is
	 * not merely unnecessary but fatal: the write itself faults, and with
	 * no fault handler this far into early boot the partition is torn
	 * down without a word.
	 */
	hypercall_page = mshv_alloc_page(&pa, UK_PAGING_PAGE_ATTR_PROT_RWX);
	if (unlikely(!hypercall_page))
		return -ENOMEM;

	uk_pr_info("mshv: hypercall page va %p gpa 0x%lx\n",
		   hypercall_page, (unsigned long)pa);

	val = (__u64)pa | HV_HYPERCALL_ENABLE;
	mshv_wrmsr(HV_X64_MSR_HYPERCALL, val);

	uk_pr_info("mshv: hypercall msr written\n");

	val = mshv_rdmsr(HV_X64_MSR_HYPERCALL);

	/* There is deliberately no probe hypercall here. The obvious one - ask
	 * for a call code that does not exist and require a well-formed
	 * rejection - is safe only against a hypervisor, which is specified to
	 * answer HV_STATUS_INVALID_HYPERCALL_CODE. A paravisor is bound by no
	 * such contract and may simply tear the partition down, which is a
	 * silent death exactly where a diagnostic was wanted. The MSR readback
	 * and the first instruction word logged below are evidence enough that
	 * the overlay is in place; the first real hypercall checks its own
	 * status like every other.
	 */
	uk_pr_info("mshv: hypercall msr reads back 0x%lx, first word 0x%lx\n",
		   (unsigned long)val,
		   (unsigned long)(*(volatile __u64 *)hypercall_page));
	if (unlikely(!(val & HV_HYPERCALL_ENABLE))) {
		uk_pr_err("mshv: the hypervisor refused the hypercall page\n");
		return -EIO;
	}

	uk_pr_debug("mshv: hypercall page at 0x%lx\n", (unsigned long)pa);

skip_hypercall_page:
	/* Private for the same reason as every other hypercall input block,
	 * and in any case it could not be shared without the very call it
	 * exists to make.
	 *
	 * Allocated whether or not the partition is isolated: a VTL2 payload
	 * on an unisolated partition never publishes a page, but it does have
	 * to hand the host access to its VMBus buffers, and that call reads
	 * its page list from here too.
	 */
	vis_in = mshv_alloc_page(&vis_in_pa, UK_PAGING_PAGE_ATTR_PROT_RW);
	if (unlikely(!vis_in))
		return -ENOMEM;

	/* Nothing may be handed to the host until the partition agrees that
	 * VTL protections are what decides. Failing this is not fatal: a
	 * payload that is not running in VTL2 has no protections to change
	 * and no need to, and its buffers are reachable already.
	 */

	return 0;
}


/* How many messages the drain has handed on, so a wait that times out can
 * tell a slot that was never written from one that was written and eaten.
 */
static unsigned long synic_drained;

unsigned long mshv_synic_drained(void)
{
	return synic_drained;
}

static void mshv_synic_drain(void)
{
	struct mshv_message *slot = synic_msg_page + HV_SYNIC_SINT_VMBUS;
	volatile __u64 *head = (volatile __u64 *)slot;

	/* A slot is occupied when anything at all has been written into its
	 * header, not only when the type is one this guest recognises. Under
	 * a paravisor the type has been seen to arrive as zero behind a
	 * perfectly well formed payload, and keying the drain on the type
	 * alone leaves that message sitting in the page for ever.
	 */
	while (*head != 0) {
		__u64 seen = *head;

		if (synic_msg_handler)
			synic_msg_handler(slot);

		synic_drained++;
		uk_pr_debug("mshv: drained a message, head was %016lx\n",
			    (unsigned long)seen);

		/* Release the whole header, not just the type: the size is
		 * part of what marks the slot as written. Then make the
		 * release visible before signalling, so that a message which
		 * arrived in between is not left undelivered.
		 */
		*head = 0;
		uk_arch_mb();

		/* Say the slot is free every time, not only when the sender
		 * said it had more waiting. A hypervisor talking straight to
		 * the guest notices the empty slot on its own, but a paravisor
		 * relaying for someone else holds the next message until it is
		 * told the last one was taken, and then nothing further ever
		 * arrives.
		 */
		mshv_wrmsr(HV_X64_MSR_EOM, 0);

		if (!((__u8)(seen >> 40) & HV_MSGFLAG_PENDING))
			break;
	}
}

/*
 * Counted so that a wait which times out can say whether the synthetic
 * interrupt was ever delivered, which is the difference between a message
 * that never arrived and one that arrived where nothing was looking.
 */
static unsigned long synic_intr_count;

unsigned long mshv_synic_intr_count(void)
{
	return synic_intr_count;
}

void mshv_synic_dump_slots(void)
{
	const struct mshv_message *m = synic_msg_page;

	if (unlikely(!m))
		return;

	for (unsigned int i = 0; i < HV_SYNIC_SINT_COUNT; i++) {
		__u64 hdr = *(volatile __u64 *)(m + i);

		if (hdr)
			uk_pr_info("mshv: message slot %u header 0x%lx\n",
				   i, (unsigned long)hdr);
	}
}

__u64 mshv_synic_slot_header(void)
{
	if (unlikely(!synic_msg_page))
		return 0;

	return *(volatile __u64 *)(synic_msg_page + HV_SYNIC_SINT_VMBUS);
}

/*
 * The head of the slot the synthetic bus is answered in, word by word. A
 * header alone cannot say whether a message was written and withdrawn or
 * whether the page was never touched at all; the words behind it can.
 */
void mshv_synic_dump_vmbus_slot(const char *when)
{
	const volatile __u64 *w;

	if (unlikely(!synic_msg_page))
		return;

	for (unsigned int i = 0; i < HV_SYNIC_SINT_COUNT; i++) {
		w = (const volatile __u64 *)(synic_msg_page + i);

		/* Every source is worth showing, because a reply that never
		 * appears where it was asked for may still have been left
		 * somewhere else. Empty ones are skipped so the interesting
		 * slot is not buried.
		 */
		if (i != HV_SYNIC_SINT_VMBUS && !w[0] && !w[1] && !w[2])
			continue;

		uk_pr_info("mshv: slot %u %s, in this domain: %016lx %016lx %016lx %016lx\n",
			   i, when, (unsigned long)w[0], (unsigned long)w[1],
			   (unsigned long)w[2], (unsigned long)w[3]);
	}

}

static void mshv_synic_dispatch(void)
{
	/* Ring events and control messages have independent pending state. */
	if (synic_evt_handler)
		synic_evt_handler();
	mshv_synic_drain();
}

void mshv_synic_poll(void)
{
	unsigned long flags;

	if (unlikely(!synic_ready))
		return;

	/* The drain is written for the interrupt handler, which cannot be
	 * re-entered. A poll can run concurrently with one, so it is masked.
	 */
	flags = uk_lcpu_save_irqf();
	mshv_synic_dispatch();
	uk_lcpu_restore_irqf(flags);
}

static int mshv_synic_intr(void *arg __unused)
{
	synic_intr_count++;

	/*
	 * Both the message and the event handler run from here, and the
	 * interrupt says nothing about which of the two has work. The event
	 * handler goes first: a channel whose ring has filled is more urgent
	 * than a message, and a message handler may take a while.
	 */
	mshv_synic_dispatch();

	return 1;
}

void mshv_synic_set_evt_handler(mshv_evt_handler_t handler)
{
	synic_evt_handler = handler;
}

volatile unsigned long *mshv_synic_evtflags(void)
{
	if (unlikely(!synic_evt_page))
		return __NULL;

	/*
	 * From VMBus 2.4 onwards the host records which channels have work
	 * directly in this processor's event flag page, in the block that
	 * belongs to the interrupt source VMBus was bound to.
	 */
	return (volatile unsigned long *)((__u8 *)synic_evt_page
			+ HV_SYNIC_SINT_VMBUS * HV_SYNIC_EVTFLAGS_SIZE);
}

void mshv_synic_set_msg_handler(mshv_msg_handler_t handler)
{
	synic_msg_handler = handler;
}

/*
 * The hypervisor's own index for this processor, which is not necessarily the
 * ACPI or platform CPU id. Channel messages that name a target processor use
 * this number.
 */
__u32 mshv_vp_index(void)
{
	if (unlikely(!mshv_has_features(HV_MSR_VP_INDEX_AVAILABLE)))
		return 0;

	return (__u32)mshv_rdmsr(HV_X64_MSR_VP_INDEX);
}

/* Which way a posted message leaves the guest. An isolated partition has two
 * candidates and no way to tell from inside which one the host is listening
 * on, so the choice is left open and settled by trying.
 */
static int postmsg_plain;

/* Whether the route the first message took has already been reported */
static int postmsg_reported;

void mshv_post_message_plain(int on)
{
	postmsg_plain = on;
}

int mshv_post_message(__u32 connid, __u32 msgtype, const void *data,
			__sz dsize)
{
	struct mshv_postmsg_in *in;
	__u64 status;
	__u64 deadline;
	int i, rc;

	UK_ASSERT(data);

	if (unlikely(!synic_ready))
		return -ENODEV;
	if (unlikely(dsize > HV_MESSAGE_PAYLOAD_SIZE))
		return -EINVAL;

	/* The input block is read by the hypervisor from guest memory, so on
	 * an isolated partition it has to be shared, which is far too
	 * expensive to arrange per message. It is set up once instead and
	 * reused, which is safe because posting only happens on VMBus control
	 * paths - connect, GPADL construction, channel open - and never from
	 * the synthetic interrupt handler.
	 */
	in = postmsg_in;
	if (unlikely(!in))
		return -ENODEV;

	memset(in, 0, sizeof(*in));
	in->connid = connid;
	in->msgtype = msgtype;
	in->dsize = (__u32)dsize;
	memcpy(in->data, data, dsize);

	rc = -EIO;
	for (i = 0; i < HV_POST_MESSAGE_RETRIES; i++) {
		if (mshv_ghcb_ready() && !postmsg_plain) {
			/* Naming the request in registers instead was tried
			 * and the exit itself is refused here, so the request
			 * goes in the block, which is also where the guest
			 * this platform is built for puts it.
			 */
			status = mshv_ghcb_hypercall(
					HV_HYPERCALL_POST_MESSAGE,
					in, sizeof(*in));
		} else {
			status = mshv_hypercall(HV_HYPERCALL_POST_MESSAGE,
						  postmsg_in_pa, 0);
		}

		status &= HV_HYPERCALL_STATUS_MASK;

		/* Say once which route carried the first message and what it
		 * answered. A route that answers nothing at all answers with
		 * zero, which reads as success, so the route matters as much
		 * as the answer.
		 */
		if (unlikely(!postmsg_reported)) {
			postmsg_reported = 1;
			uk_pr_info("mshv: the first message went out %s and was answered 0x%lx\n",
				   (mshv_ghcb_ready() && !postmsg_plain)
					? "through the shared block"
					: "through the trampoline",
				   (unsigned long)status);
		}

		if (status == HV_STATUS_SUCCESS) {
			rc = 0;
			break;
		}

		/* Only a shortage of host-side buffers is worth retrying;
		 * everything else is a caller error and will not improve.
		 */
		if (status != HV_STATUS_INSUFFICIENT_BUFFERS) {
			uk_pr_err("mshv: HvPostMessage failed, status 0x%lx\n",
				  (unsigned long)status);
			break;
		}

		deadline = mshv_ref_time_nsec()
			   + HV_POST_MESSAGE_BACKOFF_NSEC * (__u64)(i + 1);
		while (mshv_ref_time_nsec() < deadline)
			uk_arch_spinwait();
	}

	if (unlikely(rc && status == HV_STATUS_INSUFFICIENT_BUFFERS))
		uk_pr_err("mshv: HvPostMessage gave up after %d retries\n",
			  HV_POST_MESSAGE_RETRIES);

	return rc;
}

int mshv_sigevt_init(struct mshv_sigevt *se, __u32 connid, __u16 evtflag)
{
	struct mshv_sigevt_in *in;

	if (unlikely(!synic_ready))
		return -ENODEV;

	/* The hypervisor reads the eight-byte input block from guest memory,
	 * so it cannot live inside the caller's structure: on an isolated
	 * partition that memory is private and the host would read ciphertext.
	 * Blocks are handed out from a shared page instead, and the caller
	 * keeps only the address the hypercall needs.
	 */
	if (unlikely(sigevt_next >= MSHV_SIGEVT_SLOTS)) {
		uk_pr_err("mshv: no free signal-event slot\n");
		return -ENOSPC;
	}

	in = &sigevt_slots[sigevt_next];

	in->connid = connid;
	in->evtflag = evtflag;
	in->rsvd = 0;

	se->connid = connid;
	se->evtflag = evtflag;
	se->rsvd = 0;
	se->pa = uk_paging_virt_to_phys((__vaddr_t)in);

	/* The hypercall reads eight bytes starting here, so the block may not
	 * cross a page: guaranteed by the slot's eight-byte alignment,
	 * asserted so a future field reordering cannot quietly break it.
	 */
	UK_ASSERT((se->pa & (__PAGE_SIZE - 1)) <= __PAGE_SIZE - 8);

	sigevt_next++;

	return 0;
}

int mshv_sigevt_signal(const struct mshv_sigevt *se)
{
	__u64 status;

	if (unlikely(!synic_ready))
		return -ENODEV;

	if (mshv_ghcb_ready()) {
		struct mshv_sigevt_in in = {
			.connid = se->connid,
			.evtflag = se->evtflag,
			.rsvd = 0,
		};

		status = mshv_ghcb_hypercall(HV_HYPERCALL_SIGNAL_EVENT,
					       &in, sizeof(in));
	} else {
		status = mshv_hypercall(HV_HYPERCALL_SIGNAL_EVENT,
					  se->pa, 0);
	}

	status &= HV_HYPERCALL_STATUS_MASK;

	if (unlikely(status != HV_STATUS_SUCCESS)) {
		uk_pr_err("mshv: HvSignalEvent failed, status 0x%lx\n",
			  (unsigned long)status);
		return -EIO;
	}

	return 0;
}

int mshv_synic_init(void)
{
	__paddr_t msg_pa = 0, evt_pa = 0;
	__u64 val;
	int rc;

	/* Bring-up is idempotent and every caller wants the same answer */
	if (synic_rc != -EAGAIN)
		return synic_rc;

	synic_rc = -ENODEV;

	/* The first line of this port that is certain to reach a console.
	 * Detection runs before the console exists, so anything printed there
	 * is lost - which is why the tag is announced here and not at the
	 * point the hypervisor is first recognised.
	 */
	uk_pr_info("mshv: guest build " MSHV_RUN_TAG "\n");

	if (!mshv_available()) {
		uk_pr_err("mshv: not running on a MSHV partition\n");
		return synic_rc;
	}

	/* Reading a synthetic MSR the partition is not permitted to touch
	 * raises a #GP, so check before doing anything else.
	 */
	if (!mshv_has_features(HV_MSR_SYNIC_AVAILABLE)) {
		uk_pr_err("mshv: the partition has no synthetic interrupt controller\n");
		return synic_rc;
	}

	/* Whether guest memory is hardware-isolated from the host decides how
	 * every buffer below has to be allocated, so it has to be settled
	 * before the first of them - the hypercall page - is asked for.
	 */
	rc = mshv_isolation_init();
	if (unlikely(rc))
		goto err;

	rc = mshv_hypercall_init();
	if (unlikely(rc))
		goto err;

	/* Both hypercall input blocks are read by the hypervisor out of guest
	 * memory and are reused for the lifetime of the partition, so they are
	 * placed once, here, rather than around each call.
	 */
	postmsg_in = mshv_alloc_page(&postmsg_in_pa,
				       UK_PAGING_PAGE_ATTR_PROT_RW);
	sigevt_slots = mshv_alloc_page(&sigevt_slots_pa,
					 UK_PAGING_PAGE_ATTR_PROT_RW);
	if (unlikely(!postmsg_in || !sigevt_slots)) {
		rc = -ENOMEM;
		goto err;
	}

	/* On x86 the trap table maps IRQ n onto vector 32 + n, and the vector
	 * a synthetic source raises is not a free choice on an isolated
	 * partition: the layer beneath refuses a source that is unmasked, not
	 * polled, and carries a vector below the range it reserves for
	 * delivered interrupts. A fixed high vector is used instead of one
	 * taken from the allocatable pool, which hands out low numbers.
	 */
	synic_irq = MSHV_SYNIC_VECTOR - 32;

	rc = uk_intctlr_irq_alloc(&synic_irq, 1);
	if (unlikely(rc))
		uk_pr_warn("mshv: the pool did not hand out an IRQ: %d\n", rc);

	synic_irq = MSHV_SYNIC_VECTOR - 32;

	rc = uk_intctlr_irq_register(synic_irq, mshv_synic_intr, __NULL);
	if (unlikely(rc)) {
		uk_pr_err("mshv: cannot register the synthetic interrupt: %d\n",
			  rc);
		goto err;
	}

	/* Every register below is emulated, so on an isolated partition none
	 * of them can be reached with the instruction that names it. The GHCB
	 * is what carries them to whoever is emulating them, so it has to be
	 * up before the first one is touched.
	 */
	rc = mshv_ghcb_init();
	if (unlikely(rc))
		goto err;

	/* Under restricted injection nothing can be delivered until the
	 * hypervisor has somewhere to write the vector, so the doorbell has
	 * to exist before the first source is unmasked below. The call is a
	 * no-op on a guest launched the ordinary way.
	 */
	rc = mshv_hv_doorbell_init();
	if (unlikely(rc))
		goto err;

	/* The identity written before the hypercall page went to the
	 * hypervisor, which is the only party a plain register write can
	 * reach. On an isolated partition that is not the party that answers
	 * requests made through the block, and it keeps its own copy of the
	 * same register - still zero, because nothing has ever written it.
	 *
	 * An unidentified guest is not refused with an error; it is not
	 * answered at all, which is indistinguishable from a request nobody
	 * read. Announcing the same identity through the block is therefore
	 * the precondition for every request made that way, and it can only
	 * be done once the block exists.
	 */
	if (mshv_isolated() && mshv_ghcb_ready()) {
		rc = mshv_ghcb_wrmsr(HV_X64_MSR_GUEST_OS_ID,
				       HV_GUEST_OS_ID_UNIKRAFT);
		if (unlikely(rc))
			uk_pr_err("mshv: the paravisor would not take the guest identity: %d\n",
				  rc);
		else
			uk_pr_info("mshv: guest identity announced to the paravisor as well\n");
	}

	if (mshv_isolated())
		uk_pr_info("mshv: SIMP 0x%lx SIEFP 0x%lx before init\n",
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SIMP),
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SIEFP));

	/* Who owns the message and event pages depends on who is emulating the
	 * controller. On an ordinary partition nobody has placed them, so they
	 * are allocated here and the registers are pointed at them. On an
	 * isolated partition the paravisor has already established its own and
	 * the hypervisor refuses to be pointed anywhere else: the base has to
	 * be left exactly as found and only the enable bit set. The address it
	 * reports carries the shared-memory boundary bit, so an alias is
	 * mapped onto the page to reach it, as for any other shared buffer.
	 *
	 * Both registers carry reserved bits that must be preserved.
	 */
	val = mshv_rdmsr(HV_X64_MSR_SIMP);

	if (mshv_ghcb_ready()) {
		__paddr_t simp_gpa = (val & HV_SYNIC_PAGE_MASK)
				     & ~mshv_shared_gpa_boundary();

		/* The page is reached through the shared aperture. Reaching it
		 * at the address it is reported at, with the boundary bit
		 * taken off, faults: the page is not part of this partition's
		 * own encryption domain even though the layer beneath placed
		 * it.
		 */
		synic_msg_page = mshv_map_shared_gpa(
			simp_gpa, 1, UK_PAGING_PAGE_ATTR_PROT_RW);
	} else {
		synic_msg_page = mshv_alloc_page(&msg_pa,
					UK_PAGING_PAGE_ATTR_PROT_RW);
		val = (val & ~HV_SYNIC_PAGE_MASK) | (__u64)msg_pa;
	}

	if (unlikely(!synic_msg_page)) {
		rc = -ENOMEM;
		goto err;
	}

	/* Whoever held this page before - firmware, or the layer beneath -
	 * may have left a message in it that they had already read and
	 * answered. Only the type is cleared when a message is taken, so what
	 * remains looks exactly like a reply that has just arrived. Start from
	 * a page that says nothing, so that anything read out of it later was
	 * genuinely put there for this guest.
	 */
	memset((void *)synic_msg_page, 0,
	       sizeof(struct mshv_message) * HV_SYNIC_SINT_COUNT);

	mshv_wrmsr(HV_X64_MSR_SIMP, val | HV_SYNIC_PAGE_ENABLE);

	val = mshv_rdmsr(HV_X64_MSR_SIEFP);

	if (mshv_ghcb_ready()) {
		synic_evt_page = mshv_map_shared_gpa(
			(val & HV_SYNIC_PAGE_MASK)
				& ~mshv_shared_gpa_boundary(),
			1, UK_PAGING_PAGE_ATTR_PROT_RW);
	} else {
		synic_evt_page = mshv_alloc_page(&evt_pa,
					UK_PAGING_PAGE_ATTR_PROT_RW);
		val = (val & ~HV_SYNIC_PAGE_MASK) | (__u64)evt_pa;
	}

	if (unlikely(!synic_evt_page)) {
		rc = -ENOMEM;
		goto err;
	}

	mshv_wrmsr(HV_X64_MSR_SIEFP, val | HV_SYNIC_PAGE_ENABLE);

	if (mshv_isolated())
		uk_pr_info("mshv: after pointing them, message page 0x%lx event page 0x%lx\n",
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SIMP),
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SIEFP));

	/* Route the source VMBus uses. Auto-EOI is deliberately left off so
	 * that the acknowledgement goes through the platform's own local APIC
	 * EOI path, which is already correct in both xAPIC and x2APIC mode.
	 */
	val = mshv_rdmsr(HV_X64_MSR_SINT(HV_SYNIC_SINT_VMBUS));
	val &= ~(HV_SYNIC_SINT_VECTOR_MASK | HV_SYNIC_SINT_MASKED
		 | HV_SYNIC_SINT_AUTO_EOI);
	val |= (__u64)(synic_irq + 32) & HV_SYNIC_SINT_VECTOR_MASK;

	/* The forwarding request belongs to the paravisor's copy alone and is
	 * added on the way there, so the value named here is the plain one.
	 */
	mshv_wrmsr(HV_X64_MSR_SINT(HV_SYNIC_SINT_VMBUS), val);

	if (mshv_isolated()) {
		__u32 lo, hi;

		uk_arch_x86_64_rdmsr(HV_X64_MSR_SINT(HV_SYNIC_SINT_VMBUS),
				     &lo, &hi);

		uk_pr_info("mshv: the source vmbus uses is 0x%lx to the hypervisor and 0x%lx to the paravisor\n",
			   (unsigned long)mshv_rdmsr(
				HV_X64_MSR_SINT(HV_SYNIC_SINT_VMBUS)),
			   (unsigned long)(((__u64)hi << 32) | lo));
	}

	/* Mask every source we do not service, so that a stray synthetic
	 * interrupt cannot land on a vector nothing is listening to.
	 */
	for (unsigned int i = 0; i < HV_SYNIC_SINT_COUNT; i++) {
		if (i == HV_SYNIC_SINT_VMBUS)
			continue;

		val = mshv_rdmsr(HV_X64_MSR_SINT(i));
		mshv_wrmsr(HV_X64_MSR_SINT(i), val | HV_SYNIC_SINT_MASKED);
	}

	val = mshv_rdmsr(HV_X64_MSR_SCONTROL) | HV_SYNIC_SCONTROL_ENABLE;
	mshv_wrmsr(HV_X64_MSR_SCONTROL, val);

	/* No unmasking to do at the interrupt controller: the synthetic
	 * interrupt is delivered straight to the vector by the SynIC, so the
	 * SINT MSR above is the only gate. The IRQ number is purely a software
	 * handle used to dispatch into the registered handler.
	 */

	synic_ready = 1;
	synic_rc = 0;

	if (mshv_isolated())
		uk_pr_info("mshv: SCONTROL 0x%lx SINT%u 0x%lx SIMP 0x%lx SIEFP 0x%lx after init\n",
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SCONTROL),
			   HV_SYNIC_SINT_VMBUS,
			   (unsigned long)mshv_rdmsr(
				HV_X64_MSR_SINT(HV_SYNIC_SINT_VMBUS)),
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SIMP),
			   (unsigned long)mshv_rdmsr(HV_X64_MSR_SIEFP));

	/* Self-IPI on the SynIC's own vector. The local APIC delivers this
	 * one without any help from the hypervisor, so if the handler runs
	 * then the vector, the IDT entry and the interrupt path are all
	 * sound, and a missing synthetic interrupt is the host failing to
	 * signal rather than the guest failing to receive. The count is
	 * reported again later by the vmbus connect message.
	 */
	if (mshv_isolated()) {
		unsigned long f = uk_lcpu_save_irqf();

		uk_arch_x86_64_wrmsrl(UK_ARCH_X86_64_APIC_MSR_SELF_IPI,
				      synic_irq + 32);
		uk_lcpu_restore_irqf(f);
		uk_pr_info("mshv: self-IPI issued on vector %u, count now %lu\n",
			   synic_irq + 32, synic_intr_count);
	}

	if (hypercall_page)
		uk_pr_info("mshv: SynIC online, irq %u vector %u, hypercall page at 0x%lx\n",
			   synic_irq, synic_irq + 32,
			   (unsigned long)uk_paging_virt_to_phys(
				   (__vaddr_t)hypercall_page));
	else
		uk_pr_info("mshv: SynIC online, irq %u vector %u, hypercalls issued directly\n",
			   synic_irq, synic_irq + 32);

	return 0;

err:
	/* Leave the partition as we found it rather than half configured */
	mshv_wrmsr(HV_X64_MSR_HYPERCALL, 0);
	mshv_wrmsr(HV_X64_MSR_GUEST_OS_ID, 0);

	if (mshv_isolated() && mshv_ghcb_ready())
		mshv_ghcb_wrmsr(HV_X64_MSR_GUEST_OS_ID, 0);

	synic_rc = rc;

	return rc;
}

void mshv_synic_set_vmbus_sint(__u8 sint)
{
	__u64 val;

	if (sint == mshv_vmbus_sint)
		return;

	/* Silence the source being left behind first. The handler is shared, so
	 * an interrupt arriving on the old source after the switch would be
	 * counted against a route that is no longer being used.
	 */
	val = mshv_rdmsr(HV_X64_MSR_SINT(mshv_vmbus_sint));
	mshv_wrmsr(HV_X64_MSR_SINT(mshv_vmbus_sint),
		     val | HV_SYNIC_SINT_MASKED);

	mshv_vmbus_sint = sint;

	/* Give the new source the vector the handler is registered on, and
	 * unmask it. Auto EOI stays off for the same reason it does at init:
	 * the handler acknowledges the controller itself.
	 */
	val = mshv_rdmsr(HV_X64_MSR_SINT(sint));
	val &= ~(HV_SYNIC_SINT_VECTOR_MASK | HV_SYNIC_SINT_MASKED
		 | HV_SYNIC_SINT_AUTO_EOI);
	val |= (__u64)(synic_irq + 32) & HV_SYNIC_SINT_VECTOR_MASK;
	mshv_wrmsr(HV_X64_MSR_SINT(sint), val);

	uk_pr_info("mshv: vmbus traffic moved to SINT %u\n", sint);
}
