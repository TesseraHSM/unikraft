/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * The Guest-Hypervisor Communication Block on a hardware-isolated partition.
 *
 * A SEV-ES or SEV-SNP guest cannot complete every instruction it issues. An
 * access to something the hypervisor emulates rather than owns - a port, an
 * emulated MSR - has no meaning inside the encrypted guest, and the hardware
 * refuses to silently hand the register file to a hypervisor that is outside
 * the guest's trust boundary. Instead the guest asks: it writes the operands
 * into an agreed page, names the exit it wants, and executes VMGEXIT. The
 * hypervisor reads the page, performs the operation, writes the results back
 * and resumes the guest. That page is the GHCB.
 *
 * MSHV's synthetic interrupt controller registers are exactly such
 * registers. They live in the synthetic MSR range, no silicon implements
 * them, and on an isolated partition a bare wrmsr to one does not reach the
 * hypervisor - it takes the partition down. Every SynIC register therefore
 * has to be driven from here.
 *
 * The GHCB itself is not ours to allocate. A partition with a paravisor comes
 * up with one already established: the paravisor, running at VMPL0 inside the
 * guest's encryption domain, sets it up and leaves its guest physical address
 * in the architectural GHCB MSR. All this file does is find that address, map
 * a window onto it through the shared alias so that our stores land in the
 * clear where the hypervisor can read them, agree a protocol version, and
 * then marshal individual operations through it.
 *
 * Only the synthetic MSR range is routed this way. Everything else the guest
 * touches is real, and a plain rdmsr or wrmsr remains both correct and very
 * much faster.
 *
 * There is one GHCB per virtual processor and a request occupies it from the
 * first operand written until the results are read back, so operations run
 * with interrupts off. Ending a message is itself a write to a synthetic
 * register and is done from the synthetic interrupt handler, which is exactly
 * the path that would otherwise land in the middle of another request.
 */

#include <errno.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/paging.h>
#include <uk/lcpu/except.h>
#include <uk/print.h>

#include <string.h>

#include <uk/plat/mshv.h>
#include <uk/plat/shmem.h>
#include <x86/snp.h>

/** Architectural AMD MSR holding the guest physical address of the GHCB */
#define MSR_AMD64_SEV_ES_GHCB		0xc0010130

/*
 * Before a GHCB page exists there is a smaller protocol carried entirely in
 * the GHCB MSR itself: the low twelve bits select a request or response and
 * the rest carries its payload. It is used here only to agree a version.
 */
#define GHCB_MSR_INFO_MASK		0xfffULL
#define GHCB_MSR_SEV_INFO_RESP		0x001
#define GHCB_MSR_SEV_INFO_REQ		0x002
#define GHCB_MSR_HV_FEATURES_REQ		0x080
#define GHCB_MSR_HV_FEATURES_RESP		0x081
#define GHCB_MSR_PROTO_MAX(v)		(((v) >> 48) & 0xffff)
#define GHCB_MSR_PROTO_MIN(v)		(((v) >> 32) & 0xffff)

#define GHCB_PROTOCOL_MIN		1
#define GHCB_PROTOCOL_MAX		2

/** Usage value that says the page holds the standard AMD-defined layout */
#define GHCB_USAGE_DEFAULT		0

/*
 * Byte offsets of the fields used here. The layout is architectural, so these
 * are constants of the platform rather than of any particular implementation.
 * A field is only looked at by the hypervisor if its bit is set in the valid
 * bitmap, and a field's bit number is its offset divided by eight.
 */
#define GHCB_OFF_RAX			0x1f8
#define GHCB_OFF_RCX			0x308
#define GHCB_OFF_RDX			0x310
#define GHCB_OFF_R8			0x340
#define GHCB_OFF_SW_EXIT_CODE		0x390
#define GHCB_OFF_SW_EXIT_INFO_1		0x398
#define GHCB_OFF_SW_EXIT_INFO_2		0x3a0
#define GHCB_OFF_VALID_BITMAP		0x3f0
#define GHCB_VALID_BITMAP_LEN		16
#define GHCB_OFF_PROTOCOL_VERSION	0xffa
#define GHCB_OFF_USAGE			0xffc

/** The exit the hypervisor is asked for to read or write an emulated MSR */
#define SVM_EXIT_MSR			0x7c

/* The exit a guest takes when it executes the call instruction itself.
 * Where the request page carries a hypercall for an ordinary guest, a
 * guest whose memory the hypervisor may not read has to name the same
 * request in registers and leave the operands where the far side is
 * allowed to look.
 */
#define SVM_EXIT_VMMCALL		0x81

/** Set in sw_exit_info_1 of an SVM_EXIT_MSR request to make it a write */
#define SVM_EXIT_MSR_WRITE		1

/* Carry a request to the platform security processor.
 *
 * This is not an emulated instruction: the two operands are pages, named
 * by address, and the far side hands them to the firmware rather than
 * reading them itself. Both must stay private to the guest, because what
 * makes the exchange trustworthy is that only the guest and the firmware
 * hold the key it is authenticated under - a page the host could read
 * would give away the very thing being protected.
 */
#define SVM_EXIT_SNP_GUEST_REQUEST	0x80000011

/* Tell the hypervisor where to leave the events it may no longer inject.
 *
 * Under restricted injection the only thing the hypervisor is allowed to
 * inject is #HV, which carries no vector of its own. The vector it wanted to
 * deliver is written into this page instead, so the exception is only a
 * doorbell and the page is the message. It has to be shared: the writer is
 * the host, which sees ciphertext everywhere else.
 */
#define SVM_EXIT_HV_DOORBELL_PAGE	0x80000014

/** Set in sw_exit_info_1 to install the page named by sw_exit_info_2 */
#define SVM_HV_DOORBELL_PAGE_SET	1

/*
 * A hypercall can also be made through the GHCB, under a different usage
 * value that reinterprets the page. The input block occupies it from the
 * start; the address any output is to be written to and the control word sit
 * at the end, overlapping where the standard layout keeps its version and
 * usage fields. Those two are written first, so the overlap costs nothing.
 *
 * The result is written back over the control word rather than beside it, so
 * the same address is read afterwards and the low sixteen bits are the
 * status. The word after it belongs to the standard layout and is measured to
 * stay untouched across the exit, which is how the two were told apart.
 */
#define GHCB_USAGE_MSHV_CALL		1
#define GHCB_OFF_HV_OUTPUT_GPA		0xfe8
#define GHCB_OFF_HV_CONTROL		0xff0
#define GHCB_OFF_HV_STATUS		0xff8

/* Left in the answer word before a request so that silence can be seen. No
 * status has this value and no hypervisor writes it.
 */
#define GHCB_HV_NO_ANSWER		0xa5a5a5a5a5a5a5a5ULL

/* Transport-level refusals of a guest request, reported in the upper half of
 * the second exit-info word. Only "busy" is transient.
 */
#define GHCB_GUEST_REQ_VMM_ERR_BUSY	2

/* Enough attempts to outlast a host that is briefly busy, few enough that a
 * host which is permanently so is reported rather than spun on.
 */
#define GHCB_GUEST_REQ_MAX_TRIES	8
#define GHCB_HV_INPUT_MAX		0xfe8


static volatile __u8 *ghcb;
static __u16 ghcb_version;

/* Two different things can be true of a GHCB, and conflating them costs the
 * synthetic interrupt controller.
 *
 * ghcb_present says a block exists and can carry the architectural exits the
 * processor defines - a guest request to the security processor, say. That is
 * true of any isolated partition, because the #VC handler cannot work without
 * one.
 *
 * ghcb_ready says the paravisor is behind the block and answers the extended
 * requests it defines: reads and writes of the registers it emulates, and
 * hypercalls placed in the block rather than issued. Nothing answers those
 * when there is no paravisor, and a caller that assumes otherwise ends up
 * asking the hypervisor to honour a page it never placed.
 */
static int ghcb_present;
static int ghcb_ready;

/*
 * VMGEXIT. The encoding is a repeated VMMCALL, which is what distinguishes a
 * guest asking the hypervisor to complete an instruction from a guest making
 * an ordinary hypercall.
 */
static inline void vmgexit(void)
{
	snp_vmgexit();
}

static inline __u64 ghcb_msr_get(void)
{
	__u32 eax, edx;

	uk_arch_x86_64_rdmsr(MSR_AMD64_SEV_ES_GHCB, &eax, &edx);

	return ((__u64)edx << 32) | (__u64)eax;
}

static inline void ghcb_msr_set(__u64 val)
{
	uk_arch_x86_64_wrmsr(MSR_AMD64_SEV_ES_GHCB, (__u32)val,
			     (__u32)(val >> 32));
}

/* Store one field and mark it valid, which are inseparable: a field written
 * without its bit set is not read, and a bit set over a field never written
 * offers the hypervisor a stale value.
 */
static inline void ghcb_put(unsigned int off, __u64 val)
{
	unsigned int bit = off / 8;

	*(volatile __u64 *)(ghcb + off) = val;
	ghcb[GHCB_OFF_VALID_BITMAP + bit / 8] |= (__u8)(1U << (bit % 8));
}

static inline __u64 ghcb_get(unsigned int off)
{
	return *(volatile __u64 *)(ghcb + off);
}

/* Whether the far side marked a field as one it had filled in. The bitmap is
 * cleared before every request, so a bit that is set afterwards was set by
 * whoever serviced the request and by nobody else.
 */
static inline int ghcb_was_written(unsigned int off)
{
	unsigned int bit = off / 8;

	return !!(ghcb[GHCB_OFF_VALID_BITMAP + bit / 8]
		  & (__u8)(1U << (bit % 8)));
}

/* Start a request. The valid bitmap is cleared so that each request describes
 * only its own operands and cannot inherit a field from the one before it.
 */
static void ghcb_begin(void)
{
	for (unsigned int i = 0; i < GHCB_VALID_BITMAP_LEN; i++)
		ghcb[GHCB_OFF_VALID_BITMAP + i] = 0;

	*(volatile __u16 *)(ghcb + GHCB_OFF_PROTOCOL_VERSION) = ghcb_version;
	*(volatile __u32 *)(ghcb + GHCB_OFF_USAGE) = GHCB_USAGE_DEFAULT;
}

/* Name the exit and hand the page over. On return the hypervisor reports
 * failure in the low half of sw_exit_info_1; the high half is reserved for
 * exits that return a value there, which these do not.
 */
static int ghcb_call(__u64 exit_code, __u64 exit_info_1, __u64 exit_info_2)
{
	ghcb_put(GHCB_OFF_SW_EXIT_CODE, exit_code);
	ghcb_put(GHCB_OFF_SW_EXIT_INFO_1, exit_info_1);
	ghcb_put(GHCB_OFF_SW_EXIT_INFO_2, exit_info_2);

	vmgexit();

	if (unlikely(ghcb_get(GHCB_OFF_SW_EXIT_INFO_1) & 0xffffffffUL))
		return -EIO;

	return 0;
}

int mshv_ghcb_ready(void)
{
	return ghcb_ready;
}

int mshv_ghcb_wrmsr(__u32 msr, __u64 val)
{
	unsigned long flags;
	int rc;

	if (unlikely(!ghcb_ready))
		return -ENODEV;

	flags = uk_lcpu_save_irqf();

	ghcb_begin();

	/* The operands are placed where the instruction itself would have
	 * taken them, so the hypervisor needs no description beyond the exit
	 * code: the register to act on in RCX and the value split across the
	 * low halves of RAX and RDX.
	 */
	ghcb_put(GHCB_OFF_RCX, msr);
	ghcb_put(GHCB_OFF_RAX, val & 0xffffffffUL);
	ghcb_put(GHCB_OFF_RDX, (val >> 32) & 0xffffffffUL);

	rc = ghcb_call(SVM_EXIT_MSR, SVM_EXIT_MSR_WRITE, 0);

	uk_lcpu_restore_irqf(flags);

	return rc;
}

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
int mshv_ghcb_hv_features(__u64 *features)
{
	unsigned long flags;
	__u64 saved, response;
	int rc = 0;

	UK_ASSERT(features);
	if (unlikely(!ghcb_present || mshv_paravisor()))
		return -ENODEV;

	flags = uk_lcpu_save_irqf();
	saved = ghcb_msr_get();
	ghcb_msr_set(GHCB_MSR_SEV_INFO_REQ);
	vmgexit();
	response = ghcb_msr_get();
	if ((response & GHCB_MSR_INFO_MASK) != GHCB_MSR_SEV_INFO_RESP) {
		rc = -EPROTO;
		goto out;
	}
	if (GHCB_MSR_PROTO_MIN(response) > 2 ||
	    GHCB_MSR_PROTO_MAX(response) < 2) {
		rc = -ENOTSUP;
		goto out;
	}

	ghcb_msr_set(GHCB_MSR_HV_FEATURES_REQ);
	vmgexit();
	response = ghcb_msr_get();
	if ((response & GHCB_MSR_INFO_MASK) != GHCB_MSR_HV_FEATURES_RESP) {
		rc = -EPROTO;
		goto out;
	}
	*features = response >> 12;
	ghcb_version = 2;
out:
	/* The direct path restores the mailbox, without replaying a page exit. */
	ghcb_msr_set(saved);
	uk_lcpu_restore_irqf(flags);
	if (rc)
		uk_pr_err("mshv: GHCB feature query failed: %d, response 0x%lx\n",
			  rc, (unsigned long)response);
	return rc;
}
#endif

int mshv_ghcb_set_doorbell(__paddr_t gpa)
{
	unsigned long flags;
	int rc;
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	int bad_echo = 0;
#endif

	/* This is an architectural exit rather than one of the paravisor's
	 * extensions, so a bare block is enough for it - which is the only
	 * kind there is on the configuration that needs a doorbell at all.
	 */
	if (unlikely(!ghcb_present))
		return -ENODEV;

	flags = uk_lcpu_save_irqf();

	ghcb_begin();

	rc = ghcb_call(SVM_EXIT_HV_DOORBELL_PAGE, SVM_HV_DOORBELL_PAGE_SET,
		       (__u64)gpa);
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	if (!rc && ghcb_get(GHCB_OFF_SW_EXIT_INFO_2) != (__u64)gpa) {
		bad_echo = 1;
		rc = -EIO;
	}
#endif

	uk_lcpu_restore_irqf(flags);

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	if (bad_echo)
		uk_pr_err("mshv: #HV doorbell accepted GPA differs from 0x%lx\n",
			  (unsigned long)gpa);
#endif
	return rc;
}

int mshv_ghcb_mmio(__paddr_t address, void *value, unsigned int width,
		     int write)
{
	unsigned long flags;
	__u64 status;
	unsigned int i;

	if (!ghcb_present || mshv_paravisor())
		return -ENODEV;
	if ((width != 1 && width != 2 && width != 4 && width != 8) ||
	    address > ~(__u64)0 - (width - 1))
		return -EINVAL;

	flags = uk_lcpu_save_irqf();
	ghcb_begin();
	ghcb_put(GHCB_OFF_SW_EXIT_CODE, write ? 0x80000002 : 0x80000001);
	ghcb_put(GHCB_OFF_SW_EXIT_INFO_1, address);
	ghcb_put(GHCB_OFF_SW_EXIT_INFO_2, width);
	ghcb_put(0x3a8, SNP_GHCB_GPA + 0x800);
	for (i = 0; i < width; i++)
		ghcb[0x800 + i] = write ? ((__u8 *)value)[i] : 0;
	vmgexit();
	status = ghcb_get(GHCB_OFF_SW_EXIT_INFO_1);
	if (!status && !write)
		for (i = 0; i < width; i++)
			((__u8 *)value)[i] = ghcb[0x800 + i];
	for (i = 0; i < width; i++)
		ghcb[0x800 + i] = 0;
	uk_lcpu_restore_irqf(flags);
	return status ? -EIO : 0;
}

int mshv_ghcb_guest_request(__paddr_t req_gpa, __paddr_t resp_gpa,
			      __u64 *fw_err)
{
	unsigned long flags;
	__u64 info1, info2;
	unsigned int tries;

	/* A guest request is an architectural exit, not one of the paravisor's
	 * extensions, so it only needs a block to put it in.
	 */
	if (unlikely(!ghcb_present))
		return -ENODEV;

	if (fw_err)
		*fw_err = 0;

	for (tries = 0; tries < GHCB_GUEST_REQ_MAX_TRIES; tries++) {
		flags = uk_lcpu_save_irqf();

		ghcb_begin();

		ghcb_put(GHCB_OFF_SW_EXIT_CODE, SVM_EXIT_SNP_GUEST_REQUEST);
		ghcb_put(GHCB_OFF_SW_EXIT_INFO_1, req_gpa);
		ghcb_put(GHCB_OFF_SW_EXIT_INFO_2, resp_gpa);

		vmgexit();

		info1 = ghcb_get(GHCB_OFF_SW_EXIT_INFO_1);
		info2 = ghcb_get(GHCB_OFF_SW_EXIT_INFO_2);

		uk_lcpu_restore_irqf(flags);

		if (unlikely(info1 & 0xffffffffULL))
			return -EIO;

		/* Two parties can refuse this request and the second word
		 * carries both answers at once: the layer that transported
		 * it reports in the upper half, the firmware that would have
		 * answered it in the lower. They mean entirely different
		 * things, so they cannot be handed upwards as one number - a
		 * caller that conflates them will retry a request the
		 * firmware has already rejected on its merits, and the
		 * sequence number that request consumed is not recoverable.
		 */
		if (likely(!info2))
			return 0;

		/* The one transport refusal worth absorbing here. It means
		 * the request never reached the firmware, so nothing was
		 * consumed and the identical message can simply be sent
		 * again.
		 */
		if ((info2 >> 32) == GHCB_GUEST_REQ_VMM_ERR_BUSY)
			continue;

		if (info2 >> 32)
			return -EIO;

		if (fw_err)
			*fw_err = info2 & 0xffffffffULL;

		return -EPROTO;
	}

	return -EBUSY;
}

int mshv_ghcb_rdmsr(__u32 msr, __u64 *val)
{
	static int reported;
	unsigned long flags;
	__u64 got;
	int written;
	int rc;

	UK_ASSERT(val);

	if (unlikely(!ghcb_ready))
		return -ENODEV;

	flags = uk_lcpu_save_irqf();

	ghcb_begin();
	ghcb_put(GHCB_OFF_RCX, msr);

	/* Clearing the valid bitmap does not clear the fields themselves, so
	 * the answer slots still hold whatever the last request left in them
	 * - which, after a write of this same register, is the very value a
	 * read is expected to return. An answer that is never written would
	 * then be indistinguishable from a correct one. Leave a mark in them
	 * that no register could hold, so that reading it back afterwards
	 * says plainly that nothing was put there.
	 */
	*(volatile __u64 *)(ghcb + GHCB_OFF_RAX) = GHCB_HV_NO_ANSWER;
	*(volatile __u64 *)(ghcb + GHCB_OFF_RDX) = GHCB_HV_NO_ANSWER;

	rc = ghcb_call(SVM_EXIT_MSR, 0, 0);

	got = (ghcb_get(GHCB_OFF_RAX) & 0xffffffffUL)
	      | ((ghcb_get(GHCB_OFF_RDX) & 0xffffffffUL) << 32);

	written = ghcb_was_written(GHCB_OFF_RAX);

	if (unlikely(ghcb_get(GHCB_OFF_RAX) == GHCB_HV_NO_ANSWER
		     && ghcb_get(GHCB_OFF_RDX) == GHCB_HV_NO_ANSWER))
		rc = -EIO;

	if (!rc)
		*val = got;

	uk_lcpu_restore_irqf(flags);

	if (unlikely(!reported)) {
		reported = 1;
		uk_pr_info("mshv: the first register read through the block %s, and the answer slot %s claimed as filled in\n",
			   rc ? "was left unanswered" : "came back answered",
			   written ? "was" : "was not");
	}

	return rc;
}

/* Ask for a hypercall the way the instruction itself would have asked.
 *
 * The block is left in its ordinary form and the request is described
 * entirely in registers: what to do in RCX, where its operands are in RDX,
 * where to leave the answer in R8. Both addresses name memory the far side
 * is permitted to read and write, so nothing here depends on it being able
 * to see inside this guest. The answer to the request comes back in RAX,
 * separately from whether the exit was taken at all.
 */
__u64 mshv_ghcb_vmmcall(__u64 control, __u64 input_gpa, __u64 output_gpa)
{
	unsigned long flags;
	__u64 status;
	int rc;

	if (unlikely(!ghcb_ready))
		return MSHV_VMMCALL_NOT_TAKEN;

	flags = uk_lcpu_save_irqf();

	ghcb_begin();
	ghcb_put(GHCB_OFF_RCX, control);
	ghcb_put(GHCB_OFF_RDX, input_gpa);
	ghcb_put(GHCB_OFF_R8, output_gpa);
	ghcb_put(GHCB_OFF_RAX, 0);

	rc = ghcb_call(SVM_EXIT_VMMCALL, 0, 0);
	status = ghcb_get(GHCB_OFF_RAX);

	uk_lcpu_restore_irqf(flags);

	if (unlikely(rc))
		return MSHV_VMMCALL_NOT_TAKEN;

	return status;
}

__u64 mshv_ghcb_hypercall(__u64 control, const void *input, __sz input_size)
{
	return mshv_ghcb_hypercall_out(control, input, input_size, 0);
}

static int ghcb_hypercall_scrub;
static int ghcb_hc_unanswered;
static int ghcb_hc_narrowed;
static int ghcb_hc_full_control;
static __u16 ghcb_hc_version;
static __u16 ghcb_found_version;
static __u32 ghcb_found_format;

/* Choose how a request under the enlightened layout is framed.
 *
 * The three degrees of freedom are the protocol version stamped on the page,
 * whether the argument space is cleared first, and whether the control word
 * is carried whole or with the register-passing bit removed. Which
 * combination the other side expects is not documented anywhere reachable
 * from here, so it is discovered rather than assumed.
 *
 * A version of zero leaves whatever the layer beneath established, which is
 * itself one of the combinations worth trying.
 */
void mshv_ghcb_hypercall_style(int version, int scrub, int full_control)
{
	ghcb_hc_version = version < 0 ? 0 : (__u16)version;
	ghcb_hypercall_scrub = scrub;
	ghcb_hc_full_control = full_control;
}

__u16 mshv_ghcb_negotiated_version(void)
{
	return ghcb_version;
}

__u16 mshv_ghcb_established_version(void)
{
	return ghcb_found_version;
}

__u32 mshv_ghcb_established_format(void)
{
	return ghcb_found_format;
}
static int ghcb_output_shared;

void mshv_ghcb_output_shared(int on)
{
	ghcb_output_shared = on;
}

int mshv_ghcb_output_is_shared(void)
{
	return ghcb_output_shared;
}

void mshv_ghcb_hypercall_scrub(int on)
{
	ghcb_hypercall_scrub = on;
}

/* Whether the request left behind by a plain register access is withdrawn
 * before an enlightened request is made. The two share one page, and the
 * register access leaves a completed request described in the save area: an
 * exit code, its arguments, and the bitmap that says which of them are to be
 * read. A reader that looks at the save area first would find that stale
 * request still standing and serve it instead of the one being made.
 */
static int ghcb_hc_clean = 1;

void mshv_ghcb_hypercall_clean(int on)
{
	ghcb_hc_clean = on;
}

__u64 mshv_ghcb_msr_value(void)
{
	__u32 eax, edx;

	uk_arch_x86_64_rdmsr(MSR_AMD64_SEV_ES_GHCB, &eax, &edx);

	return ((__u64)edx << 32) | eax;
}

__u64 mshv_ghcb_hypercall_out(__u64 control, const void *input,
				__sz input_size, __paddr_t output_gpa)
{
	unsigned long flags;
	__u64 status, answer, asked;

	UK_ASSERT(input);
	UK_ASSERT(input_size <= GHCB_HV_INPUT_MAX);

	if (unlikely(!ghcb_ready))
		return HV_STATUS_INVALID_HYPERCALL_CODE;

	flags = uk_lcpu_save_irqf();

	if (ghcb_hc_clean) {
		*(volatile __u64 *)(ghcb + GHCB_OFF_SW_EXIT_CODE) = 0;
		*(volatile __u64 *)(ghcb + GHCB_OFF_SW_EXIT_INFO_1) = 0;
		*(volatile __u64 *)(ghcb + GHCB_OFF_SW_EXIT_INFO_2) = 0;

		for (unsigned int i = 0; i < GHCB_VALID_BITMAP_LEN; i++)
			ghcb[GHCB_OFF_VALID_BITMAP + i] = 0;
	}

	if (ghcb_hc_version)
		*(volatile __u16 *)(ghcb + GHCB_OFF_PROTOCOL_VERSION) =
			ghcb_hc_version;

	*(volatile __u32 *)(ghcb + GHCB_OFF_USAGE) = GHCB_USAGE_MSHV_CALL;

	/* Under this usage the control word is not the trampoline's: only the
	 * call code is carried, in the low sixteen bits, and every other field
	 * - fast, nested, repetition counts - must read as zero.
	 */
	/* Everything below the published fields is argument space under this
	 * usage, so anything an earlier request left there is now part of
	 * the request being made.
	 */
	if (ghcb_hypercall_scrub)
		memset((void *)ghcb, 0, GHCB_OFF_HV_OUTPUT_GPA);

	*(volatile __u64 *)(ghcb + GHCB_OFF_HV_OUTPUT_GPA) = output_gpa;

	/* Under this usage the request and the answer share one word: the
	 * request is written into it, and the answer is written back over it.
	 * Keeping a copy of what was written is therefore the only way to
	 * tell an answer of zero apart from a word nothing ever touched.
	 */
	asked = ghcb_hc_full_control ? control : (control & 0xffffULL);

	if (unlikely(!ghcb_hc_full_control && control != asked
		     && !ghcb_hc_narrowed)) {
		ghcb_hc_narrowed = 1;
		uk_pr_warn("mshv: a request carrying 0x%lx was narrowed to the call code 0x%lx; this route cannot express repetition or fast arguments\n",
			   (unsigned long)control, (unsigned long)asked);
	}

	*(volatile __u64 *)(ghcb + GHCB_OFF_HV_CONTROL) = asked;

	/* The input block is copied in rather than pointed at. That is the
	 * whole reason the call works here: the hypervisor reads it out of a
	 * page it can reach, instead of out of guest memory it cannot.
	 */
	memcpy((void *)ghcb, input, input_size);

	vmgexit();

	/* Where the answer is read from is not a free choice: the request
	 * occupies the last-but-one word of the block and the answer the last.
	 * Reading the request back after the call reads whatever the far side
	 * left in it, which on this platform is zero whether or not anything
	 * serviced the request - a success that is indistinguishable from
	 * silence. The answer word says which it was.
	 */
	answer = *(volatile __u64 *)(ghcb + GHCB_OFF_HV_CONTROL);

	if (unlikely(answer == asked)) {
		if (!ghcb_hc_unanswered) {
			ghcb_hc_unanswered = 1;
			uk_pr_warn("mshv: a request made in the block was left unanswered; the word still reads 0x%lx\n",
				   (unsigned long)answer);
		}

		status = HV_STATUS_INVALID_HYPERCALL_CODE;
	} else {
		status = answer & 0xffffULL;
	}

	/* Leave the page in a state no later request can misread: the usage
	 * value no longer names a layout, and no field claims to be valid.
	 */
	*(volatile __u32 *)(ghcb + GHCB_OFF_USAGE) = 0xffffffff;

	for (unsigned int i = 0; i < GHCB_VALID_BITMAP_LEN; i++)
		ghcb[GHCB_OFF_VALID_BITMAP + i] = 0;

	uk_lcpu_restore_irqf(flags);

	/* The whole word is returned, not just the result: for a request that
	 * carries a list, how much of the list was got through is the only
	 * way to tell a request that was serviced from one that was merely
	 * answered with zeroes.
	 */
	if (answer == asked)
		return status;

	return answer;
}

int mshv_ghcb_init(void)
{
	unsigned long flags;
	__u64 boundary, gpa, val;
	void *va;

	if (ghcb_present)
		return 0;

	/* Without isolation nothing is emulated behind the guest's back and
	 * there is no GHCB to find.
	 */
	if (!mshv_isolated())
		return 0;

	/* With no paravisor to establish one, the guest's own early startup
	 * did: the #VC handler cannot function without a GHCB, so one is
	 * built, published and registered with the hypervisor before any C
	 * code runs. It is reserved out of the memory map and keeps its 1:1
	 * mapping, so adopting it here is a matter of naming it. Establishing
	 * a second one would be worse than redundant - the hypervisor is told
	 * of exactly one registered address per processor, and the early
	 * handler goes on using the address it registered.
	 */
	if (!mshv_paravisor()) {
		ghcb = (volatile __u8 *)(__uptr)SNP_GHCB_GPA;
		ghcb_version = snp_ghcb_version();
		ghcb_present = 1;

		uk_pr_info("mshv: using the GHCB established at startup, 0x%lx, protocol %u\n",
			   (unsigned long)SNP_GHCB_GPA,
			   (unsigned int)ghcb_version);

		return 0;
	}

	boundary = mshv_shared_gpa_boundary();

	/* Whatever the paravisor left here has to survive the version
	 * exchange, which uses the same MSR as a mailbox.
	 */
	flags = uk_lcpu_save_irqf();

	gpa = ghcb_msr_get();

	ghcb_msr_set(GHCB_MSR_SEV_INFO_REQ);
	vmgexit();
	val = ghcb_msr_get();

	/* Put back what was there before reading the answer, so that no exit
	 * from here leaves the mailbox holding a request. Restoring the
	 * address is not the whole of it: the mailbox is only consulted when
	 * an exit is taken, so the address has to be presented as well as
	 * written. The reference guest for this platform takes an exit here
	 * for exactly that reason.
	 */
	ghcb_msr_set(gpa);
	vmgexit();

	uk_lcpu_restore_irqf(flags);

	if (unlikely((val & GHCB_MSR_INFO_MASK) != GHCB_MSR_SEV_INFO_RESP)) {
		uk_pr_err("mshv: no GHCB version response: 0x%lx\n",
			  (unsigned long)val);
		return -ENODEV;
	}

	if (unlikely(GHCB_MSR_PROTO_MAX(val) < GHCB_PROTOCOL_MIN
		     || GHCB_MSR_PROTO_MIN(val) > GHCB_PROTOCOL_MAX)) {
		uk_pr_err("mshv: no common GHCB protocol version, host offers %lu-%lu\n",
			  (unsigned long)GHCB_MSR_PROTO_MIN(val),
			  (unsigned long)GHCB_MSR_PROTO_MAX(val));
		return -ENOTSUP;
	}

	ghcb_version = (__u16)MIN(GHCB_MSR_PROTO_MAX(val), GHCB_PROTOCOL_MAX);

	/* The address the paravisor published is shared memory and so carries
	 * the boundary bit. Drop it to recover the name of the page, which is
	 * what the mapping is asked for; the alias it builds sets the bit
	 * again on our side.
	 */
	gpa &= ~GHCB_MSR_INFO_MASK;
	gpa &= ~boundary;

	if (unlikely(!gpa)) {
		uk_pr_err("mshv: the paravisor established no GHCB\n");
		return -ENODEV;
	}

	va = mshv_map_shared_gpa((__paddr_t)gpa, 1,
				   UK_PAGING_PAGE_ATTR_PROT_RW);
	if (unlikely(!va)) {
		uk_pr_err("mshv: cannot map the GHCB at 0x%lx\n",
			  (unsigned long)gpa);
		return -ENOMEM;
	}

	ghcb = (volatile __u8 *)va;
	ghcb_present = 1;
	ghcb_ready = 1;

	/* Record what the layer beneath left on the page before anything here
	 * overwrites it. Those values are the only first-hand evidence of what
	 * this host actually expects.
	 */
	ghcb_found_version = *(volatile __u16 *)(ghcb + GHCB_OFF_PROTOCOL_VERSION);
	ghcb_found_format = *(volatile __u32 *)(ghcb + GHCB_OFF_USAGE);
	ghcb_hc_version = ghcb_version;

	uk_pr_info("mshv: GHCB at 0x%lx, negotiated version %u, established version %u format %u\n",
		   (unsigned long)gpa, (unsigned int)ghcb_version,
		   (unsigned int)ghcb_found_version,
		   (unsigned int)ghcb_found_format);

	return 0;
}

int ukplat_confidential_mmio(__paddr_t gpa, void *value, unsigned int width,
			     int write)
{
	return mshv_ghcb_mmio(gpa, value, width, write);
}

int ukplat_confidential_mmio_init(void)
{
	int rc = mshv_isolation_init();

	if (rc)
		return rc;

	/* Only a guest that holds its own encryption state and has no
	 * paravisor in front of it performs device accesses itself.
	 */
	if (mshv_isolation_type() != 2 || mshv_paravisor())
		return -ENOTSUP;

	return mshv_ghcb_init();
}
