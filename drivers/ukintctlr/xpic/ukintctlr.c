/* Copyright (c) 2023, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <errno.h>
#include <uk/arch/util.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/event.h>
#include <uk/config.h>
#include <uk/intctlr.h>
#include <uk/lcpu.h>

#if CONFIG_LIBUKINTCTLR_APIC
#include <uk/arch/x86_64.h>
#include <uk/arch/util.h>
#include <uk/intctlr/apic.h>

/* The local APIC is not always reachable through the x2APIC MSR window: on a
 * machine that lacks x2APIC the registers are memory-mapped instead, and the
 * MSR access faults. Both the acknowledgement below and the enable path are
 * therefore routed through the mode-neutral accessors in <uk/intctlr/apic.h>.
 */
#define apic_ack_interrupt	uk_intctlr_apic_eoi
#define apic_enable		uk_intctlr_apic_enable
#endif /* CONFIG_LIBUKINTCTLR_APIC */

#include "pic.h"

#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
__isr int mshv_hv_no_eoi_required(void);
#endif

static struct uk_intctlr_desc intctlr;

static int configure_irq(struct uk_intctlr_irq *irq __unused)
{
	return 0;
}

static int uk_intctlr_xpic_handle_irq(void *data)
{
	struct uk_lcpu_except_irq_ctx *ctx;
	__u32 __unused irq;

	ctx = data;
	uk_intctlr_irq_handle(ctx);

	irq = uk_lcpu_except_irq_ctx_get_irq(ctx);

#if CONFIG_LIBUKINTCTLR_APIC
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	if (!mshv_hv_no_eoi_required())
		apic_ack_interrupt();
#else
	apic_ack_interrupt();
#endif

#if !CONFIG_LIBUKINTCTLR_XPIC_NO_8259
	/* FIXME This is here because right now we only use
	 * APIC for IPIs on SMP. This should be removed as
	 * soon as we fully implement APIC and get rid of
	 * PIC
	 */
	if (irq <= 16)
		pic_ack_irq(irq);
#endif /* !CONFIG_LIBUKINTCTLR_XPIC_NO_8259 */
#else   /* !CONFIG_LIBUKINTCTLR_APIC */
	pic_ack_irq(irq);
#endif /* !CONFIG_LIBUKINTCTLR_APIC */

	return UK_EVENT_HANDLED;
}

UK_EVENT_HANDLER(UK_LCPU_EXCEPT_EVENT_IRQ, uk_intctlr_xpic_handle_irq);

#if CONFIG_LIBUKINTCTLR_XPIC_NO_8259
/* Without an 8259 there is nothing to mask or unmask: the only interrupt
 * sources on such machines are local APIC LVT entries, which are masked
 * through the LVT entry itself by whoever owns it.
 */
static void noop_mask_irq(unsigned int irq __unused) { }
static void noop_unmask_irq(unsigned int irq __unused) { }

static struct uk_intctlr_driver_ops apic_only_ops = {
	.fdt_xlat = __NULL,
	.mask_irq = noop_mask_irq,
	.unmask_irq = noop_unmask_irq,
};
#endif /* CONFIG_LIBUKINTCTLR_XPIC_NO_8259 */

int uk_intctlr_probe(void)
{
	struct uk_intctlr_driver_ops *ops;

#if CONFIG_LIBUKINTCTLR_XPIC_NO_8259
	/* Touching the 8259 command/data ports on a machine that has none is
	 * harmless, but pointless, and the resulting ops would be lying about
	 * being able to mask interrupts.
	 */
	ops = &apic_only_ops;
#else /* !CONFIG_LIBUKINTCTLR_XPIC_NO_8259 */
	int rc;

	rc = pic_init(&ops);
	if (unlikely(rc))
		return rc;
#endif /* !CONFIG_LIBUKINTCTLR_XPIC_NO_8259 */

#if CONFIG_LIBUKINTCTLR_APIC
	apic_enable();
	intctlr.name = "APIC";
#else /* ! CONFIG_LIBUKINTCTLR_APIC */
	intctlr.name = "PIC";
#endif /* CONFIG_LIBUKINTCTLR_APIC */

	intctlr.ops = ops;
	intctlr.ops->configure_irq = configure_irq;

	return uk_intctlr_register(&intctlr);
}
