/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * Microsoft hypervisor (MSHV) support.
 *
 * Generation 2 virtual machines have no BIOS, no i8254 PIT, no 8259 PIC, no
 * CMOS RTC and no VGA adapter. What they do have is a UEFI firmware, a local
 * APIC, ACPI, a 16550-compatible COM1, and the synthetic MSRs defined by the
 * Hypervisor Top-Level Functional Specification. This file provides the
 * detection and the MSR accessors the rest of the platform needs; the timer
 * work lives in tscclock.c.
 */

#include <errno.h>
#include <uk/arch/time.h>
#include <uk/arch/util.h>
#include <uk/arch/x86_64.h>
#include <uk/assert.h>
#include <uk/boot/earlytab.h>
#include <uk/config.h>
#include <uk/intctlr/apic.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/pm.h>
#include <uk/print.h>
#include <uk/prio.h>

#include <x86/mmio.h>

#include <uk/plat/mshv.h>

#if CONFIG_LIBUKACPI
#include <uk/acpi.h>
#include <uk/acpi/sdt.h>
#endif /* CONFIG_LIBUKACPI */

static int mshv_present;
static int mshv_probed;
static __u32 mshv_features_eax;
static __u32 mshv_features_edx;
static __u32 mshv_stack_properties_eax;
static __u32 mshv_stack_interface_eax;
static __u32 mshv_max_leaf;

static inline __u64 mshv_rdmsr(__u32 msr)
{
	__u32 eax, edx;

	uk_arch_x86_64_rdmsr(msr, &eax, &edx);

	return ((__u64)edx << 32) | (__u64)eax;
}

static inline void mshv_wrmsr(__u32 msr, __u64 val)
{
	uk_arch_x86_64_wrmsr(msr, (__u32)val, (__u32)(val >> 32));
}

int mshv_init(void)
{
	__u32 eax, ebx, ecx, edx;

	/* Detection is cheap but not free, and both the early boot table and
	 * the clock initialisation want the answer. Whoever asks first pays.
	 */
	if (mshv_probed)
		return mshv_present;

	mshv_probed = 1;
	mshv_present = 0;
	mshv_max_leaf = 0;

	/* Bit 31 of CPUID(1).ECX is the architectural "running under a
	 * hypervisor" bit. Without it, the 0x40000000 leaf range is not
	 * guaranteed to exist at all and must not be probed.
	 */
	uk_arch_x86_64_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
	if (!(ecx & (1UL << 31)))
		return 0;

	uk_arch_x86_64_cpuid(MSHV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0,
			     &eax, &ebx, &ecx, &edx);
	if (ebx != MSHV_CPUID_VENDOR_EBX ||
	    ecx != MSHV_CPUID_VENDOR_ECX ||
	    edx != MSHV_CPUID_VENDOR_EDX)
		return 0;

	/* A partition may carry the Microsoft Hv vendor string while speaking
	 * a different interface (nested Xen/KVM emulation does this). Only the
	 * "Hv#1" interface has the synthetic MSRs we rely on.
	 */
	if (eax < MSHV_CPUID_INTERFACE)
		return 0;

	mshv_max_leaf = eax;

	uk_arch_x86_64_cpuid(MSHV_CPUID_INTERFACE, 0, &eax, &ebx, &ecx, &edx);
	if (eax != MSHV_CPUID_INTERFACE_SIGNATURE)
		return 0;

	/* Which synthetic MSRs this partition may touch. Reading an MSR that
	 * is not advertised here raises #GP, so every accessor below is gated
	 * on these bits.
	 */
	uk_arch_x86_64_cpuid(MSHV_CPUID_FEATURES, 0, &eax, &ebx, &ecx, &edx);
	mshv_features_eax = eax;
	mshv_features_edx = edx;

	mshv_present = 1;

	uk_arch_x86_64_cpuid(MSHV_CPUID_VERSION, 0, &eax, &ebx, &ecx, &edx);
	uk_pr_info("Microsoft MSHV %u.%u build %u detected (features 0x%08x, 0x%08x)\n",
		   (ebx >> 16) & 0xffff, ebx & 0xffff, eax,
		   mshv_features_eax, mshv_features_edx);

	/* The virtualisation stack above this partition publishes, in a leaf
	 * of its own, whether the synthetic bus is served by the host or by
	 * the layer beneath. Those two arrangements use different transports
	 * for the same messages, and a guest that picks the wrong one is
	 * never answered rather than refused, so the answer is read here
	 * instead of assumed.
	 *
	 * These leaves are deliberately not covered by the highest function
	 * the partition advertises: the layer that answers them is not the
	 * one that answers the rest, and it never raises that number. Gating
	 * the read on it therefore skips the read on exactly the partitions
	 * the read exists for, and leaves an unasked question looking like an
	 * answer of no.
	 */
	uk_arch_x86_64_cpuid(MSHV_CPUID_STACK_INTERFACE, 0,
			     &eax, &ebx, &ecx, &edx);
	mshv_stack_interface_eax = eax;

	uk_arch_x86_64_cpuid(MSHV_CPUID_STACK_PROPERTIES, 0,
			     &eax, &ebx, &ecx, &edx);
	mshv_stack_properties_eax = eax;

	uk_pr_info("mshv: virtualisation stack interface 0x%08x, properties 0x%08x\n",
		   mshv_stack_interface_eax, mshv_stack_properties_eax);

	return 1;
}

__u32 mshv_stack_interface(void)
{
	return mshv_stack_interface_eax;
}

__u32 mshv_stack_properties(void)
{
	return mshv_stack_properties_eax;
}

int mshv_confidential_vmbus(void)
{
	return !!(mshv_stack_properties_eax & MSHV_STACK_CONFIDENTIAL_VMBUS);
}

int mshv_available(void)
{
	return mshv_present;
}

__u32 mshv_max_cpuid_leaf(void)
{
	return mshv_max_leaf;
}

int mshv_has_features(__u32 features)
{
	if (!mshv_present)
		return 0;

	return (mshv_features_eax & features) == features;
}

__u64 mshv_ref_time_nsec(void)
{
	if (!mshv_has_features(HV_MSR_TIME_REF_COUNT_AVAILABLE))
		return 0;

	return mshv_rdmsr(HV_X64_MSR_TIME_REF_COUNT) * HV_CLOCK_TICK_NSEC;
}

__u64 mshv_tsc_freq(void)
{
	if (!mshv_has_features(HV_ACCESS_FREQUENCY_MSRS))
		return 0;

	return mshv_rdmsr(HV_X64_MSR_TSC_FREQUENCY);
}

__u64 mshv_apic_freq(void)
{
	if (!mshv_has_features(HV_ACCESS_FREQUENCY_MSRS))
		return 0;

	return mshv_rdmsr(HV_X64_MSR_APIC_FREQUENCY);
}

/*
 * Local APIC timer.
 *
 * This is the platform's only usable one-shot timer: the i8254 the rest of
 * plat/kvm/x86 relies on does not exist here. The synthetic timers would work
 * too, but they deliver through the synthetic interrupt controller, which
 * needs a message page and a SINT routing setup; the local APIC timer needs
 * three MSR writes and lands on an ordinary interrupt vector, which is what
 * the existing interrupt plumbing already understands.
 */

/** LVT timer register, one-shot mode */
#define APIC_LVT_TIMER_ONESHOT		(0U << 17)
/** LVT timer register, interrupt masked */
#define APIC_LVT_TIMER_MASKED		(1U << 16)
/** Divide configuration register, divide the input frequency by one */
#define APIC_TIMER_DCR_DIV1		0x0BU

/** The largest value the initial count register holds */
#define APIC_TIMER_MAX_TICKS		0xFFFFFFFFULL

/** How long to measure the APIC timer against the reference counter */
#define APIC_TIMER_CALIBRATE_NSEC	(10ULL * 1000 * 1000)

static __u64 apic_timer_hz;
static __u64 apic_timer_max_nsec;

/* The local APIC is reached through whichever register window the machine
 * presents -- the x2APIC MSRs, or the memory-mapped xAPIC window. Which one
 * it is was settled by uk_intctlr_apic_enable() during uk_intctlr_probe(),
 * which runs before the platform clock is initialised. Registers are named
 * throughout by their x2APIC MSR number either way.
 */
static inline void apic_write(__u32 reg, __u32 val)
{
	uk_intctlr_apic_write(reg, val);
}

static inline __u32 apic_read(__u32 reg)
{
	return uk_intctlr_apic_read(reg);
}

/* Both windows are only usable once the APIC has been brought up, and an
 * x2APIC MSR access made while the APIC is in xAPIC mode raises #GP, which
 * this early in boot is indistinguishable from a hang. Check rather than
 * trust.
 */
static int apic_usable(void)
{
	return uk_intctlr_apic_mode != UK_INTCTLR_APIC_MODE_NONE;
}

/* Measure the APIC timer's input frequency against the partition reference
 * counter. Used when the partition may not read HV_X64_MSR_APIC_FREQUENCY.
 */
static __u64 apic_timer_calibrate(void)
{
	__u64 t_start, t_now;
	__u32 c_start, c_end;

	if (!mshv_has_features(HV_MSR_TIME_REF_COUNT_AVAILABLE))
		return 0;

	/* Free-run the timer with its interrupt masked. At any plausible APIC
	 * frequency a full 2^32 tick countdown lasts seconds, so it cannot
	 * expire within the measurement window.
	 */
	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_DCR, APIC_TIMER_DCR_DIV1);
	apic_write(UK_ARCH_X86_64_APIC_MSR_LVT_TIMER,
		   APIC_LVT_TIMER_MASKED | APIC_LVT_TIMER_ONESHOT);
	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_IC, APIC_TIMER_MAX_TICKS);

	t_start = mshv_rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	c_start = apic_read(UK_ARCH_X86_64_APIC_MSR_TIMER_CC);

	/* The reference counter is monotonic and advertised as available, so
	 * this loop terminates.
	 */
	do {
		t_now = mshv_rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	} while ((t_now - t_start) * HV_CLOCK_TICK_NSEC <
		 APIC_TIMER_CALIBRATE_NSEC);

	c_end = apic_read(UK_ARCH_X86_64_APIC_MSR_TIMER_CC);
	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_IC, 0);

	/* The current count register counts down. */
	if (c_end >= c_start)
		return 0;

	return ((__u64)(c_start - c_end) * UKARCH_NSEC_PER_SEC) /
	       ((t_now - t_start) * HV_CLOCK_TICK_NSEC);
}

int mshv_apic_timer_init(__u8 vector)
{
	__u64 hz;

	if (unlikely(!mshv_present))
		return -ENODEV;

	if (unlikely(!apic_usable())) {
		uk_pr_err("No usable local APIC\n");

		return -ENODEV;
	}

	hz = mshv_apic_freq();
	if (!hz) {
		hz = apic_timer_calibrate();
		if (hz)
			uk_pr_info("Local APIC timer measured at %lu Hz\n",
				   (unsigned long)hz);
	} else {
		uk_pr_info("Local APIC timer runs at %lu Hz\n",
			   (unsigned long)hz);
	}

	if (unlikely(!hz)) {
		uk_pr_err("Could not determine the local APIC timer frequency\n");

		return -ENOTSUP;
	}

	apic_timer_hz = hz;

	/* Beyond this delay the tick count no longer fits the initial count
	 * register. Capping the delay here also keeps the multiplication in
	 * mshv_apic_timer_arm_nsec() inside 64 bits.
	 */
	apic_timer_max_nsec = (APIC_TIMER_MAX_TICKS * UKARCH_NSEC_PER_SEC) / hz;

	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_DCR, APIC_TIMER_DCR_DIV1);
	apic_write(UK_ARCH_X86_64_APIC_MSR_LVT_TIMER,
		   APIC_LVT_TIMER_ONESHOT | vector);
	/* An initial count of zero leaves the timer stopped. */
	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_IC, 0);

	return 0;
}

__u64 mshv_apic_timer_max_nsec(void)
{
	return apic_timer_max_nsec;
}

void mshv_apic_timer_arm_nsec(__u64 nsec)
{
	__u64 ticks;

	UK_ASSERT(apic_timer_hz);

	if (nsec > apic_timer_max_nsec)
		nsec = apic_timer_max_nsec;

	ticks = (nsec * apic_timer_hz) / UKARCH_NSEC_PER_SEC;

	/* Zero would stop the timer rather than fire it immediately. */
	if (!ticks)
		ticks = 1;

	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_IC, (__u32)ticks);
}

void mshv_apic_timer_disarm(void)
{
	apic_write(UK_ARCH_X86_64_APIC_MSR_TIMER_IC, 0);
}

/*
 * Power management.
 *
 * MSHV has no isa-debug-exit device, so shutdown goes through ACPI. The
 * SLP_TYP value to use lives in the \_S5_ package in the DSDT, which we
 * locate with a narrow scan rather than dragging in a full AML interpreter.
 * Where that value is written depends on what the FADT describes:
 *
 *  - A hardware-reduced platform names a SLEEP_CONTROL_REG and expects
 *    (SLP_TYP << 2) | SLP_EN there.
 *  - Otherwise the PM1a control block takes (SLP_TYP << 10) | SLP_EN.
 *
 * The PM1a block itself is described twice: by the legacy 32-bit I/O port
 * field, and by the ACPI 2.0 generic address structure that supersedes it.
 * Real MSHV firmware leaves the legacy field zero and fills in only the
 * generic one, so the generic one has to be honoured -- including its address
 * space id, which decides between port I/O and memory-mapped access.
 */

#if CONFIG_LIBUKACPI

#define ACPI_SLP_EN		(1 << 13)
#define ACPI_SLP_TYP_SHIFT	10

/* The hardware-reduced sleep control register packs the same two fields
 * differently: SLP_TYP in bits 4:2 and SLP_EN in bit 5.
 */
#define ACPI_SLP_CTLR_EN	(1 << 5)
#define ACPI_SLP_CTLR_TYP_SHIFT	2

/* Generic address structure address space ids */
#define ACPI_GAS_ASID_SYSTEM_MEMORY	0x00
#define ACPI_GAS_ASID_SYSTEM_IO		0x01

/* AML opcodes we need to recognise around the \_S5_ name */
#define AML_NAME_OP		0x08
#define AML_ROOT_CHAR		0x5C	/* '\' */
#define AML_PACKAGE_OP		0x12
#define AML_BYTE_PREFIX		0x0A
#define AML_WORD_PREFIX		0x0B
#define AML_ZERO_OP		0x00
#define AML_ONE_OP		0x01

static int s5_valid;
static __u16 s5_slp_typa;

/**
 * Where and how the sleep value has to be written, resolved once from the
 * FADT.
 */
static struct {
	/** Address of the register */
	__u64 addr;
	/** Width of the register in bits */
	__u8 bit_sz;
	/** Non-zero if @addr is a system memory address rather than a port */
	__u8 mmio;
	/** Non-zero for the hardware-reduced SLEEP_CONTROL_REG encoding */
	__u8 reduced;
} s5_reg;

/* Decode a single AML integer term, as used for the SLP_TYP elements of the
 * \_S5_ package. Returns the number of bytes consumed, or 0 if the term is
 * not an integer we understand.
 */
static __sz aml_read_int(const __u8 *p, const __u8 *end, __u16 *out)
{
	if (p >= end)
		return 0;

	switch (*p) {
	case AML_ZERO_OP:
		*out = 0;
		return 1;
	case AML_ONE_OP:
		*out = 1;
		return 1;
	case AML_BYTE_PREFIX:
		if (p + 1 >= end)
			return 0;
		*out = p[1];
		return 2;
	case AML_WORD_PREFIX:
		if (p + 2 >= end)
			return 0;
		*out = (__u16)p[1] | ((__u16)p[2] << 8);
		return 3;
	default:
		return 0;
	}
}

/**
 * Whether the FADT is long enough to actually contain a given field. Fields
 * added by later ACPI revisions are simply absent from a shorter table, and
 * reading them would return whatever follows the table in memory.
 */
#define FADT_HAS_FIELD(fadt, field)					\
	((fadt)->hdr.tab_len >= __offsetof(struct uk_acpi_fadt, field) +	\
	 sizeof(((struct uk_acpi_fadt *)__NULL)->field))

/* A generic address structure is usable if it names an address space we can
 * actually reach and carries a non-zero address and width.
 */
static int acpi_gas_usable(const struct uk_acpi_gas *gas)
{
	if (!gas->addr || !gas->bit_sz)
		return 0;

	return gas->asid == ACPI_GAS_ASID_SYSTEM_MEMORY ||
	       gas->asid == ACPI_GAS_ASID_SYSTEM_IO;
}

static void acpi_s5_reg_from_gas(const struct uk_acpi_gas *gas, int reduced)
{
	s5_reg.addr = gas->addr;
	s5_reg.bit_sz = gas->bit_sz;
	s5_reg.mmio = (gas->asid == ACPI_GAS_ASID_SYSTEM_MEMORY);
	s5_reg.reduced = reduced;
}

/*
 * Work out where the sleep value has to be written, in this order:
 *
 *  1. The hardware-reduced sleep control register, when the FADT says the
 *     platform is hardware-reduced. Such a platform has no PM1 block at all.
 *  2. The legacy 32-bit PM1a control block, which is always an I/O port.
 *  3. The ACPI 2.0 generic address structure for the same block, which is
 *     what firmware fills in when the legacy field is left at zero.
 */
static int acpi_s5_reg_resolve(const struct uk_acpi_fadt *fadt)
{
	int reduced = 0;

	if (FADT_HAS_FIELD(fadt, flags))
		reduced = !!(fadt->flags & UK_ACPI_FADT_FLAGS_HW_REDUCED);

	if (reduced && FADT_HAS_FIELD(fadt, slp_ctlr_blk) &&
	    acpi_gas_usable(&fadt->slp_ctlr_blk)) {
		acpi_s5_reg_from_gas(&fadt->slp_ctlr_blk, 1);

		return 0;
	}

	if (fadt->pm1a_ctlr_blk) {
		s5_reg.addr = fadt->pm1a_ctlr_blk;
		/* The legacy field has no width of its own; PM1_CNT_LEN gives
		 * it in bytes, and the register is 16 bits wide by definition.
		 */
		s5_reg.bit_sz = 16;
		s5_reg.mmio = 0;
		s5_reg.reduced = 0;

		return 0;
	}

	if (FADT_HAS_FIELD(fadt, xpm1a_ctlr_blk) &&
	    acpi_gas_usable(&fadt->xpm1a_ctlr_blk)) {
		acpi_s5_reg_from_gas(&fadt->xpm1a_ctlr_blk, 0);

		return 0;
	}

	return -ENOTSUP;
}

/* Write the assembled sleep value to wherever acpi_s5_reg_resolve() decided
 * it lives, at the width the firmware described.
 */
static int acpi_s5_reg_write(__u32 val)
{
	__vaddr_t vaddr;
	__u64 page;
	int rc;

	if (s5_reg.mmio) {
		page = s5_reg.addr & ~(__u64)(__PAGE_SIZE - 1);

		rc = x86_mmio_map_uc((__paddr_t)page, &vaddr);
		if (unlikely(rc))
			return rc;

		vaddr += (__vaddr_t)(s5_reg.addr - page);

		if (s5_reg.bit_sz <= 8)
			*(volatile __u8 *)vaddr = (__u8)val;
		else if (s5_reg.bit_sz <= 16)
			*(volatile __u16 *)vaddr = (__u16)val;
		else
			*(volatile __u32 *)vaddr = val;

		return 0;
	}

	if (s5_reg.bit_sz <= 8)
		uk_arch_x86_64_outb((__u16)s5_reg.addr, (__u8)val);
	else if (s5_reg.bit_sz <= 16)
		uk_arch_x86_64_outw((__u16)s5_reg.addr, (__u16)val);
	else
		uk_arch_x86_64_outl((__u16)s5_reg.addr, val);

	return 0;
}

static int acpi_s5_lookup(void)
{
	const struct uk_acpi_sdt_hdr *dsdt;
	struct uk_acpi_fadt *fadt;
	const __u8 *p, *end;
	__paddr_t dsdt_paddr;
	__u16 val;
	__sz n;
	int rc;

	if (s5_valid)
		return 0;

	fadt = uk_acpi_get_fadt();
	if (unlikely(!fadt)) {
		uk_pr_warn("ACPI FADT unavailable, cannot use S5 shutdown\n");
		return -ENOENT;
	}

	rc = acpi_s5_reg_resolve(fadt);
	if (unlikely(rc)) {
		uk_pr_warn("ACPI sleep control register not described by FADT\n");
		return rc;
	}

	/* Prefer the 64-bit DSDT pointer, as ACPI 2.0+ requires. */
	dsdt_paddr = fadt->xdsdt_paddr ? (__paddr_t)fadt->xdsdt_paddr
				       : (__paddr_t)fadt->dsdt_paddr;
	if (unlikely(!dsdt_paddr)) {
		uk_pr_warn("ACPI DSDT not described by FADT\n");
		return -ENOENT;
	}

	/* ACPI tables are reachable through their physical address, exactly as
	 * the rest of libukacpi already assumes.
	 */
	dsdt = (const struct uk_acpi_sdt_hdr *)dsdt_paddr;
	if (unlikely(dsdt->tab_len <= sizeof(*dsdt))) {
		uk_pr_warn("ACPI DSDT looks malformed\n");
		return -EINVAL;
	}

	p = (const __u8 *)dsdt + sizeof(*dsdt);
	end = (const __u8 *)dsdt + dsdt->tab_len;

	for (; p + 4 < end; p++) {
		if (p[0] != '_' || p[1] != 'S' || p[2] != '5' || p[3] != '_')
			continue;

		/* The name must be introduced by NameOp, optionally preceded
		 * by the root prefix. Anything else is a coincidental match
		 * inside some other object.
		 */
		if (!((p >= (const __u8 *)dsdt + 1 && p[-1] == AML_NAME_OP) ||
		      (p >= (const __u8 *)dsdt + 2 && p[-1] == AML_ROOT_CHAR &&
		       p[-2] == AML_NAME_OP)))
			continue;

		/* _S5_, PackageOp, PkgLength, NumElements, elements... */
		if (p + 4 >= end || p[4] != AML_PACKAGE_OP)
			continue;

		/* Skip PackageOp, the PkgLength lead byte and NumElements.
		 * The \_S5_ package is always short, so PkgLength is encoded
		 * in a single byte.
		 */
		if (p + 7 >= end)
			continue;

		n = aml_read_int(p + 7, end, &val);
		if (!n)
			continue;

		s5_slp_typa = val;
		s5_valid = 1;

		uk_pr_info("ACPI S5: %s register at 0x%lx (%u bits, %s), SLP_TYPa %u\n",
			   s5_reg.reduced ? "sleep control" : "PM1a control",
			   (unsigned long)s5_reg.addr, s5_reg.bit_sz,
			   s5_reg.mmio ? "memory" : "port I/O",
			   s5_slp_typa);

		return 0;
	}

	uk_pr_warn("ACPI \\_S5_ object not found in DSDT\n");

	return -ENOENT;
}

static int mshv_acpi_shutdown(void)
{
	__u32 val;

	if (acpi_s5_lookup() < 0)
		return -ENOTSUP;

	if (s5_reg.reduced)
		val = ((__u32)s5_slp_typa << ACPI_SLP_CTLR_TYP_SHIFT) |
		      ACPI_SLP_CTLR_EN;
	else
		val = ((__u32)s5_slp_typa << ACPI_SLP_TYP_SHIFT) | ACPI_SLP_EN;

	if (acpi_s5_reg_write(val) < 0)
		return -ENOTSUP;

	/* Should not return. */
	return -EIO;
}

#else /* !CONFIG_LIBUKACPI */

static int mshv_acpi_shutdown(void)
{
	return -ENOTSUP;
}

#endif /* !CONFIG_LIBUKACPI */

static int mshv_halt(void)
{
	return mshv_acpi_shutdown();
}

static int mshv_restart(void)
{
	/* The hypervisor's own reset MSR is the most direct route, and unlike
	 * the ACPI reset register it needs no table parsing.
	 */
	if (mshv_has_features(HV_MSR_RESET_AVAILABLE)) {
		mshv_wrmsr(HV_X64_MSR_RESET, 1);

		return -EIO;
	}

	return mshv_acpi_shutdown();
}

static int mshv_crash(void)
{
	/* Report the crash to the host so it shows up in the VM's event log,
	 * then power off. Both steps are best effort.
	 *
	 * The crash MSRs are gated on their own feature bit for the same
	 * reason every other synthetic MSR is: a partition that has not been
	 * granted them faults on the write. On an encrypted partition that
	 * fault arrives as a #VC the host declines, which would strand the
	 * crash path in the one place a diagnostic is most wanted.
	 */
	if (mshv_present
	    && (mshv_features_edx & HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE)) {
		mshv_wrmsr(HV_X64_MSR_CRASH_P0, 0);
		mshv_wrmsr(HV_X64_MSR_CRASH_P1, 0);
		mshv_wrmsr(HV_X64_MSR_CRASH_P2, 0);
		mshv_wrmsr(HV_X64_MSR_CRASH_P3, 0);
		mshv_wrmsr(HV_X64_MSR_CRASH_P4, 0);
		mshv_wrmsr(HV_X64_MSR_CRASH_CTL, HV_CRASH_CTL_CRASH_NOTIFY);
	}

	return mshv_acpi_shutdown();
}

static const struct uk_pm_ops mshv_pm_ops = {
	.syshalt = mshv_halt,
	.sysrestart = mshv_restart,
	.syscrash = mshv_crash,
};

static int mshv_early_init(struct ukplat_bootinfo __unused *bi)
{
	mshv_init();

	return uk_pm_ops_register(&mshv_pm_ops);
}

UK_BOOT_EARLYTAB_ENTRY(mshv_early_init, UK_PRIO_EARLIEST);
