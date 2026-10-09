/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

/*
 * MSHV Generation 2 timekeeping.
 *
 * There is no CMOS RTC and no i8254 here, and reading either would not fail
 * loudly: an unimplemented port returns 0xff, which turns both the RTC update
 * poll and the PIT calibration loop into loops that never terminate. Neither
 * is therefore allowed to run. The hypervisor supplies everything they were
 * there for: a monotonic 100 ns counter, the virtual TSC frequency, and the
 * local APIC timer frequency, all through synthetic MSRs.
 */

#include <errno.h>
#include <uk/arch/util.h>
#include <uk/arch/x86_64.h>
#include <uk/config.h>
#include <uk/lcpu.h>
#include <uk/plat/time.h>
#include <uk/timeconv.h>
#include <uk/print.h>
#include <uk/assert.h>

#include <uk/plat/mshv.h>
#include <uk/plat/common/efi_boot_time.h>
#include <x86/tscclock.h>
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
#include <x86/snp.h>
#endif

/** Reference counter value corresponding to a monotonic time of zero */
static __u64 hv_refcnt_base;
/** Set when the partition reference counter backs the monotonic clock */
static int hv_refcnt_active;
/** Set when the local APIC timer is armed by tscclock_backend_cpu_block() */
static int hv_apic_timer_active;

/*
 * Minimum delay worth arming the local APIC timer for. Below this, the cost
 * of programming the timer and taking the interrupt exceeds the delay itself,
 * so spin instead, exactly as the i8254 path does.
 */
#define HV_TIMER_MIN_DELTA_NSEC		5000

/*
 * The interrupt vector the local APIC timer raises.
 *
 * The platform timer is IRQ 0 (see ukplat_time_get_irq()), and the x86 trap
 * table maps IRQ n onto vector 32 + n. Routing the APIC timer there means the
 * handler ukplat_time_init() registers is reached through the ordinary
 * interrupt path, with no special-casing anywhere else.
 */
#define HV_TIMER_IRQ			0
#define HV_TIMER_VECTOR			(32 + HV_TIMER_IRQ)

/*
 * Derive the wall-clock time at boot from the firmware clock the EFI stub
 * read before it exited boot services. Only the EFI stub can take that
 * reading, so a guest entered through any other boot protocol starts its
 * wall clock at the epoch, exactly as one whose firmware refused to answer.
 */
#if CONFIG_PLAT_GUEST_BOOT_PROTO_EFI_STUB
static __u64 mshv_boot_wallclock(void)
{
	struct uktimeconv_bmkclock dt;
	__u64 nsec;

	if (!ukplat_efi_boot_time.valid) {
		uk_pr_warn("No firmware clock reading, wall clock starts at the epoch\n");

		return 0;
	}

	dt.dt_year = ukplat_efi_boot_time.year;
	dt.dt_mon = ukplat_efi_boot_time.mon;
	dt.dt_day = ukplat_efi_boot_time.day;
	dt.dt_hour = ukplat_efi_boot_time.hour;
	dt.dt_min = ukplat_efi_boot_time.min;
	dt.dt_sec = ukplat_efi_boot_time.sec;

	nsec = uktimeconv_bmkclock_to_nsec(&dt);

	/* UEFI reports the time in the firmware's local zone, with the offset
	 * from UTC alongside it. When the firmware declines to say which zone
	 * that is, the reading is used as-is, which is what MSHV's firmware
	 * intends: it reports UTC and leaves the zone unspecified.
	 */
	if (ukplat_efi_boot_time.tz_minutes != UKPLAT_EFI_UNSPECIFIED_TIMEZONE)
		nsec += (__s64)ukplat_efi_boot_time.tz_minutes * 60 *
			UKARCH_NSEC_PER_SEC;

	return nsec;
}
#else /* !CONFIG_PLAT_GUEST_BOOT_PROTO_EFI_STUB */
static __u64 mshv_boot_wallclock(void)
{
	uk_pr_warn("No firmware clock reading, wall clock starts at the epoch\n");

	return 0;
}
#endif /* !CONFIG_PLAT_GUEST_BOOT_PROTO_EFI_STUB */

int tscclock_backend_monotonic_active(void)
{
	return hv_refcnt_active;
}

__u64 tscclock_backend_monotonic(void)
{
	__u64 now = mshv_ref_time_nsec();

	/* The partition reference counter is monotonic by definition, but a
	 * stale reading must never be allowed to move the clock backwards for
	 * a caller that already saw a later one.
	 */
	if (likely(now > hv_refcnt_base))
		tscclock_time_base = now - hv_refcnt_base;

	return tscclock_time_base;
}

int tscclock_backend_available(void)
{
	return mshv_available();
}

int tscclock_backend_init(void)
{
	__u64 tsc_freq;
	int rc;

	/*
	 * Monotonic time. The partition reference counter is the time source
	 * MSHV intends guests to use: it is monotonic, it counts in fixed
	 * 100 ns units regardless of what the TSC is doing, and it survives
	 * live migration between hosts whose TSCs differ.
	 */
	if (mshv_has_features(HV_MSR_TIME_REF_COUNT_AVAILABLE)) {
		hv_refcnt_base = mshv_ref_time_nsec();
		hv_refcnt_active = 1;

		uk_pr_info("Clock source: MSHV partition reference counter\n");
	}

	/*
	 * The TSC is still the fallback, and is calibrated from the frequency
	 * the hypervisor reports. The generic hypervisor timing leaf the
	 * legacy path uses, CPUID 0x40000010, is a KVM and VMware convention
	 * that MSHV does not implement.
	 */
	tscclock_tsc_base = uk_arch_x86_64_rdtsc();
	tsc_freq = mshv_tsc_freq();
	if (tsc_freq) {
		tscclock_tsc_mult = (UKARCH_NSEC_PER_SEC << 32) / tsc_freq;

		uk_pr_info("TSC frequency is %llu Hz\n",
			   (unsigned long long)tsc_freq);
	} else if (!hv_refcnt_active) {
		/* Without either source there is nothing left to fall back on:
		 * the i8254 the legacy path calibrates against does not exist
		 * on this machine, and trying it would hang the boot.
		 */
		uk_pr_err("MSHV offers neither a reference counter nor a TSC frequency\n");

		return -ENOTSUP;
	}

	/* Monotonic time begins here. */
	tscclock_monotonic();

	tscclock_epoch_offset = mshv_boot_wallclock() - tscclock_time_base;

	/*
	 * Timer interrupts. Without this the scheduler halts on the first
	 * sleep and is never woken, since nothing else on this machine can
	 * raise a timer interrupt.
	 */
	rc = mshv_apic_timer_init(HV_TIMER_VECTOR);
	if (unlikely(rc)) {
		uk_pr_err("Failed to initialise the local APIC timer: %d\n",
			  rc);

		return rc;
	}

	hv_apic_timer_active = 1;

	return 0;
}

/*
 * Wait until `until`, or until an interrupt arrives, using the local APIC
 * timer. Same contract as the PC implementation.
 */
int tscclock_backend_cpu_block(__u64 until)
{
	__u64 now, delta_ns;

	if (!hv_apic_timer_active)
		return -ENODEV;

	now = ukplat_monotonic_clock();
	if (until <= now)
		delta_ns = 0;
	else
		delta_ns = until - now;

	if (delta_ns < HV_TIMER_MIN_DELTA_NSEC) {
		/* Too short to be worth a timer. Spin, but open the interrupt
		 * window briefly so that pending work can arrive.
		 */
		uk_lcpu_enable_irq();
		uk_arch_x86_64_nop(); /* ints are enabled 1 instr after sti */
		uk_lcpu_disable_irq();

		return 0;
	}

	/* Delays longer than the timer's range wake us early; the caller
	 * loops, so an early wakeup costs an extra iteration and nothing else.
	 */
#if CONFIG_MSHV_SNP_RESTRICTED_INJECTION
	if (snp_sev_status_raw() & SNP_SEV_STATUS_RESTRICT_INJ)
		UK_ASSERT(mshv_hv_doorbell_ready());
#endif
	mshv_apic_timer_arm_nsec(delta_ns);

	uk_lcpu_halt_irq();

	/* Any interrupt may have ended the halt, so cancel the timer rather
	 * than leave a stale one to fire into the next sleep.
	 */
	mshv_apic_timer_disarm();

	return 0;
}
