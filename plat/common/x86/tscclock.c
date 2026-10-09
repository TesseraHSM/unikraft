/* SPDX-License-Identifier: ISC */
/* Copyright (c) Microsoft Corporation. */
/*
 * Authors: Dan Williams
 *          Martin Lucina
 *          Ricardo Koller
 *          Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2015-2017 IBM
 * Copyright (c) 2016-2017 Docker, Inc.
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Taken from solo5 tscclock.c */

/*-
 * Copyright (c) 2014, 2015 Antti Kantee.  All Rights Reserved.
 * Copyright (c) 2015 Martin Lucina.  All Rights Reserved.
 * Modified for solo5 by Ricardo Koller <kollerr@us.ibm.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>

#include <uk/arch/util.h>
#include <uk/arch/x86_64.h>
#include <uk/config.h>
#include <uk/lcpu.h>
#include <uk/plat/time.h>
#include <uk/timeconv.h>
#include <uk/print.h>
#include <uk/assert.h>
#include <uk/atomic.h>

#include <x86/tscclock.h>

/* RTC wall time offset at monotonic time base. */
__u64 tscclock_epoch_offset;

/* Base time values at the last call to tscclock_monotonic(). */
__u64 tscclock_time_base;
__u64 tscclock_tsc_base;

/* Multiplier for converting TSC ticks to nsecs. (0.32) fixed point. */
__u32 tscclock_tsc_mult;

/*
 * Return monotonic time using TSC clock.
 */
__u64 tscclock_monotonic(void)
{
	__u64 tsc_now, tsc_delta;

#if CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND
	if (tscclock_backend_monotonic_active())
		return tscclock_backend_monotonic();
#endif /* CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND */

	/*
	 * Update tscclock_time_base (monotonic time) and tscclock_tsc_base
	 * (TSC time).
	 */
	tsc_now = uk_arch_x86_64_rdtsc();
	tsc_delta = tsc_now - tscclock_tsc_base;
	if (tsc_delta >= UINT64_MAX / 2)
		tsc_delta = 1;
	tscclock_time_base += uk_arch_x86_64_mul64_32(tsc_delta,
						      tscclock_tsc_mult);
	tscclock_tsc_base = tsc_now;

	return tscclock_time_base;
}

/*
 * Calibrate TSC and initialise TSC clock.
 */
int tscclock_init(void)
{
#if CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND
	/* An image configured for a machine with a synthetic clock still runs
	 * unchanged on one that has the legacy devices, which is what makes it
	 * testable under QEMU. Only the absence of the backend's machine sends
	 * this to the legacy devices; once that machine is present, a clock
	 * that fails to start is reported rather than replaced, because the
	 * i8254 and the CMOS RTC need not exist there to fall back on.
	 */
	if (tscclock_backend_available())
		return tscclock_backend_init();
#endif /* CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND */

	return tscclock_pc_init();
}

/*
 * Return epoch offset (wall time offset to monotonic clock start).
 */
__u64 tscclock_epochoffset(void)
{
	return tscclock_epoch_offset;
}

/*
 * Returns early if any interrupts are serviced, or if the requested delay is
 * too short. Must be called with interrupts disabled, will enable interrupts
 * "atomically" during idle loop.
 *
 * This function must be called only from the scheduler. It will screw
 * your system if you do otherwise. And, there is no reason you
 * actually want to use it anywhere else. THIS IS NOT A YIELD or any
 * kind of mutex_lock. It will simply halt the cpu, not allowing any
 * other thread to execute.
 */
static void tscclock_cpu_block(__u64 until)
{
	UK_ASSERT(uk_lcpu_irqs_disabled());

#if CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND
	if (tscclock_backend_cpu_block(until) == 0)
		return;
#endif /* CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND */

	tscclock_pc_cpu_block(until);
}

unsigned long sched_have_pending_events;

void time_block_until(__snsec until)
{
	while ((__snsec) ukplat_monotonic_clock() < until) {
		tscclock_cpu_block(until);

		if (uk_and_relax(&sched_have_pending_events, 0))
			break;
	}
}
