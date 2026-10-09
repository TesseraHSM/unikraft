/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * Copyright (c) 2018, NEC Europe Ltd., NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __UK_PLAT_COMMON_X86_TSCCLOCK_H__
#define __UK_PLAT_COMMON_X86_TSCCLOCK_H__

#include <uk/arch/types.h>

int tscclock_init(void);
__u64 tscclock_monotonic(void);
__u64 tscclock_epochoffset(void);

/*
 * TSC accounting shared by the clock and whichever backend drives it. The
 * backend that calibrates the TSC writes the multiplier and the base; the
 * shared clock advances the monotonic base from them.
 */
extern __u64 tscclock_time_base;
extern __u64 tscclock_tsc_base;
extern __u32 tscclock_tsc_mult;
extern __u64 tscclock_epoch_offset;

/*
 * The PC implementation, kept separate because a machine without an i8254 or
 * a CMOS RTC cannot run it: an absent port reads back 0xff, which turns the
 * calibration loop and the RTC update poll into loops that never end.
 */
int tscclock_pc_init(void);
void tscclock_pc_cpu_block(__u64 until);

#if CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND
/*
 * A platform whose machine supplies its own monotonic counter and timer
 * implements these instead. The backend is chosen at link time, and declines
 * at run time when the hypervisor it needs turns out not to be there, which
 * is what lets the same image run against plain PC hardware.
 */

/**
 * Non-zero when the machine this backend drives is the one being run on. The
 * answer is separate from initialisation so that a machine that is present
 * but fails to start its clock is never mistaken for an absent one.
 */
int tscclock_backend_available(void);

/**
 * Take over timekeeping. Called only once the backend's machine is known to
 * be present, so every error it returns is a real failure to start the clock.
 */
int tscclock_backend_init(void);

/** Non-zero once the backend counter, rather than the TSC, tells the time */
int tscclock_backend_monotonic_active(void);

/** Read the backend counter and update the shared monotonic base from it */
__u64 tscclock_backend_monotonic(void);

/** Block until @until using the backend timer. Returns 0 when it did. */
int tscclock_backend_cpu_block(__u64 until);
#endif /* CONFIG_PLAT_GUEST_X86_CLOCK_BACKEND */

#endif /* __UK_PLAT_COMMON_X86_TSCCLOCK_H__ */

