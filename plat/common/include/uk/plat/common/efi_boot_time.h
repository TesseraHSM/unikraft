/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_PLAT_COMMON_EFI_BOOT_TIME_H__
#define __UK_PLAT_COMMON_EFI_BOOT_TIME_H__

#include <uk/arch/types.h>

/** UEFI's "time zone is unknown" sentinel for struct uk_efi_time.time_zone */
#define UKPLAT_EFI_UNSPECIFIED_TIMEZONE		0x07FF

/**
 * Wall-clock time as the UEFI firmware reported it, just before the EFI stub
 * exited boot services.
 *
 * Once boot services are gone the runtime services are no longer mapped, so a
 * machine without a CMOS RTC has no other opportunity to learn the date.
 * Filled in by the EFI stub; consumed by whichever platform clock derives a
 * wall-clock epoch offset from it.
 */
struct ukplat_efi_boot_time {
	/** Zero if the firmware clock could not be read */
	__u8 valid;
	__s64 year;
	__u8 mon;
	__u8 day;
	__u8 hour;
	__u8 min;
	__u8 sec;
	/** Minutes east of UTC, or UKPLAT_EFI_UNSPECIFIED_TIMEZONE */
	__s16 tz_minutes;
};

extern struct ukplat_efi_boot_time ukplat_efi_boot_time;

#endif /* __UK_PLAT_COMMON_EFI_BOOT_TIME_H__ */
