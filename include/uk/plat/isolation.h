/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_PLAT_ISOLATION_H__
#define __UK_PLAT_ISOLATION_H__

#include <uk/arch/types.h>
#include <uk/essentials.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The technology, if any, isolating this guest's memory from its host */
enum uk_isolation_type {
	UK_ISOLATION_NONE = 0,
	UK_ISOLATION_VBS,
	UK_ISOLATION_SNP,
	UK_ISOLATION_TDX,
};

/**
 * Report which isolation technology covers this guest.
 *
 * Asked of the platform rather than of the hardware: the architectural CPUID
 * leaves report nothing useful on a partition whose isolation is arranged by
 * the hypervisor, so a guest cannot answer this for itself.
 *
 * @return one of the UK_ISOLATION_* values; UK_ISOLATION_NONE on a platform
 *   that has no notion of isolation at all
 */
enum uk_isolation_type uk_isolation_type(void);

/**
 * The name of an isolation technology, for display.
 *
 * @param type
 *   One of the UK_ISOLATION_* values
 *
 * @return a constant string, never NULL
 */
static inline const char *uk_isolation_name(enum uk_isolation_type type)
{
	switch (type) {
	case UK_ISOLATION_NONE:
		return "none";
	case UK_ISOLATION_VBS:
		return "vbs";
	case UK_ISOLATION_SNP:
		return "snp";
	case UK_ISOLATION_TDX:
		return "tdx";
	default:
		return "unknown";
	}
}

#ifdef __cplusplus
}
#endif

#endif /* __UK_PLAT_ISOLATION_H__ */
