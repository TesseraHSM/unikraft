/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_PLAT_SHMEM_H__
#define __UK_PLAT_SHMEM_H__

#include <uk/arch/types.h>
#include <uk/essentials.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Prepare host-visible memory.
 *
 * A guest whose memory is isolated from its host cannot hand a device an
 * ordinary allocation: the host cannot read it. Such a platform publishes a
 * separate pool instead, and a driver that has to be reachable by a device
 * asks for its buffers from here.
 *
 * Safe to call more than once.
 *
 * @return 0 on success or a negative errno
 */
int ukplat_shmem_init(void);

/**
 * Report whether device-visible buffers have to come from this interface.
 *
 * Reads the isolation state that ukplat_shmem_init() establishes, so that
 * call has to come first. Zero on a guest whose memory the host can already
 * read, where an ordinary allocation is device-visible and nothing here is
 * needed.
 */
int ukplat_shmem_required(void);

/**
 * Allocate host-visible memory.
 *
 * @param size
 *   Number of bytes, rounded up to whole pages
 * @param attr
 *   UK_PAGING_PAGE_ATTR_* protection for the guest's own mapping
 *
 * @return the guest virtual address, or NULL
 */
void *ukplat_shmem_alloc(__sz size, unsigned long attr);

/** Release memory obtained from ukplat_shmem_alloc() */
void ukplat_shmem_free(void *ptr);

/**
 * The address a device is given for a host-visible buffer.
 *
 * Not simply the physical address: a platform that publishes memory through
 * an alias above a boundary reports the aliased address here.
 */
__paddr_t ukplat_shmem_gpa(const void *addr);

#if CONFIG_HAVE_SNP_CONFIDENTIAL_MMIO
/**
 * Perform a device MMIO access on the guest's behalf.
 *
 * On an isolated guest a load or store to a device mapping does not reach
 * the device, so the access is asked of the platform instead.
 *
 * @param gpa
 *   Guest physical address of the device register
 * @param value
 *   Buffer of @width bytes read into, or written from
 * @param width
 *   Access width in bytes
 * @param write
 *   Non-zero for a store, zero for a load
 *
 * @return 0 on success or a negative errno
 */
int ukplat_confidential_mmio(__paddr_t gpa, void *value, unsigned int width,
			     int write);

/**
 * Ready the transport ukplat_confidential_mmio() runs over.
 *
 * Safe to call more than once.
 *
 * @return 0 when device accesses can be made this way, -ENOTSUP on a machine
 *   where the guest is not the one performing them, or another negative errno
 */
int ukplat_confidential_mmio_init(void);
#endif /* CONFIG_HAVE_SNP_CONFIDENTIAL_MMIO */

#ifdef __cplusplus
}
#endif

#endif /* __UK_PLAT_SHMEM_H__ */
