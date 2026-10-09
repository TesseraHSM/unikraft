/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) Microsoft Corporation.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __UK_PLAT_SNP_H__
#define __UK_PLAT_SNP_H__

#include <uk/arch/types.h>
#include <uk/essentials.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Length of the key a guest request is authenticated under */
#define UK_SNP_VMPCK_LEN		32

/**
 * Obtain the key this guest's requests to the security processor must be
 * authenticated under, and the index that names it.
 *
 * Where the guest owns its own partition the key is read out of a page the
 * launch process leaves behind. That page is absent under a paravisor -
 * it belongs to a higher privilege level - so the key is asked for
 * instead, and the answer is whatever key belongs to the level that asked.
 * A caller does not choose. The index matters as much as the key itself:
 * it travels in the clear in every message, and the firmware uses it to
 * decide which key to verify against.
 *
 * The key is secret. It must not be written to memory the host can read,
 * and it must not be logged.
 *
 * @param key
 *   Filled with UK_SNP_VMPCK_LEN bytes on success
 * @param index
 *   Filled with the index naming that key
 *
 * @return 0 on success, or a negative errno. -ENOTSUP means this platform
 *   will not give a key to a guest at this privilege level, which is a
 *   settled answer rather than a transient failure.
 */
int uk_snp_vmpck(__u8 key[UK_SNP_VMPCK_LEN], __u8 *index);

/**
 * Hand a prepared request to the security processor and wait for its
 * answer.
 *
 * Both buffers must be page-aligned, a page long, and private to this
 * guest: the exchange is only meaningful because the host cannot read it.
 * Neither buffer's contents are interpreted here - framing and
 * authentication belong to the caller, which is the only party holding
 * the key.
 *
 * @param req
 *   The page holding the authenticated request
 * @param resp
 *   The page the answer is to be written to
 * @param fw_err
 *   If non-NULL, receives what the firmware reported. This is set even
 *   when the call fails, because a firmware refusal names what was wrong
 *   with the message and is the only way to tell a malformed request from
 *   one that never arrived.
 *
 * @return 0 if the firmware answered without complaint, -EPROTO if it
 *   refused the message, -EIO if the layer beneath refused to carry it,
 *   -EINVAL if either buffer is not page-aligned, or -ENODEV if there is
 *   no way to reach the firmware at all.
 */
int uk_snp_guest_request(const void *req, void *resp, __u64 *fw_err);

/**
 * Take the message sequence number to use for the next request, and
 * record it as spent.
 *
 * A number may authenticate exactly one message under a given key, and
 * the firmware refuses anything it has seen before. Where the count is
 * kept persistently - a guest holding its own secrets page, with no
 * paravisor above it - it continues from whatever the launch process left
 * rather than restarting, and this call both reads and advances it. Two
 * numbers are consumed per exchange, because the firmware answers under
 * the number following the request's.
 *
 * The number is spent by this call, not by the request succeeding. What
 * makes a number unusable is the firmware having seen it, which the guest
 * can neither take back nor reliably observe.
 *
 * @param index
 *   The key index the count belongs to
 * @param seqno
 *   Filled with the number to use
 *
 * @return 0 on success, -ENOTSUP if this guest keeps no persistent count
 *   and the caller should maintain its own, or -EOVERFLOW if the count
 *   has been exhausted and the key can no longer be used.
 */
int uk_snp_seqno_reserve(__u8 index, __u64 *seqno);

/**
 * Report whether this guest can reach the security processor at all.
 *
 * @return 1 if it can, 0 otherwise.
 */
int uk_snp_available(void);

#ifdef __cplusplus
}
#endif

#endif /* __UK_PLAT_SNP_H__ */
