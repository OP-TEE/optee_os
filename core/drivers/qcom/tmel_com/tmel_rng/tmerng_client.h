/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMERNG_H
#define __TMERNG_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tmecom_client.h>

/* TME-Lite RNG client interface */

/* Maximum random bytes that can be requested in a single call */
#define TME_RNG_MAX_LENGTH	512

/* TME RNG Get Message Structure */
struct tme_rng_get_msg {
	struct {
		uint32_t length;
	} input;
	struct {
		uint32_t buf;
		uint32_t buf_len;
		uint32_t buf_len_used;
		uint32_t status;
		struct tme_sequencer_status seq_status;
	} output;
};

/*
 * Fill @buf with @len random bytes via TME-Lite, falling back to the IMEM
 * entropy pool when TME-Lite is bypassed. Returns a TEE_Result.
 */
TEE_Result tme_hw_get_random_bytes(void *buf, size_t len);

#endif /* __TMERNG_H */
