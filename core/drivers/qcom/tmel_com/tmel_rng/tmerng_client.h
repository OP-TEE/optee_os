/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMERNG_H
#define __TMERNG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>

/* TME-Lite RNG client interface */

/* Maximum random bytes that can be requested in a single call */
#define TME_RNG_MAX_LENGTH	512

/* Sequencer Status Response */
struct tme_sequencer_status {
	uint32_t tme_error_status;
	uint32_t seq_error_status;
	uint32_t seq_kp_error_status0;
	uint32_t seq_kp_error_status1;
	uint32_t seq_rsp_status;
};

/* TME RNG Get Message Structure */
struct tme_rng_get_msg {
	struct {
		uint32_t length;
	} input;
	struct {
		uint32_t rng_buf_pdata;
		uint32_t rng_buf_length;
		uint32_t rng_buf_length_used;
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
