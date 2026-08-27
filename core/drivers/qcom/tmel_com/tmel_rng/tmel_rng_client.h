/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_RNG_CLIENT_H
#define __TMEL_RNG_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tmel_com_client.h>

#define TMEL_RNG_MAX_LENGTH	512

struct tmel_rng_get_msg {
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

TEE_Result tmel_rng_get_random_bytes(void *buf, size_t len);

#endif /* __TMEL_RNG_CLIENT_H */
