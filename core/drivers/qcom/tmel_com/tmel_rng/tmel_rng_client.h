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

/* Largest chunk requested from TME-Lite in one message, in bytes */
#define TMEL_RNG_MAX_LENGTH	512U

/*
 * struct tmel_rng_get_msg - Message to get random data from TME-Lite
 * @input.length:        bytes of random data wanted
 * @output.buf:          physical address TME-Lite writes the data to
 * @output.buf_len:      size of that buffer in bytes
 * @output.buf_len_used: bytes TME-Lite wrote
 * @output.status:       TME_STATUS_* result
 * @output.seq_status:   sequencer error status
 */
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

/*
 * tmel_rng_get_random_bytes() - Fill a buffer with random bytes from TME-Lite
 * @buf: buffer to fill
 * @len: number of bytes; fetched in chunks of at most TMEL_RNG_MAX_LENGTH
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @buf is NULL or @len is 0.
 *   TEE_ERROR_BAD_STATE      the TME-Lite session is not up.
 *   other                    tmel_com_client_send_message() error, or TME-Lite
 *                            failed the request.
 */
TEE_Result tmel_rng_get_random_bytes(void *buf, size_t len);

#endif /* __TMEL_RNG_CLIENT_H */
