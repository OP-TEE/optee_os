// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <compiler.h>
#include <crypto/crypto.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>

static uint8_t *rng_fifo;
static size_t rng_fifo_size;
static size_t rng_fifo_pos;
static struct mutex rng_fifo_mutex = MUTEX_INITIALIZER;

/* This is a HW RNG, no need for seeding */
TEE_Result crypto_rng_init(const void *data __unused, size_t dlen __unused)
{
	TEE_Result ret;

	/*
	 * We do not need to seed our HW RNG, but we do need to allocate
	 * a buffer for storing extra entropy, set that up here.
	 */
	ret = hw_get_max_available_entropy(&rng_fifo_size);
	if (ret != TEE_SUCCESS) {
		rng_fifo_size = 0;
		return ret;
	}

	rng_fifo = malloc(rng_fifo_size);
	if (!rng_fifo)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

/* This is a HW RNG, no need to add entropy */
void crypto_rng_add_event(enum crypto_rng_src sid __unused,
			  unsigned int *pnum __unused,
			  const void *data __unused,
			  size_t dlen __unused)
{
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	uint8_t *buffer = buf;
	size_t buffer_pos = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&rng_fifo_mutex);

	while (buffer_pos < blen) {
		/* Refill our FIFO */
		if (rng_fifo_pos == 0) {
			while (true) {
				ret = hw_get_available_entropy(rng_fifo);
				if (ret == TEE_SUCCESS)
					break;
				else if (ret != TEE_ERROR_BUSY)
					goto out;
			}
		}

		buffer[buffer_pos++] = rng_fifo[rng_fifo_pos++];
		if (rng_fifo_pos == rng_fifo_size)
			rng_fifo_pos = 0;
	}

out:
	mutex_unlock(&rng_fifo_mutex);
	return ret;
}
