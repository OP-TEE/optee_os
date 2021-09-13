/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2025, STMicroelectronics - All Rights Reserved
 */

#ifndef STM32_HASH_H
#define STM32_HASH_H

#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <mm/core_memprot.h>
#include <stdint.h>

/* Max size supported is SHA512 */
#define STM32_HASH_MAX_DIGEST_SIZE	U(64)

enum stm32_hash_algo {
	STM32_HASH_MD5,
	STM32_HASH_SHA1,
	STM32_HASH_SHA224,
	STM32_HASH_SHA256,
	STM32_HASH_SHA384,
	STM32_HASH_SHA512,
	STM32_HASH_SHA3_224,
	STM32_HASH_SHA3_256,
	STM32_HASH_SHA3_384,
	STM32_HASH_SHA3_512,
};

enum stm32_hash_mode {
	STM32_HMAC_MODE,
	STM32_HASH_MODE,
};

struct stm32_hash_remain {
	uint32_t *buf;
	size_t len;
};

struct stm32_hash_context {
	struct stm32_hash_device *dev;
	size_t digest_u32;
	size_t block_size;
	size_t queue_size;
	struct stm32_hash_remain remain;
	enum stm32_hash_mode mode;
	enum stm32_hash_algo algo;
	uint32_t save_mode;
	uint32_t imr;
	uint32_t str;
	uint32_t cr;
	uint32_t *csr;
};

size_t stm32_hash_digest_size(struct stm32_hash_context *c);
TEE_Result stm32_hash_deep_copy(struct stm32_hash_context *dst,
				struct stm32_hash_context *src);
TEE_Result stm32_hash_alloc(struct stm32_hash_context *c,
			    enum stm32_hash_mode mode,
			    enum stm32_hash_algo algo);
void stm32_hash_free(struct stm32_hash_context *c);
TEE_Result stm32_hash_update(struct stm32_hash_context *ctx,
			     const uint8_t *buffer, size_t length);
TEE_Result stm32_hash_final(struct stm32_hash_context *c, uint8_t *digest,
			    const uint8_t *key, size_t len);
TEE_Result stm32_hash_init(struct stm32_hash_context *ctx, const uint8_t *key,
			   size_t len);
#endif /* STM32_HASH_H */
