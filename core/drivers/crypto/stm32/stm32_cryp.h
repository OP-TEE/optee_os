/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, STMicroelectronics - All Rights Reserved
 */

#ifndef STM32_CRYP_H
#define STM32_CRYP_H

#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Platform data related to CRYP instance
 * @base - IO memory base address
 * @clk - CRYP clock reference
 * @rstctrl - CRYP reset controller reference
 */
struct stm32_cryp_platdata {
	struct io_pa_va base;
	struct clk *clock;
	struct rstctrl *reset;
};

enum stm32_cryp_algo_mode {
	STM32_CRYP_MODE_TDES_ECB,
	STM32_CRYP_MODE_TDES_CBC,
	STM32_CRYP_MODE_DES_ECB,
	STM32_CRYP_MODE_DES_CBC,
	STM32_CRYP_MODE_AES_ECB,
	STM32_CRYP_MODE_AES_CBC,
	STM32_CRYP_MODE_AES_CTR,
	STM32_CRYP_MODE_AES_GCM,
	STM32_CRYP_MODE_AES_CCM,
};

/*
 * Full CRYP context.
 * Store CRYP internal state to be able to compute any supported algorithm.
 */
struct stm32_cryp_context {
	vaddr_t base;
	uint32_t cr;
	struct mutex *lock; /* Protect CRYP HW instance access */
	uint32_t assoc_len;
	uint32_t load_len;
	uint32_t key[8]; /* In HW byte order */
	size_t key_size;
	size_t block_u32;
	uint32_t iv[4];  /* In HW byte order */
	uint32_t pm_gcmccm[8];
	union {
		uint32_t pm_gcm[8];
		uint32_t ctr0_ccm[4];
	};
	uint32_t extra[4];
	size_t extra_size;
};

TEE_Result stm32_cryp_init(struct stm32_cryp_context *ctx, bool is_decrypt,
			   enum stm32_cryp_algo_mode mode,
			   const void *key, size_t key_size, const void *iv,
			   size_t iv_size);
TEE_Result stm32_cryp_update(struct stm32_cryp_context *ctx, bool last_block,
			     uint8_t *data_in, uint8_t *data_out,
			     size_t data_size);
TEE_Result stm32_cryp_update_assodata(struct stm32_cryp_context *ctx,
				      uint8_t *data, size_t data_size);
TEE_Result stm32_cryp_update_load(struct stm32_cryp_context *ctx,
				  uint8_t *data_in, uint8_t *data_out,
				  size_t data_size);
TEE_Result stm32_cryp_final(struct stm32_cryp_context *ctx, uint8_t *tag,
			    size_t tag_size);
#endif
