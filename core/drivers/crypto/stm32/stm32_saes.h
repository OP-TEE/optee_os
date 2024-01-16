/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2023, STMicroelectronics - All Rights Reserved
 */

#ifndef STM32_SAES_H
#define STM32_SAES_H

#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <kernel/mutex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_defines.h>

enum stm32_saes_chaining_mode {
	STM32_SAES_MODE_ECB,
	STM32_SAES_MODE_CBC,
	STM32_SAES_MODE_CTR,
	STM32_SAES_MODE_GCM,
	STM32_SAES_MODE_CCM,
};

enum stm32_saes_key_selection {
	STM32_SAES_KEY_SOFT,
	STM32_SAES_KEY_DHU,           /* Derived HW unique key */
	STM32_SAES_KEY_BH,            /* Boot HW key */
	STM32_SAES_KEY_BHU_XOR_BH,    /* XOR of DHUK and BHK */
	STM32_SAES_KEY_WRAPPED
};

struct stm32_saes_context {
	vaddr_t base;
	uint32_t cr;
	struct mutex *lock;	/* Save the HW instance mutex */
	uint32_t assoc_len;
	uint32_t load_len;
	uint32_t key[8]; /* In HW byte order */
	uint32_t iv[4];  /* In HW byte order */
	uint32_t susp[8];
	uint32_t extra[4];
	size_t extra_size;
};

TEE_Result stm32_saes_init(struct stm32_saes_context *ctx, bool is_decrypt,
			   enum stm32_saes_chaining_mode ch_mode,
			   enum stm32_saes_key_selection key_select,
			   const void *key, size_t key_len, const void *iv,
			   size_t iv_len);
TEE_Result stm32_saes_update(struct stm32_saes_context *ctx, bool last_block,
			     uint8_t *data_in, uint8_t *data_out,
			     size_t data_len);
TEE_Result stm32_saes_update_assodata(struct stm32_saes_context *ctx,
				      uint8_t *data, size_t data_len);
TEE_Result stm32_saes_update_load(struct stm32_saes_context *ctx,
				  bool last_block, uint8_t *data_in,
				  uint8_t *data_out, size_t data_len);
TEE_Result stm32_saes_final(struct stm32_saes_context *ctx, uint8_t *tag,
			    size_t tag_len);

TEE_Result stm32_saes_kdf(struct stm32_saes_context *ctx,
			  enum stm32_saes_key_selection key_sel,
			  const void *key, size_t key_size,
			  const void *input, size_t input_size,
			  uint8_t *subkey, size_t subkey_size);

#endif
