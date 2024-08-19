/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 HiSilicon Limited.
 */
#ifndef __HPRE_MONTGOMERY_H__
#define __HPRE_MONTGOMERY_H__

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define HPRE_X_KEY_PARAM_NUM 3
#define X25519_KEY_BITS 256
#define X448_KEY_BITS 448
#define HPRE_HW_X25519_KBITS 256
#define HPRE_HW_X448_KBITS 576
#define HPRE_MONTGOMERY_TOTAL_BUF_SIZE(key_bytes) ((key_bytes) * 5)
#define HPRE_X_KEY_SIZE(hsz)	((hsz) * HPRE_X_KEY_PARAM_NUM)

struct hpre_montgomery_msg {
	uint8_t *key;
	paddr_t key_dma;
	uint8_t *in;
	paddr_t in_dma;
	uint8_t *out;
	paddr_t out_dma;
	uint32_t alg_type;
	uint32_t key_bytes;
	uint32_t curve_bytes;
	uint32_t x_bytes;
	uint32_t result;
};

#endif
