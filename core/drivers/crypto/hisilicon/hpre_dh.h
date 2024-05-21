/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, HiSilicon Technologies Co., Ltd.
 */

#ifndef __HPRE_DH_H__
#define __HPRE_DH_H__

#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define HPRE_DH_MAX_KEY_BYTES 512
#define HPRE_DH_TOTAL_BUF_SIZE(key_bytes) ((key_bytes) * 4)

struct hpre_dh_msg {
	uint8_t *x_p; /* X and p data in order */
	paddr_t x_p_dma;
	uint8_t *g;
	paddr_t g_dma;
	uint8_t *out;
	paddr_t out_dma;
	uint32_t alg_type;
	uint32_t key_bytes;
	uint32_t xbytes;
	uint32_t pbytes;
	uint32_t gbytes;
	uint32_t out_bytes;
};

TEE_Result hpre_dh_init(void);

#endif
