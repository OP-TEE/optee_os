/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2024, HiSilicon Technologies Co., Ltd.
 */

#ifndef __HPRE_ECC_H__
#define __HPRE_ECC_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

enum ecc_verify_status {
	ECC_VERIFY_ERR = 0,
	ECC_VERIFY_SUCCESS = 1,
};

struct hpre_ecc_dh {
	uint32_t d_bytes;
	uint32_t x_bytes;
	uint32_t y_bytes;
	uint32_t rx_bytes;
	uint32_t ry_bytes;
};

struct hpre_ecc_sign {
	uint32_t d_bytes;
	uint32_t e_bytes;
	uint32_t k_bytes;
	uint32_t r_bytes;
	uint32_t s_bytes;
};

struct hpre_ecc_verify {
	uint32_t pubx_bytes;
	uint32_t puby_bytes;
	uint32_t e_bytes;
	uint32_t s_bytes;
	uint32_t r_bytes;
};

struct hpre_sm2_enc {
	uint32_t pubx_bytes;
	uint32_t puby_bytes;
	uint32_t k_bytes;
	uint32_t m_bytes;
	uint32_t c1x_bytes;
	uint32_t c1y_bytes;
	uint32_t c2_bytes;
	uint32_t c3_bytes;
};

struct hpre_sm2_dec {
	uint32_t d_bytes;
	uint32_t c1x_bytes;
	uint32_t c1y_bytes;
	uint32_t c2_bytes;
	uint32_t c3_bytes;
	uint32_t m_bytes;
};

struct hpre_ecc_msg {
	uint8_t *key;
	paddr_t key_dma;
	uint8_t *in;
	paddr_t in_dma;
	uint8_t *out;
	paddr_t out_dma;
	uint8_t alg_type;
	uint32_t key_bytes;
	uint32_t curve_bytes;
	uint32_t result;
	uint32_t sm2_mlen;
	bool sm2_sp;
	union {
		struct hpre_ecc_dh ecc_dh;
		struct hpre_ecc_sign ecc_sign;
		struct hpre_ecc_verify ecc_verify;
		struct hpre_sm2_enc sm2_enc;
		struct hpre_sm2_dec sm2_dec;
	} param_size;
};

#endif
