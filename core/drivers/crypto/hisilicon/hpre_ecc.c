// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, HiSilicon Technologies Co., Ltd.
 * Kunpeng hardware accelerator hpre ecc algorithm implementation.
 */
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <initcall.h>
#include <malloc.h>
#include <rng_support.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#include "hpre_main.h"
#include "hpre_ecc.h"

#define ECC_DH_IN_PARAM_NUM	2
#define ECC_DH_KEY_PARAM_NUM	4
#define ECC_DH_OUT_PARAM_NUM	2
#define ECC_DH_IN_SIZE(hsz)	((hsz) * ECC_DH_IN_PARAM_NUM)
#define ECC_DH_KEY_SIZE(hsz)	((hsz) * ECC_DH_KEY_PARAM_NUM)
#define ECC_DH_OUT_SIZE(hsz)	((hsz) * ECC_DH_OUT_PARAM_NUM)

#define ECC_SIGN_IN_PARAM_NUM	2
#define ECC_SIGN_KEY_PARAM_NUM	7
#define SM2_DEC_KEY_PARAM_NUM	4
#define SM2_DEC_IN_PARAM_NUM	4
#define ECC_SIGN_OUT_PARAM_NUM	2
#define ECC_SIGN_IN_SIZE(hsz)	((hsz) * ECC_SIGN_IN_PARAM_NUM)
#define ECC_SIGN_KEY_SIZE(hsz)	((hsz) * ECC_SIGN_KEY_PARAM_NUM)
#define ECC_SIGN_OUT_SIZE(hsz)	((hsz) * ECC_SIGN_OUT_PARAM_NUM)

#define ECC_VERIF_IN_PARAM_NUM	3
#define ECC_VERIF_KEY_PARAM_NUM	8
#define SM2_ENC_KEY_PARAM_NUM	8
#define ECC_VERIF_IN_SIZE(hsz)	((hsz) * ECC_VERIF_IN_PARAM_NUM)
#define ECC_VERIF_KEY_SIZE(hsz)	((hsz) * ECC_VERIF_KEY_PARAM_NUM)
#define SM2_ENC_KEY_SIZE(hsz)	((hsz) * SM2_ENC_KEY_PARAM_NUM)
#define SM2_DEC_KEY_SIZE(hsz)	((hsz) * SM2_DEC_KEY_PARAM_NUM)
#define ECC_POINT_PARAM_NUM		2
#define MAX_SM2_MLEN			512

#define HPRE_ECC_DH_TOTAL_BUF_SIZE(key_bytes) ((key_bytes) * 8)
#define HPRE_ECC_SIGN_TOTAL_BUF_SIZE(key_bytes) ((key_bytes) * 11)
#define HPRE_ECC_VERIFY_TOTAL_BUF_SIZE(key_bytes) ((key_bytes) * 11)
#define HPRE_SM2_ENC_TOTAL_BUF_SIZE(key_bytes, sm2_mlen) \
	((key_bytes) * 12 + (sm2_mlen) * 2)
#define HPRE_SM2_DEC_TOTAL_BUF_SIZE(key_bytes, sm2_mlen) \
	((key_bytes) * 7 + (sm2_mlen) * 2)

#define SM2_X2Y2_LEN 64

struct hpre_ecc_curve {
	const uint32_t id;
	const uint32_t key_bits;
	const uint8_t *p;
	const uint8_t *a;
	const uint8_t *b;
	const uint8_t *x;
	const uint8_t *y;
	const uint8_t *n;
};

/* NID_X9_62_prime192v1 */
static const uint8_t g_prime192v1_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t g_prime192v1_a[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static const uint8_t g_prime192v1_b[] = {
	0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB,
	0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1
};

static const uint8_t g_prime192v1_gx[] = {
	0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6, 0x7C, 0xBF, 0x20, 0xEB,
	0x43, 0xA1, 0x88, 0x00, 0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12
};

static const uint8_t g_prime192v1_gy[] = {
	0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78, 0x63, 0x10, 0x11, 0xed,
	0x6b, 0x24, 0xcd, 0xd5, 0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11
};

static const uint8_t g_prime192v1_n[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
};

/* NID_secp224r1 */
static const uint8_t g_secp224r1_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

static const uint8_t g_secp224r1_a[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE
};

static const uint8_t g_secp224r1_b[] = {
	0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56,
	0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43,
	0x23, 0x55, 0xFF, 0xB4
};

static const uint8_t g_secp224r1_gx[] = {
	0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9,
	0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
	0x11, 0x5C, 0x1D, 0x21
};

static const uint8_t g_secp224r1_gy[] = {
	0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6,
	0xcd, 0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99,
	0x85, 0x00, 0x7e, 0x34
};

static const uint8_t g_secp224r1_n[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
	0x5C, 0x5C, 0x2A, 0x3D
};

/* NID_X9_62_prime256v1 */
static const uint8_t g_prime256v1_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t g_prime256v1_a[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static const uint8_t g_prime256v1_b[] = {
	0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55,
	0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
	0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

static const uint8_t g_prime256v1_gx[] = {
	0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
	0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
	0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};

static const uint8_t g_prime256v1_gy[] = {
	0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
	0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
	0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

static const uint8_t g_prime256v1_n[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
	0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

/* NID_secp384r1 */
static const uint8_t g_secp384r1_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t g_secp384r1_a[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
};

static const uint8_t g_secp384r1_b[] = {
	0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B,
	0xE3, 0xF8, 0x2D, 0x19, 0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
	0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A, 0xC6, 0x56, 0x39, 0x8D,
	0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
};

static const uint8_t g_secp384r1_gx[] = {
	0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E,
	0xF3, 0x20, 0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
	0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D,
	0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
};

static const uint8_t g_secp384r1_gy[] = {
	0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
	0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
	0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
	0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f
};

static const uint8_t g_secp384r1_n[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2,
	0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
};

/* NID_secp521r1 */
static const uint8_t g_secp521r1_p[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t g_secp521r1_a[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static const uint8_t g_secp521r1_b[] = {
	0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A,
	0x21, 0xA0, 0xB6, 0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
	0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19,
	0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
	0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45,
	0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00
};

static const uint8_t g_secp521r1_gx[] = {
	0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E,
	0xCB, 0x66, 0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
	0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B,
	0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
	0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E,
	0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66
};

static const uint8_t g_secp521r1_gy[] = {
	0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a,
	0x5f, 0xb4, 0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b,
	0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee,
	0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad,
	0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe,
	0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50
};

static const uint8_t g_secp521r1_n[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86,
	0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
	0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
	0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09
};

/* NID_SM2 */
static const uint8_t g_sm2_p[] = {
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t g_sm2_a[] = {
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
};

static const uint8_t g_sm2_b[] = {
	0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b,
	0xcf, 0x65, 0x09, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
	0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93
};

static const uint8_t g_sm2_gx[] = {
	0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46,
	0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
	0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7
};

static const uint8_t g_sm2_gy[] = {
	0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3,
	0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
	0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0
};

static const uint8_t g_sm2_n[] = {
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
	0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23
};

static const struct hpre_ecc_curve g_curve_list[] = {
	{
		.id = TEE_ECC_CURVE_NIST_P192,
		.key_bits = 192,
		.p = g_prime192v1_p,
		.a = g_prime192v1_a,
		.b = g_prime192v1_b,
		.x = g_prime192v1_gx,
		.y = g_prime192v1_gy,
		.n = g_prime192v1_n,
	},
	{
		.id = TEE_ECC_CURVE_NIST_P224,
		.key_bits = 224,
		.p = g_secp224r1_p,
		.a = g_secp224r1_a,
		.b = g_secp224r1_b,
		.x = g_secp224r1_gx,
		.y = g_secp224r1_gy,
		.n = g_secp224r1_n,
	},
	{
		.id = TEE_ECC_CURVE_NIST_P256,
		.key_bits = 256,
		.p = g_prime256v1_p,
		.a = g_prime256v1_a,
		.b = g_prime256v1_b,
		.x = g_prime256v1_gx,
		.y = g_prime256v1_gy,
		.n = g_prime256v1_n,
	},
	{
		.id = TEE_ECC_CURVE_NIST_P384,
		.key_bits = 384,
		.p = g_secp384r1_p,
		.a = g_secp384r1_a,
		.b = g_secp384r1_b,
		.x = g_secp384r1_gx,
		.y = g_secp384r1_gy,
		.n = g_secp384r1_n,
	},
	{
		.id = TEE_ECC_CURVE_NIST_P521,
		.key_bits = 521,
		.p = g_secp521r1_p,
		.a = g_secp521r1_a,
		.b = g_secp521r1_b,
		.x = g_secp521r1_gx,
		.y = g_secp521r1_gy,
		.n = g_secp521r1_n,
	},
	{
		.id = TEE_ECC_CURVE_SM2,
		.key_bits = 256,
		.p = g_sm2_p,
		.a = g_sm2_a,
		.b = g_sm2_b,
		.x = g_sm2_gx,
		.y = g_sm2_gy,
		.n = g_sm2_n,
	}
};

static bool is_all_zero(uint8_t *data, uint32_t size, const char *p_name)
{
	uint32_t i = 0;

	for (i = 0; i < size; i++) {
		if (data[i])
			return false;
	}

	EMSG("Error: %s all zero", p_name);

	return true;
}

static enum hisi_drv_status hpre_ecc_curve_to_hpre_bin(uint8_t *p, uint8_t *a,
						       uint8_t *b, uint8_t *n,
						       uint8_t *gx, uint8_t *gy,
						       uint32_t curve_bytes,
						       uint32_t key_bytes)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_bin_from_crypto_bin(p, p, key_bytes, curve_bytes);
	if (ret) {
		EMSG("Fail to transfer p from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(a, a, key_bytes, curve_bytes);
	if (ret) {
		EMSG("Fail to transfer a from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(b, b, key_bytes, curve_bytes);
	if (ret) {
		EMSG("Fail to transfer b from crypto_bin to hpre_bin");
		return ret;
	}

	if (n) {
		ret = hpre_bin_from_crypto_bin(n, n, key_bytes, curve_bytes);
		if (ret) {
			EMSG("Fail to transfer n from crypto_bin to hpre_bin");
			return ret;
		}
	}

	if (gx) {
		ret = hpre_bin_from_crypto_bin(gx, gx, key_bytes, curve_bytes);
		if (ret) {
			EMSG("Fail to transfer gx from crypto_bin to hpre_bin");
			return ret;
		}
	}

	if (gy) {
		ret = hpre_bin_from_crypto_bin(gy, gy, key_bytes, curve_bytes);
		if (ret)
			EMSG("Fail to transfer gy from crypto_bin to hpre_bin");
	}

	return ret;
}

static enum hisi_drv_status hpre_ecc_fill_sqe(void *bd, void *info)
{
	struct hpre_ecc_msg *msg = (struct hpre_ecc_msg *)info;
	struct hpre_sqe *sqe = (struct hpre_sqe *)bd;

	sqe->w0 = msg->alg_type | SHIFT_U32(0x1, HPRE_DONE_SHIFT);
	sqe->task_len1 = TASK_LENGTH(msg->key_bytes);
	sqe->ext1 = msg->sm2_sp << HPRE_SQE_BD_RSV2_SHIFT;

	if (msg->alg_type == HPRE_ALG_SM2_ENC ||
	    msg->alg_type == HPRE_ALG_SM2_DEC)
		sqe->sm2enc_klen = msg->sm2_mlen - 1;

	if (msg->alg_type == HPRE_ALG_SM2_SIGN ||
	    msg->alg_type == HPRE_ALG_SM2_ENC)
		sqe->ext1 |= SHIFT_U32(0x1, HPRE_SQE_SM2_KSEL_SHIFT);

	sqe->key = msg->key_dma;
	sqe->in = msg->in_dma;
	if (msg->alg_type != HPRE_ALG_ECDSA_VERF &&
	    msg->alg_type != HPRE_ALG_SM2_VERF)
		sqe->out = msg->out_dma;

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static enum hisi_drv_status ecc_dh_out_to_crypto_bin(struct hpre_ecc_msg *msg)
{
	struct hpre_ecc_dh *ecc_dh = &msg->param_size.ecc_dh;
	uint8_t *rx = msg->out;
	uint8_t *ry = rx + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_bin_to_crypto_bin(rx, rx, msg->key_bytes,
				     ecc_dh->rx_bytes);
	if (ret) {
		EMSG("Fail to transfer ecc dh rx from hpre_bin to crypto_bin");
		return ret;
	}

	ret = hpre_bin_to_crypto_bin(ry, ry, msg->key_bytes,
				     ecc_dh->ry_bytes);
	if (ret)
		EMSG("Fail to transfer ecc dh ry from hpre_bin to crypto_bin");

	return ret;
}

static enum hisi_drv_status ecc_sign_out_to_crypto_bin(struct hpre_ecc_msg *msg)
{
	struct hpre_ecc_sign *ecc_sign = &msg->param_size.ecc_sign;
	uint8_t *r = msg->out;
	uint8_t *s = r + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_bin_to_crypto_bin(r, r, msg->key_bytes,
				     ecc_sign->r_bytes);
	if (ret) {
		EMSG("Fail to transfer ecc sign r from hpre_bin to crypto_bin");
		return ret;
	}

	ret = hpre_bin_to_crypto_bin(s, s, msg->key_bytes,
				     ecc_sign->s_bytes);
	if (ret)
		EMSG("Fail to transfer ecc sign s from hpre_bin to crypto_bin");

	return ret;
}

static enum hisi_drv_status hpre_ecc_verify_get_result(struct hpre_ecc_msg *msg,
						       struct hpre_sqe *sqe)
{
	if (sqe->out & BIT64(1)) {
		msg->result = ECC_VERIFY_SUCCESS;
		return HISI_QM_DRVCRYPT_NO_ERR;
	}

	msg->result = ECC_VERIFY_ERR;
	return HISI_QM_DRVCRYPT_VERIFY_ERR;
}

static enum hisi_drv_status
hpre_ecc_out_to_crypto_bin(struct hpre_ecc_msg *msg, struct hpre_sqe *sqe)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	switch (msg->alg_type) {
	case HPRE_ALG_ECDH_MULTIPLY:
		ret = ecc_dh_out_to_crypto_bin(msg);
		break;
	case HPRE_ALG_ECDSA_SIGN:
	case HPRE_ALG_SM2_SIGN:
		ret = ecc_sign_out_to_crypto_bin(msg);
		break;
	case HPRE_ALG_ECDSA_VERF:
	case HPRE_ALG_SM2_VERF:
		ret = hpre_ecc_verify_get_result(msg, sqe);
		break;
	default:
		EMSG("Invalid alg type.");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	return ret;
}

static enum hisi_drv_status hpre_ecc_parse_sqe(void *bd, void *info)
{
	struct hpre_ecc_msg *msg = (struct hpre_ecc_msg *)info;
	struct hpre_sqe *sqe = (struct hpre_sqe *)bd;
	uint16_t err = 0;
	uint16_t err1 = 0;
	uint16_t done = 0;

	err = HPRE_TASK_ETYPE(sqe->w0);
	err1 = HPRE_TASK_ETYPE1(sqe->w0);
	done = HPRE_TASK_DONE(sqe->w0);
	if (done != HPRE_HW_TASK_DONE || err || err1) {
		EMSG("HPRE do ecc fail! done=0x%"PRIX16", etype=0x%"PRIX16
		     ",etype1=0x%"PRIX16, done, err, err1);

		if (done == HPRE_HW_TASK_INIT)
			return HISI_QM_DRVCRYPT_ENOPROC;

		return HISI_QM_DRVCRYPT_IN_EPARA;
	}

	if (hpre_ecc_out_to_crypto_bin(msg, sqe)) {
		EMSG("HPRE qm transfer ecc out fail.");
		return HISI_QM_DRVCRYPT_EINVAL;
	}

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static TEE_Result hpre_do_ecc_task(void *msg)
{
	struct hisi_qp *ecc_qp = NULL;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ecc_qp = hpre_create_qp(HISI_QM_CHANNEL_TYPE1);
	if (!ecc_qp) {
		EMSG("Fail to create ecc qp");
		return TEE_ERROR_BUSY;
	}

	ecc_qp->fill_sqe = hpre_ecc_fill_sqe;
	ecc_qp->parse_sqe = hpre_ecc_parse_sqe;
	ret = hisi_qp_send(ecc_qp, msg);
	if (ret) {
		EMSG("Fail to send task, ret=%d", ret);
		hisi_qm_release_qp(ecc_qp);
		return TEE_ERROR_BAD_STATE;
	}

	ret = hisi_qp_recv_sync(ecc_qp, msg);
	if (ret) {
		EMSG("Recv task error, ret=%d", ret);
		hisi_qm_release_qp(ecc_qp);
		return TEE_ERROR_BAD_STATE;
	}

	hisi_qm_release_qp(ecc_qp);

	return TEE_SUCCESS;
}

static bool key_size_is_supported(size_t key_bits)
{
	return (key_bits == 192 || key_bits == 224 || key_bits == 256 ||
		key_bits == 384 || key_bits == 448 || key_bits == 512 ||
		BITS_TO_BYTES(key_bits) == BITS_TO_BYTES(521) ||
		BITS_TO_BYTES(key_bits) == BITS_TO_BYTES(225));
}

static TEE_Result hpre_ecc_alloc_keypair(struct ecc_keypair *key,
					 uint32_t type __unused,
					 size_t size_bits)
{
	if (!key || !key_size_is_supported(size_bits)) {
		EMSG("Invalid input params.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(key, 0, sizeof(*key));

	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto d_err;

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto x_err;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto y_err;

	return TEE_SUCCESS;

y_err:
	crypto_bignum_free(&key->x);
x_err:
	crypto_bignum_free(&key->d);
d_err:
	EMSG("Hpre ecc alloc key pair fail.");

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result hpre_ecc_alloc_publickey(struct ecc_public_key *key,
					   uint32_t type __unused,
					   size_t size_bits)
{
	if (!key || !key_size_is_supported(size_bits)) {
		EMSG("Invalid input params.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(key, 0, sizeof(*key));

	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto x_err;

	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto y_err;

	return TEE_SUCCESS;

y_err:
	crypto_bignum_free(&key->x);
x_err:
	EMSG("Hpre ecc alloc publickey fail.");

	return TEE_ERROR_OUT_OF_MEMORY;
}

static void hpre_ecc_free_publickey(struct ecc_public_key *key)
{
	if (key) {
		crypto_bignum_free(&key->x);
		crypto_bignum_free(&key->y);
	}
}

static const struct hpre_ecc_curve *get_curve_from_list(uint32_t curve_id)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(g_curve_list); i++) {
		if (g_curve_list[i].id == curve_id)
			return &g_curve_list[i];
	}

	return NULL;
}

static size_t hpre_ecc_get_hw_kbytes(size_t key_bits)
{
	size_t size = 0;

	if (BITS_TO_BYTES(key_bits) <= BITS_TO_BYTES(256))
		size = BITS_TO_BYTES(256);
	else if (BITS_TO_BYTES(key_bits) <= BITS_TO_BYTES(384))
		size = BITS_TO_BYTES(384);
	else if (BITS_TO_BYTES(key_bits) <= BITS_TO_BYTES(576))
		size = BITS_TO_BYTES(576);
	else
		EMSG("Fail to get key buffer size.");

	return size;
}

static enum hisi_drv_status hpre_ecc_dh_transfer_key(struct hpre_ecc_msg *msg)
{
	struct hpre_ecc_dh *ecc_dh = &msg->param_size.ecc_dh;
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *d = a + msg->key_bytes;
	uint8_t *b = d + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_ecc_curve_to_hpre_bin(p, a, b, NULL, NULL, NULL,
					 msg->curve_bytes, msg->key_bytes);
	if (ret)
		return ret;

	ret = hpre_bin_from_crypto_bin(d, d, msg->key_bytes, ecc_dh->d_bytes);
	if (ret)
		EMSG("Fail to transfer ecc dh d from crypto_bin to hpre_bin");

	return ret;
}

static enum hisi_drv_status hpre_ecc_dh_transfer_in(struct hpre_ecc_msg *msg)
{
	struct hpre_ecc_dh *ecc_dh = &msg->param_size.ecc_dh;
	uint8_t *x = msg->in;
	uint8_t *y = x + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_bin_from_crypto_bin(x, x, msg->key_bytes,
				       ecc_dh->x_bytes);
	if (ret) {
		EMSG("Fail to transfer ecdh gx from crypto_bin to hpre_bin");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(y, y, msg->key_bytes,
				       ecc_dh->y_bytes);
	if (ret)
		EMSG("Fail to transfer ecdh gy from crypto_bin to hpre_bin");

	return ret;
}

static enum hisi_drv_status
hpre_ecc_dh_params_fill(const struct hpre_ecc_curve *curve,
			struct hpre_ecc_msg *msg, struct bignum *privkey,
			struct ecc_public_key *pubkey)
{
	struct hpre_ecc_dh *ecc_dh = &msg->param_size.ecc_dh;
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *d = a + msg->key_bytes;
	uint8_t *b = d + msg->key_bytes;
	uint8_t *x = msg->in;
	uint8_t *y = x + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	memcpy(p, curve->p, msg->curve_bytes);
	memcpy(a, curve->a, msg->curve_bytes);
	crypto_bignum_bn2bin(privkey, d);
	ecc_dh->d_bytes = crypto_bignum_num_bytes(privkey);
	if (is_all_zero(d, ecc_dh->d_bytes, "ecc dh d"))
		return HISI_QM_DRVCRYPT_EINVAL;

	memcpy(b, curve->b, msg->curve_bytes);

	ecc_dh->x_bytes = msg->curve_bytes;
	ecc_dh->y_bytes = msg->curve_bytes;
	if (!pubkey) {
		/* gen key pair */
		memcpy(x, curve->x, ecc_dh->x_bytes);
		memcpy(y, curve->y, ecc_dh->y_bytes);
	} else {
		/* do shared secret */
		crypto_bignum_bn2bin(pubkey->x, x);
		ecc_dh->x_bytes = crypto_bignum_num_bytes(pubkey->x);
		crypto_bignum_bn2bin(pubkey->y, y);
		ecc_dh->y_bytes = crypto_bignum_num_bytes(pubkey->y);
	}

	ret = hpre_ecc_dh_transfer_key(msg);
	if (ret)
		return ret;

	return hpre_ecc_dh_transfer_in(msg);
}

static enum hisi_drv_status hpre_ecc_dh_params_alloc(struct hpre_ecc_msg *msg)
{
	uint32_t size = HPRE_ECC_DH_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc ecc dh total buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->key = data;
	msg->key_dma = virt_to_phys(msg->key);

	msg->in = msg->key + ECC_DH_KEY_SIZE(msg->key_bytes);
	msg->in_dma = msg->key_dma + ECC_DH_KEY_SIZE(msg->key_bytes);
	msg->out = msg->in + ECC_DH_IN_SIZE(msg->key_bytes);
	msg->out_dma = msg->in_dma + ECC_DH_IN_SIZE(msg->key_bytes);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void hpre_ecc_request_deinit(struct hpre_ecc_msg *msg)
{
	if (msg->key) {
		free_wipe(msg->key);
		msg->key = NULL;
	}
}

static TEE_Result hpre_ecc_request_init(const struct hpre_ecc_curve *curve,
					struct hpre_ecc_msg *msg,
					struct bignum *d,
					struct ecc_public_key *pubkey)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	msg->alg_type = HPRE_ALG_ECDH_MULTIPLY;

	if (curve->id == TEE_ECC_CURVE_SM2)
		msg->sm2_sp = true;

	msg->curve_bytes = BITS_TO_BYTES(curve->key_bits);
	msg->key_bytes = hpre_ecc_get_hw_kbytes(curve->key_bits);
	if (!msg->key_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hpre_ecc_dh_params_alloc(msg);
	if (ret)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = hpre_ecc_dh_params_fill(curve, msg, d, pubkey);
	if (ret) {
		hpre_ecc_request_deinit(msg);
		return TEE_ERROR_BAD_STATE;
	}

	msg->param_size.ecc_dh.rx_bytes = msg->curve_bytes;
	msg->param_size.ecc_dh.ry_bytes = msg->curve_bytes;

	return TEE_SUCCESS;
}

static TEE_Result gen_random_k(struct bignum *d, size_t key_bits,
			       const uint8_t *n)
{
	size_t size = BITS_TO_BYTES(key_bits);
	uint8_t *rand_k = NULL;
	size_t i = 0;
	size_t j = 0;
	TEE_Result ret = TEE_SUCCESS;

	if (!d || !n) {
		EMSG("Input param is NULL.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rand_k = malloc(size);
	if (!rand_k) {
		EMSG("Fail to malloc rand_k buf.");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	for (i = 0; i < size; i++) {
		if (n[i] > 1) {
			rand_k[i] = n[i] - 1;
			break;
		}
		rand_k[i] = n[i];
	}

	j = i + 1;
	if (hw_get_random_bytes(rand_k + j, size - j)) {
		EMSG("Fail to fill rand_k buf.");
		free(rand_k);
		return TEE_ERROR_NO_DATA;
	}

	ret = crypto_bignum_bin2bn(rand_k, size, d);
	if (ret)
		EMSG("Rand_k bin2bn fail.");

	free(rand_k);

	return ret;
}

static TEE_Result hpre_ecc_gen_keypair(struct ecc_keypair *key,
				       size_t size_bits)
{
	struct hpre_ecc_msg msg = { };
	const struct hpre_ecc_curve *curve = NULL;
	struct hpre_ecc_dh *ecc_dh = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!key || !key->d || !key->x || !key->y) {
		EMSG("Invalid ecc_gen_keypair input parameters.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	curve = get_curve_from_list(key->curve);
	if (!curve) {
		EMSG("Fail to get valid curve, id %"PRIu32, key->curve);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (BITS_TO_BYTES(size_bits) != BITS_TO_BYTES(curve->key_bits)) {
		EMSG("Invalid size_bits %zu.", size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = gen_random_k(key->d, curve->key_bits, curve->n);
	if (ret)
		return ret;

	ret = hpre_ecc_request_init(curve, &msg, key->d, NULL);
	if (ret) {
		EMSG("Ecc key pair request init fail.");
		return ret;
	}

	ret = hpre_do_ecc_task(&msg);
	if (ret) {
		EMSG("Fail to do ecc key pair task! ret = 0x%"PRIX16, ret);
		goto done;
	}

	ecc_dh = &msg.param_size.ecc_dh;
	ret = crypto_bignum_bin2bn(msg.out, ecc_dh->rx_bytes, key->x);
	if (ret) {
		EMSG("Fail to trans res x to bn.");
		goto done;
	}

	ret = crypto_bignum_bin2bn(msg.out + msg.key_bytes,
				   ecc_dh->ry_bytes, key->y);
	if (ret)
		EMSG("Fail to trans res y to bn.");
done:
	hpre_ecc_request_deinit(&msg);
	return ret;
}

static TEE_Result hpre_ecc_do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	struct hpre_ecc_msg msg = { };
	const struct hpre_ecc_curve *curve = NULL;
	struct ecc_public_key *pubkey = NULL;
	struct ecc_keypair *ecc_key = NULL;
	struct hpre_ecc_dh *ecc_dh = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!sdata || !sdata->key_priv || !sdata->key_pub) {
		EMSG("Invalid ecc_do_shared_secret input parameters.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc_key = sdata->key_priv;
	pubkey = sdata->key_pub;

	curve = get_curve_from_list(ecc_key->curve);
	if (!curve) {
		EMSG("Fail to get valid curve, id %"PRIu32, ecc_key->curve);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (sdata->size_sec != BITS_TO_BYTES(curve->key_bits)) {
		EMSG("Invalid sdata size_sec %zu.", sdata->size_sec);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = hpre_ecc_request_init(curve, &msg, ecc_key->d, pubkey);
	if (ret) {
		EMSG("Ecc shared secret request init fail.");
		return ret;
	}

	ret = hpre_do_ecc_task(&msg);
	if (ret) {
		EMSG("Fail to do ecc shared secret task! ret = 0x%"PRIX32,
		     ret);
		goto done;
	}

	ecc_dh = &msg.param_size.ecc_dh;
	/*
	 * Only take the x coordinate as the output result, according to
	 * soft computing implementation.
	 */
	memcpy(sdata->secret.data, msg.out, ecc_dh->rx_bytes);
	sdata->secret.length = ecc_dh->rx_bytes;
	memzero_explicit(msg.out, ECC_DH_OUT_SIZE(msg.key_bytes));

done:
	hpre_ecc_request_deinit(&msg);
	return ret;
}

static enum hisi_drv_status
hpre_ecc_sign_params_fill(const struct hpre_ecc_curve *curve,
			  struct hpre_ecc_msg *msg,
			  struct drvcrypt_sign_data *sdata,
			  struct bignum *rand_k)
{
	struct ecc_keypair *ecc_key = sdata->key;
	struct hpre_ecc_sign *ecc_sign = &msg->param_size.ecc_sign;
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *d = a + msg->key_bytes;
	uint8_t *b = d + msg->key_bytes;
	uint8_t *n = b + msg->key_bytes;
	uint8_t *gx = n + msg->key_bytes;
	uint8_t *gy = gx + msg->key_bytes;
	uint8_t *e = msg->in;
	uint8_t *k = e + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	memcpy(p, curve->p, msg->curve_bytes);
	memcpy(a, curve->a, msg->curve_bytes);
	crypto_bignum_bn2bin(ecc_key->d, d);
	ecc_sign->d_bytes = crypto_bignum_num_bytes(ecc_key->d);
	memcpy(b, curve->b, msg->curve_bytes);
	memcpy(n, curve->n, msg->curve_bytes);
	memcpy(gx, curve->x, msg->curve_bytes);
	memcpy(gy, curve->y, msg->curve_bytes);
	crypto_bignum_bn2bin(rand_k, k);
	ecc_sign->k_bytes = crypto_bignum_num_bytes(rand_k);

	ecc_sign->e_bytes = MIN(sdata->message.length, msg->curve_bytes);
	memcpy(e, sdata->message.data, ecc_sign->e_bytes);
	if (is_all_zero(e, ecc_sign->e_bytes, "ecc sign msg_e"))
		return HISI_QM_DRVCRYPT_EINVAL;

	ret = hpre_ecc_curve_to_hpre_bin(p, a, b, n, gx, gy, msg->curve_bytes,
					 msg->key_bytes);
	if (ret)
		return ret;

	ret = hpre_bin_from_crypto_bin(d, d, msg->key_bytes,
				       ecc_sign->d_bytes);
	if (ret) {
		EMSG("Fail to transfer ecdsa sign d");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(e, e, msg->key_bytes,
				       ecc_sign->e_bytes);
	if (ret) {
		EMSG("Fail to transfer ecdsa sign e");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(k, k, msg->key_bytes,
				       ecc_sign->k_bytes);
	if (ret)
		EMSG("Fail to transfer ecdsa sign k");

	return ret;
}

static enum hisi_drv_status hpre_ecc_sign_params_alloc(struct hpre_ecc_msg *msg)
{
	uint32_t size = HPRE_ECC_SIGN_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc ecc sign total buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->key = data;
	msg->key_dma = virt_to_phys(msg->key);
	if (!msg->key_dma) {
		EMSG("Fail to get key dma addr");
		free(data);
		return HISI_QM_DRVCRYPT_EFAULT;
	}

	msg->in = msg->key + ECC_SIGN_KEY_SIZE(msg->key_bytes);
	msg->in_dma = msg->key_dma + ECC_SIGN_KEY_SIZE(msg->key_bytes);
	msg->out = msg->in + ECC_SIGN_IN_SIZE(msg->key_bytes);
	msg->out_dma = msg->in_dma + ECC_SIGN_IN_SIZE(msg->key_bytes);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void hpre_ecc_sign_request_deinit(struct hpre_ecc_msg *msg)
{
	if (msg->key) {
		free_wipe(msg->key);
		msg->key = NULL;
	}
}

static TEE_Result
hpre_ecc_sign_request_init(const struct hpre_ecc_curve *curve,
			   struct hpre_ecc_msg *msg,
			   struct drvcrypt_sign_data *sdata,
			   struct bignum *rand_k)
{
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	if (curve->id == TEE_ECC_CURVE_SM2)
		msg->alg_type = HPRE_ALG_SM2_SIGN;
	else
		msg->alg_type = HPRE_ALG_ECDSA_SIGN;
	msg->curve_bytes = BITS_TO_BYTES(curve->key_bits);
	msg->key_bytes = hpre_ecc_get_hw_kbytes(curve->key_bits);
	if (!msg->key_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hpre_ecc_sign_params_alloc(msg);
	if (ret)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = hpre_ecc_sign_params_fill(curve, msg, sdata, rand_k);
	if (ret) {
		hpre_ecc_sign_request_deinit(msg);
		return TEE_ERROR_BAD_STATE;
	}

	msg->param_size.ecc_sign.r_bytes = msg->curve_bytes;
	msg->param_size.ecc_sign.s_bytes = msg->curve_bytes;

	return TEE_SUCCESS;
}

static TEE_Result hpre_ecdsa_param_check(struct drvcrypt_sign_data *sdata,
					 const struct hpre_ecc_curve *curve)
{
	if (sdata->size_sec != BITS_TO_BYTES(curve->key_bits)) {
		EMSG("Invalid sdata size_sec %zu", sdata->size_sec);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static void hpre_ecc_sign_get_data_out(struct hpre_ecc_msg *msg,
				       struct drvcrypt_sign_data *sdata)
{
	struct hpre_ecc_sign *ecc_sign;

	ecc_sign = &msg->param_size.ecc_sign;
	sdata->signature.length = ecc_sign->r_bytes + ecc_sign->s_bytes;
	memcpy(sdata->signature.data, msg->out, ecc_sign->r_bytes);
	memcpy(sdata->signature.data + ecc_sign->r_bytes, msg->out +
	       msg->key_bytes, ecc_sign->s_bytes);
}

static TEE_Result hpre_ecc_sign(struct drvcrypt_sign_data *sdata)
{
	struct hpre_ecc_msg msg = { };
	const struct hpre_ecc_curve *curve = NULL;
	struct ecc_keypair *ecc_key = NULL;
	struct bignum *rand_k = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!sdata || !sdata->key) {
		EMSG("Invalid ecc_sign input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc_key = sdata->key;

	curve = get_curve_from_list(ecc_key->curve);
	if (!curve) {
		EMSG("Fail to get valid curve, id %"PRIu32, ecc_key->curve);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	ret = hpre_ecdsa_param_check(sdata, curve);
	if (ret)
		return ret;

	rand_k = crypto_bignum_allocate(curve->key_bits);
	if (!rand_k) {
		EMSG("Fail to alloc private k");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	ret = gen_random_k(rand_k, curve->key_bits, curve->n);
	if (ret)
		goto free_key;

	ret = hpre_ecc_sign_request_init(curve, &msg, sdata, rand_k);
	if (ret) {
		EMSG("Ecc sign request init fail");
		goto free_key;
	}

	ret = hpre_do_ecc_task(&msg);
	if (ret) {
		EMSG("Fail to do ecc sign task! ret = 0x%"PRIX16, ret);
		goto done;
	}

	hpre_ecc_sign_get_data_out(&msg, sdata);

done:
	hpre_ecc_sign_request_deinit(&msg);
free_key:
	crypto_bignum_free(&rand_k);

	return ret;
}

static enum hisi_drv_status
hpre_ecc_verify_transfer_key(struct hpre_ecc_msg *msg)
{
	struct hpre_ecc_verify *ecc_verify = &msg->param_size.ecc_verify;
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *b = a + msg->key_bytes;
	uint8_t *n = b + msg->key_bytes;
	uint8_t *gx = n + msg->key_bytes;
	uint8_t *gy = gx + msg->key_bytes;
	uint8_t *pubx = gy + msg->key_bytes;
	uint8_t *puby = pubx + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_ecc_curve_to_hpre_bin(p, a, b, n, gx, gy, msg->curve_bytes,
					 msg->key_bytes);
	if (ret)
		return ret;

	ret = hpre_bin_from_crypto_bin(pubx, pubx, msg->key_bytes,
				       ecc_verify->pubx_bytes);
	if (ret) {
		EMSG("Fail to transfer ecdsa verify pub_x");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(puby, puby, msg->key_bytes,
				       ecc_verify->puby_bytes);
	if (ret)
		EMSG("Fail to transfer ecdsa verify pub_y");

	return ret;
}

static enum hisi_drv_status
hpre_ecc_verify_transfer_in(struct hpre_ecc_msg *msg)
{
	struct hpre_ecc_verify *ecc_verify = &msg->param_size.ecc_verify;
	uint8_t *e = msg->in;
	uint8_t *s = e + msg->key_bytes;
	uint8_t *r = s + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	ret = hpre_bin_from_crypto_bin(e, e, msg->key_bytes,
				       ecc_verify->e_bytes);
	if (ret) {
		EMSG("Fail to transfer ecdsa verify e");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(s, s, msg->key_bytes,
				       ecc_verify->s_bytes);
	if (ret) {
		EMSG("Fail to transfer ecdsa verify s");
		return ret;
	}

	ret = hpre_bin_from_crypto_bin(r, r, msg->key_bytes,
				       ecc_verify->r_bytes);
	if (ret)
		EMSG("Fail to transfer ecdsa verify r");

	return ret;
}

static TEE_Result
hpre_ecc_verify_params_fill(const struct hpre_ecc_curve *curve,
			    struct hpre_ecc_msg *msg,
			    struct drvcrypt_sign_data *sdata)
{
	struct ecc_public_key *ecc_key = sdata->key;
	struct hpre_ecc_verify *ecc_verify = &msg->param_size.ecc_verify;
	uint8_t *p = msg->key;
	uint8_t *a = p + msg->key_bytes;
	uint8_t *b = a + msg->key_bytes;
	uint8_t *n = b + msg->key_bytes;
	uint8_t *gx = n + msg->key_bytes;
	uint8_t *gy = gx + msg->key_bytes;
	uint8_t *pubx = gy + msg->key_bytes;
	uint8_t *puby = pubx + msg->key_bytes;
	uint8_t *e = msg->in;
	uint8_t *s = e + msg->key_bytes;
	uint8_t *r = s + msg->key_bytes;
	enum hisi_drv_status ret = HISI_QM_DRVCRYPT_NO_ERR;

	memcpy(p, curve->p, msg->curve_bytes);
	memcpy(a, curve->a, msg->curve_bytes);
	memcpy(b, curve->b, msg->curve_bytes);
	memcpy(n, curve->n, msg->curve_bytes);
	memcpy(gx, curve->x, msg->curve_bytes);
	memcpy(gy, curve->y, msg->curve_bytes);
	crypto_bignum_bn2bin(ecc_key->x, pubx);
	ecc_verify->pubx_bytes = crypto_bignum_num_bytes(ecc_key->x);
	crypto_bignum_bn2bin(ecc_key->y, puby);
	ecc_verify->puby_bytes = crypto_bignum_num_bytes(ecc_key->y);

	ecc_verify->e_bytes = MIN(sdata->message.length, msg->curve_bytes);
	memcpy(e, sdata->message.data, ecc_verify->e_bytes);
	if (is_all_zero(e, ecc_verify->e_bytes, "ecc verify msg_e"))
		return TEE_ERROR_BAD_PARAMETERS;

	/* user should make param r and s be full width */
	ecc_verify->r_bytes = sdata->signature.length >> 1;
	memcpy(r, sdata->signature.data, ecc_verify->r_bytes);
	ecc_verify->s_bytes = ecc_verify->r_bytes;
	memcpy(s, sdata->signature.data + ecc_verify->r_bytes,
	       ecc_verify->s_bytes);

	ret = hpre_ecc_verify_transfer_key(msg);
	if (ret)
		return TEE_ERROR_BAD_STATE;

	ret = hpre_ecc_verify_transfer_in(msg);
	if (ret)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static enum hisi_drv_status
hpre_ecc_verify_params_alloc(struct hpre_ecc_msg *msg)
{
	uint32_t size = HPRE_ECC_VERIFY_TOTAL_BUF_SIZE(msg->key_bytes);
	uint8_t *data = NULL;

	data = calloc(1, size);
	if (!data) {
		EMSG("Fail to alloc ecc verify total buf");
		return HISI_QM_DRVCRYPT_ENOMEM;
	}

	msg->key = data;
	msg->key_dma = virt_to_phys(msg->key);
	if (!msg->key_dma) {
		EMSG("Fail to get key dma addr");
		free(data);
		return HISI_QM_DRVCRYPT_EFAULT;
	}

	msg->in = msg->key + ECC_VERIF_KEY_SIZE(msg->key_bytes);
	msg->in_dma = msg->key_dma + ECC_VERIF_KEY_SIZE(msg->key_bytes);
	msg->out = msg->in + ECC_VERIF_IN_SIZE(msg->key_bytes);
	msg->out_dma = msg->in_dma + ECC_VERIF_IN_SIZE(msg->key_bytes);

	return HISI_QM_DRVCRYPT_NO_ERR;
}

static void hpre_ecc_verify_request_deinit(struct hpre_ecc_msg *msg)
{
	if (msg->key) {
		free_wipe(msg->key);
		msg->key = NULL;
	}
}

static TEE_Result
hpre_ecc_verify_request_init(const struct hpre_ecc_curve *curve,
			     struct hpre_ecc_msg *msg,
			     struct drvcrypt_sign_data *sdata)
{
	int32_t ret = 0;

	if (curve->id == TEE_ECC_CURVE_SM2)
		msg->alg_type = HPRE_ALG_SM2_VERF;
	else
		msg->alg_type = HPRE_ALG_ECDSA_VERF;
	msg->curve_bytes = BITS_TO_BYTES(curve->key_bits);
	msg->key_bytes = hpre_ecc_get_hw_kbytes(curve->key_bits);
	if (!msg->key_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hpre_ecc_verify_params_alloc(msg);
	if (ret)
		return TEE_ERROR_OUT_OF_MEMORY;

	ret = hpre_ecc_verify_params_fill(curve, msg, sdata);
	if (ret) {
		hpre_ecc_verify_request_deinit(msg);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result hpre_ecc_verify(struct drvcrypt_sign_data *sdata)
{
	struct hpre_ecc_msg msg = { };
	const struct hpre_ecc_curve *curve = NULL;
	struct ecc_public_key *pub_key = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!sdata || !sdata->key) {
		EMSG("Invalid ecc_verify input parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pub_key = sdata->key;

	curve = get_curve_from_list(pub_key->curve);
	if (!curve) {
		EMSG("Fail to get valid curve, id %"PRIu32, pub_key->curve);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	ret = hpre_ecdsa_param_check(sdata, curve);
	if (ret)
		return ret;

	ret = hpre_ecc_verify_request_init(curve, &msg, sdata);
	if (ret) {
		EMSG("Ecc verify request init fail");
		return ret;
	}

	ret = hpre_do_ecc_task(&msg);
	if (ret) {
		EMSG("Fail to do ecc verify task! ret = 0x%"PRIX16, ret);
		goto done;
	}

	if (msg.result == ECC_VERIFY_ERR) {
		EMSG("Hpre ecc verify fail");
		ret = TEE_ERROR_SIGNATURE_INVALID;
	}

done:
	hpre_ecc_verify_request_deinit(&msg);
	return ret;
}

static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = hpre_ecc_alloc_keypair,
	.alloc_publickey = hpre_ecc_alloc_publickey,
	.free_publickey = hpre_ecc_free_publickey,
	.gen_keypair = hpre_ecc_gen_keypair,
	.shared_secret = hpre_ecc_do_shared_secret,
	.sign = hpre_ecc_sign,
	.verify = hpre_ecc_verify,
};

static TEE_Result hpre_ecc_init(void)
{
	TEE_Result ret = drvcrypt_register_ecc(&driver_ecc);

	if (ret != TEE_SUCCESS)
		EMSG("Hpre ecc register to crypto fail");

	return ret;
}

driver_init(hpre_ecc_init);
