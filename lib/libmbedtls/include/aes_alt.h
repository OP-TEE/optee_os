/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2020, Linaro Limited */

#ifndef __MBEDTLS_AES_ALT_H
#define __MBEDTLS_AES_ALT_H

typedef struct mbedtls_aes_context {
	uint32_t key[60];
	unsigned int round_count;
} mbedtls_aes_context;

#endif /*__MBEDTLS_AES_ALT_H*/
