/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 */

#ifndef TEE_SE_UTIL_H
#define TEE_SE_UTIL_H

#include <tee_api_types.h>

#define DUMP_BUF_MAX	128
char *print_buf(char *buf, size_t *remain_size, const char *fmt, ...)
	__attribute__((__format__(__printf__, 3, 4)));

void dump_hex(char *buf, size_t *remain_size, uint8_t *input_buf,
		size_t input_size);

void print_hex(uint8_t *input_buf, size_t input_size);

uint8_t *hex_decode(const char *in, size_t len, uint8_t *out);

#endif
