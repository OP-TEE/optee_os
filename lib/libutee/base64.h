/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

bool _base64_enc(const void *data, size_t size, char *buf, size_t *blen);
bool _base64_dec(const char *data, size_t size, void *buf, size_t *blen);
size_t _base64_enc_len(size_t size);

#endif /* BASE64_H */
