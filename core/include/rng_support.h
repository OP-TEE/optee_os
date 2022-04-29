/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __RNG_SUPPORT_H__
#define __RNG_SUPPORT_H__

#include <stdint.h>

uint8_t hw_get_random_byte(void);
TEE_Result hw_get_random_bytes(void *buf, size_t blen);

#endif /* __RNG_SUPPORT_H__ */
