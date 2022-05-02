/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __RNG_SUPPORT_H__
#define __RNG_SUPPORT_H__

#include <stdint.h>

TEE_Result hw_get_random_bytes(void *buf, size_t blen);

/*
 * hw_get_max_available_entropy() - Get the maximum bytes of entropy per call
 * @blen:  [out] Maximum number of bytes of entropy that can be returned
 *               in a single call to the hw_get_available_entropy() function
 *
 * Returns TEE_SUCCESS on success.
 */
TEE_Result hw_get_max_available_entropy(size_t *blen);

/*
 * hw_get_available_entropy() - Get currently available entropy
 * @buf:  [out] Buffer pointer for storing entropy bytes
 *
 * Returns TEE_SUCCESS on success or an error code on failure or
 * if not enough entropy is yet available.
 */
TEE_Result hw_get_available_entropy(void *buf);

#endif /* __RNG_SUPPORT_H__ */
