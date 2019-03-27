// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <stdlib.h>

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/




/* Stubs for the crypto alloc ctx functions matching crypto_impl.h */
#undef CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED

#define CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(name, type) \
	TEE_Result \
	crypto_##name##_alloc_ctx(struct crypto_##type##_ctx **ctx __unused) \
	{ return TEE_ERROR_NOT_IMPLEMENTED; }

#if defined(CFG_CRYPTO_AES) && defined(CFG_CRYPTO_XTS)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_xts, cipher)
#endif

#if defined(CFG_CRYPTO_CCM)
CRYPTO_ALLOC_CTX_NOT_IMPLEMENTED(aes_ccm, authenc)
#endif
