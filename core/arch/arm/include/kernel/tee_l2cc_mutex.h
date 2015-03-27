/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEE_L2CC_MUTEX_H
#define TEE_L2CC_MUTEX_H
#include <inttypes.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <compiler.h>

#if defined(CFG_PL310)
TEE_Result tee_enable_l2cc_mutex(void);
TEE_Result tee_disable_l2cc_mutex(void);
TEE_Result tee_get_l2cc_mutex(paddr_t *mutex);
TEE_Result tee_set_l2cc_mutex(paddr_t *mutex);
void tee_l2cc_mutex_lock(void);
void tee_l2cc_mutex_unlock(void);

/*
 * Store the pa of a mutex used for l2cc
 * It is allocated from the boot
 */
void tee_l2cc_store_mutex_boot_pa(uint32_t pa);

#else
static TEE_Result tee_enable_l2cc_mutex(void);
static TEE_Result tee_disable_l2cc_mutex(void);
static TEE_Result tee_get_l2cc_mutex(paddr_t *mutex);
static TEE_Result tee_set_l2cc_mutex(paddr_t *mutex);

static inline TEE_Result tee_enable_l2cc_mutex(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
static inline TEE_Result tee_disable_l2cc_mutex(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
static inline TEE_Result tee_get_l2cc_mutex(paddr_t *mutex __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
static inline TEE_Result tee_set_l2cc_mutex(paddr_t *mutex __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /* TEE_L2CC_MUTEX_H */
