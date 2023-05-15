/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
