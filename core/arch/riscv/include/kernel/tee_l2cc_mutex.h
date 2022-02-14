/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef TEE_L2CC_MUTEX_H
#define TEE_L2CC_MUTEX_H

#include <inttypes.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <compiler.h>

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

#endif /* TEE_L2CC_MUTEX_H */
