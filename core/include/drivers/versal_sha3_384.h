/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Foundries.io Ltd
 */

#ifndef __DRIVERS_VERSAL_SHA3_384_H__
#define __DRIVERS_VERSAL_SHA3_384_H__

#include <platform_config.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

TEE_Result versal_sha3_384(const uint8_t *src, size_t src_len,
			   uint8_t *dst, size_t dst_len);

#endif /*__DRIVERS_VERSAL_SHA3_384_H__*/
