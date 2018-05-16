/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_CUSTOMER_PART_H
#define TEE_CUSTOMER_PART_H

#include "stdint.h"
#include "stdbool.h"
#include "tee_api_types.h"

#define TEE_SIGNING_CONSTRAINTS_LEN         64

TEE_Result tee_cust_part_import(const uint32_t cust_part,
				const uint32_t cust_size,
				const uint8_t *hash, const uint32_t hash_type);

#endif /* TEE_CUSTOMER_PART_H */
