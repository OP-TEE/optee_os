/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __CMD_DB_H__
#define __CMD_DB_H__

#include <stdint.h>
#include <tee_api_types.h>

#define CMD_DB_MAX_RES_ID_LEN 8
#define CMD_DB_DRV_ID_PRIORITY_SZ 2

/* Get resource address by resource ID */
TEE_Result cmd_db_get_addr(const char *res_id, uint32_t *addr);

/* Get resource priority for driver ID */
TEE_Result cmd_db_get_priority(uint32_t addr, uint8_t drv_id,
			       uint32_t *priority);

#endif /* __CMD_DB_H__ */
