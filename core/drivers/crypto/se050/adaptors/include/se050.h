/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_H_
#define SE050_H_

#include <fsl_sss_util_asn1_der.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU.h>
#include <se050_sss_apis.h>
#include <se050_apdu_apis.h>
#include <se050_user_apis.h>
#include <se050_utils.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

/* Supported Devices*/
#define SE050A1_ID 0xA204
#define SE050A2_ID 0xA205
#define SE050B1_ID 0xA202
#define SE050B2_ID 0xA203
#define SE050C1_ID 0xA200
#define SE050C2_ID 0xA201
#define SE050DV_ID 0xA1F4
#define SE051A2_ID 0xA565
#define SE051C2_ID 0xA564
#define SE050F2_ID 0xA77E
#define SE050E_ID 0xA921
#define SE051A_ID 0xA920
#define SE051C_ID 0xA8FA
#define SE051W_ID 0xA739
#define SE050F_ID 0xA92A

TEE_Result se050_core_early_init(struct se050_scp_key *keys);

extern sss_se05x_key_store_t *se050_kstore;
extern sss_se05x_session_t *se050_session;
extern struct sss_se05x_ctx se050_ctx;

static inline uint32_t se050_get_oefid(void)
{
	return SHIFT_U32(se050_ctx.se_info.oefid[0], 8) |
		SHIFT_U32(se050_ctx.se_info.oefid[1], 0);
}

#endif /* SE050_H_ */
