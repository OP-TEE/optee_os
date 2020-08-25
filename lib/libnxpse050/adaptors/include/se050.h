/* SPDX-License-Identifier: BSD-3-Clause */
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
#include <trace.h>

extern sss_se05x_key_store_t *se050_kstore;
extern sss_se05x_session_t *se050_session;
extern struct sss_se05x_ctx se050_ctx;

#endif /* SE050_H_ */
