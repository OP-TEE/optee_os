/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_USER_APIS_H_
#define SE050_USER_APIS_H_

#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_se05x_types.h>
#include <nxScp03_Types.h>
#include <se050_sss_apis.h>
#include <se050_utils.h>

sss_status_t se050_configure_host(sss_user_impl_session_t *host_session,
				  sss_key_store_t *host_ks,
				  SE_Connect_Ctx_t *open_ctx,
				  struct se050_auth_ctx *auth_ctx,
				  SE_AuthType_t auth_type,
				  struct se050_scp_key *keys);

TEE_Result se050_host_key_store_get_key(sss_key_store_t *ks __unused,
					sss_object_t *ko, uint8_t *data,
					size_t *byte_len, size_t *bit_len);
#endif /* SE050_USER_APIS_H_ */
