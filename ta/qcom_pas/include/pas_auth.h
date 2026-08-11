/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_AUTH_H
#define __PAS_AUTH_H

#include <qcom_pas_priv.h>
#include <tee_internal_api.h>

#ifdef CFG_QCOM_PAS_AUTH
TEE_Result pas_auth_save_metadata(struct qcom_pas_session *s, uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result pas_auth_authenticate(struct qcom_pas_session *s, uint32_t pas_id);

TEE_Result pas_auth_verify_reset(struct qcom_pas_session *s,
				 TEE_TASessionHandle pta_session,
				 uint32_t pas_id,
				 TEE_Param params[TEE_NUM_PARAMS]);

TEE_Result pas_auth_release_metadata(struct qcom_pas_session *s,
				     uint32_t pas_id);
#else
static inline TEE_Result
pas_auth_save_metadata(struct qcom_pas_session *s __unused,
		       uint32_t pt __unused,
		       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
pas_auth_authenticate(struct qcom_pas_session *s __unused,
		      uint32_t pas_id __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
pas_auth_verify_reset(struct qcom_pas_session *s __unused,
		      TEE_TASessionHandle pta_session __unused,
		      uint32_t pas_id __unused,
		      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return TEE_SUCCESS;
}

static inline TEE_Result
pas_auth_release_metadata(struct qcom_pas_session *s __unused,
			  uint32_t pas_id __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_QCOM_PAS_AUTH */

#endif /* __PAS_AUTH_H */
