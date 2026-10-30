/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_UTILS_H
#define __PAS_UTILS_H

#include <auth/pas_auth.h>

TEE_Result pas_utils_save_metadata(struct qcom_pas_session *s, uint32_t pas_id,
				   void *meta_data, size_t size);

TEE_Result pas_utils_release_metadata(struct qcom_pas_session *s,
				      uint32_t pas_id);

#endif /* __PAS_UTILS_H */
