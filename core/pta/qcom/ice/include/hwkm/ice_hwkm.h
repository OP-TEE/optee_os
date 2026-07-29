/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __ICE_HWKM_H
#define __ICE_HWKM_H

#include <tee_api_types.h>

#ifdef CFG_QCOM_HWKM
TEE_Result import_and_wrap_with_hw_key(const uint8_t *in_key, size_t in_key_len,
				       uint8_t *out_blob, size_t *out_blob_len);

TEE_Result generate_hw_wrapped_key(uint8_t *out_blob, size_t *out_blob_len);
#else
static inline TEE_Result
import_and_wrap_with_hw_key(const uint8_t *in_key __unused,
			    size_t in_key_len __unused,
			    uint8_t *out_blob __unused,
			    size_t *out_blob_len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
generate_hw_wrapped_key(uint8_t *out_blob __unused,
			size_t *out_blob_len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_QCOM_HWKM */

#endif /* __ICE_HWKM_H */
