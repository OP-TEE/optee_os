/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __ICE_HWKM_H
#define __ICE_HWKM_H

#include <tee_api_types.h>

#define ICE_HWKM_TZ_REGS_OFFSET		0x9000U
#define ICE_HWKM_TZ_KM_CTL		0x0000U
#define ICE_LEGACY_MODE_EN_OTP		BIT(0x05U)

#define ICE_RAW_SECRET_SIZE_BYTES       32U

#ifdef CFG_QCOM_HWKM
TEE_Result get_raw_secret_from_wrapped_key(const uint8_t *wrapped_blob,
					   size_t wrapped_blob_len,
					   uint8_t *raw_secret,
					   size_t *raw_secret_len);

TEE_Result clear_ice_slave_slot_hwkm(uint32_t slot);

TEE_Result set_config_ice_key_using_hwkm(uint32_t slot,
					 const uint8_t *wrapped_blob,
					 size_t wrapped_blob_len);

TEE_Result export_hw_wrapped_key(const uint8_t *in_blob, size_t in_blob_len,
                                 uint8_t *out_blob, size_t *out_blob_len);

TEE_Result import_and_wrap_with_hw_key(const uint8_t *in_key, size_t in_key_len,
				       uint8_t *out_blob, size_t *out_blob_len);

TEE_Result generate_hw_wrapped_key(uint8_t *out_blob, size_t *out_blob_len);
#else
static inline TEE_Result
get_raw_secret_from_wrapped_key(const uint8_t *wrapped_blob __unused,
				size_t wrapped_blob_len __unused,
				uint8_t *raw_secret __unused,
				size_t *raw_secret_len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
clear_ice_slave_slot_hwkm(uint32_t slot __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
set_config_ice_key_using_hwkm(uint32_t slot __unused,
			      const uint8_t *wrapped_blob __unused,
			      size_t wrapped_blob_len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
export_hw_wrapped_key(const uint8_t *in_blob __unused,
		      size_t in_blob_len __unused,
                      uint8_t *out_blob __unused,
		      size_t *out_blob_len __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

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
