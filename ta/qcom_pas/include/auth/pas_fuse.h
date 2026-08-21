/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_FUSE_H
#define __PAS_FUSE_H

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

#ifdef CFG_QCOM_PAS_AUTH
TEE_Result pas_fuse_open(void);

void pas_fuse_close(void);
#else
static inline TEE_Result pas_fuse_open(void)
{
	return TEE_SUCCESS;
}

static inline void pas_fuse_close(void)
{
}
#endif /* CFG_QCOM_PAS_AUTH */

TEE_Result pas_fuse_get_secboot_and_root_anchor(uint8_t *anchor,
						bool *secboot_on);

struct pas_device_ids {
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t jtag_id;
	uint32_t serial_num;
};

struct pas_fuse_hw_binding_info {
	struct pas_device_ids ids;
	bool use_serial_num_override;
	uint32_t soc_fam_dev;
};

TEE_Result pas_fuse_get_hw_binding_info(bool need_soc_vers,
					struct pas_fuse_hw_binding_info *info);

TEE_Result pas_fuse_get_eku_enforcement_en(bool *eku_enforced);

/*
 * Query the firmware-segment hash-table digest size for @root_cert_sel.
 * @root_cert_sel selects which algorithm-select fuse bit is read.
 * Unrelated to certificate-chain or root-of-trust hashing.
 */
TEE_Result pas_fuse_get_segment_hash_len(uint32_t root_cert_sel,
					 uint32_t *hash_len);

#endif /* __PAS_FUSE_H */
