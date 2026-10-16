/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_INIT_H
#define __PAS_INIT_H

#include <tee_api_types.h>
#include <types_ext.h>

struct pas_fw_region {
	paddr_t base;
	uint32_t size;
};

static inline TEE_Result pas_get_fw_region(uint64_t fw_min_addr,
					   uint64_t fw_max_addr,
					   struct pas_fw_region *fw_region)
{
	if (fw_max_addr - fw_min_addr > UINT32_MAX)
		return TEE_ERROR_BAD_FORMAT;

	fw_region->base = (paddr_t)fw_min_addr;
	fw_region->size = (uint32_t)(fw_max_addr - fw_min_addr);

	return TEE_SUCCESS;
}

/*
 * pas_get_fw_min_max_addr() : Extract the minimum and maximum load address
 * of the firmware from the metadata blob.
 *
 * The function loops over all the program headers in the metadata blob and
 * uses the p_paddr embedded in the headers to calculate the minimum and maximum
 * load/fw address of the firmware image.
 *
 * @metadata:            Input metadata.
 * @metadata_size:       Size of the input metadata.
 * @min_addr:            Minimum load address of the firmware image.
 * @max_addr:            Maximum load address of the firmware image.
 */
TEE_Result pas_get_fw_min_max_addr(const uint8_t *metadata,
				   size_t metadata_size,
				   uint64_t *min_addr, uint64_t *max_addr);

#endif /* __PAS_INIT_H */
