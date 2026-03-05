// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stdint.h>
#include <string.h>

#include "pas.h"
#include "pas_resources.h"

static TEE_Result get_mem_rsc(struct resource_table *rt, size_t *rt_size,
			      struct resource_table *table,
			      const struct fw_rsc_hdr *mem_hdr,
			      const struct fw_rsc_devmem *mem_res,
			      size_t table_header_size, size_t table_size)
{
	uint8_t *p = (uint8_t *)rt;
	uint32_t offset = 0;

	if (rt_size && *rt_size < table_size) {
		*rt_size = table_size;

		return TEE_SUCCESS;
	}

	if (!rt)
		return TEE_ERROR_BAD_PARAMETERS;

	offset = table_header_size;

	for (size_t i = 0; i < table->num; i++, mem_res++) {
		table->offset[i] = offset;
		memcpy(p + offset, mem_hdr, sizeof(*mem_hdr));
		offset += sizeof(*mem_hdr);
		memcpy(p + offset, mem_res, sizeof(*mem_res));
		offset += sizeof(*mem_res);
	}

	memcpy(p, table, table_header_size);

	return TEE_SUCCESS;
}

TEE_Result pas_get_resource_table(uint32_t pas_id, struct resource_table *rt,
				  size_t *rt_size)
{
	switch (pas_id) {
	case PAS_ID_WPSS:
		return get_mem_rsc(rt, rt_size, &wpss_rt, &wpss_mem_hdr,
				   wpss_mem_res,
				   WPSS_RESOURCE_TABLE_HEADER_SIZE,
				   WPSS_RESOURCE_TABLE_SIZE);
	case PAS_ID_TURING:
		return get_mem_rsc(rt, rt_size, &turing_rt, &turing_mem_hdr,
				   turing_mem_res,
				   TURING_RESOURCE_TABLE_HEADER_SIZE,
				   TURING_RESOURCE_TABLE_SIZE);
	case PAS_ID_QDSP6:
		return get_mem_rsc(rt, rt_size, &lpass_rt, &lpass_mem_hdr,
				   lpass_mem_res,
				   LPASS_RESOURCE_TABLE_HEADER_SIZE,
				   LPASS_RESOURCE_TABLE_SIZE);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
