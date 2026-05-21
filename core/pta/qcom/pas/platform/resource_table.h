/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef RESOURCE_TABLE_H
#define RESOURCE_TABLE_H

#include <compiler.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#define DEFINE_RESOURCE_TABLE(prefix, num_res)			\
	enum {							\
		prefix##_NUM_MEM_RESOURCES = (num_res),		\
		prefix##_SIZE_MEM_RES =				\
			(sizeof(struct fw_rsc_hdr) +		\
			 sizeof(struct fw_rsc_devmem)),		\
		prefix##_RESOURCE_TABLE_HEADER_SIZE =		\
			(sizeof(struct resource_table) +	\
			 (prefix##_NUM_MEM_RESOURCES *		\
			  sizeof(uint32_t))),			\
		prefix##_RESOURCE_TABLE_SIZE =			\
			(prefix##_RESOURCE_TABLE_HEADER_SIZE +	\
			 (prefix##_NUM_MEM_RESOURCES *		\
			  prefix##_SIZE_MEM_RES)),		\
	}

struct resource_table {
	uint32_t ver;
	uint32_t num;
	uint32_t reserved[2];
	uint32_t offset[];
} __packed;

struct fw_rsc_hdr {
	uint32_t type;
	uint8_t data[];
} __packed;

enum fw_resource_type {
	RSC_CARVEOUT		= 0,
	RSC_DEVMEM		= 1,
	RSC_TRACE		= 2,
	RSC_VDEV		= 3,
	RSC_LAST		= 4,
	RSC_VENDOR_START	= 128,
	RSC_VENDOR_END		= 512,
};

#define IOMMU_READ	BIT(0)
#define IOMMU_WRITE	BIT(1)

struct fw_rsc_devmem {
	uint32_t da;
	uint32_t pa;
	uint32_t len;
	uint32_t flags;
	uint32_t reserved;
	uint8_t name[32];
} __packed;

static inline TEE_Result get_mem_rsc(struct resource_table *rt, size_t *rt_size,
				     struct resource_table *table,
				     const struct fw_rsc_hdr *mem_hdr,
				     const struct fw_rsc_devmem *mem_res,
				     size_t table_header_size,
				     size_t table_size)
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

#endif

