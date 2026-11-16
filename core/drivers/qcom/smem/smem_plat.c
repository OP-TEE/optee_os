// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <mm/core_mmu.h>
#include <util.h>

#include <drivers/qcom/smem.h>
#include "smem_plat.h"

struct qcom_smem_part_map {
	SLIST_ENTRY(qcom_smem_part_map) link;
	uint32_t offset;
	void *va;
	size_t size;
};

SLIST_HEAD(qcom_smem_part_map_list, qcom_smem_part_map);

static struct qcom_smem_part_map_list qcom_smem_plat_map_list =
	SLIST_HEAD_INITIALIZER(qcom_smem_plat_map_list);

TEE_Result qcom_smem_plat_map(uint32_t offset, size_t size, uint32_t flags)
{
	struct qcom_smem_part_map *part_map = NULL;
	uintptr_t pa = 0;
	void *va = NULL;
	size_t end = 0;

	(void)flags;

	if (ADD_OVERFLOW(offset, size, &end) || end > SMEM_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	part_map = malloc(sizeof(*part_map));
	if (!part_map)
		return TEE_ERROR_OUT_OF_MEMORY;

	pa = SMEM_BASE + offset;
	va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, size);
	if (!va) {
		free(part_map);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	part_map->offset = offset;
	part_map->va = va;
	part_map->size = size;
	SLIST_INSERT_HEAD(&qcom_smem_plat_map_list, part_map, link);

	return TEE_SUCCESS;
}

void qcom_smem_plat_unmap_all(void)
{
	struct qcom_smem_part_map *part_map = NULL;

	while (!SLIST_EMPTY(&qcom_smem_plat_map_list)) {
		part_map = SLIST_FIRST(&qcom_smem_plat_map_list);
		SLIST_REMOVE_HEAD(&qcom_smem_plat_map_list, link);
		if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, part_map->va,
					    part_map->size))
			EMSG("smem: failed to unmap offset %#" PRIx32,
			     part_map->offset);
		free(part_map);
	}
}

void *qcom_smem_plat_get_addr(uint32_t offset)
{
	struct qcom_smem_part_map *part_map = NULL;

	SLIST_FOREACH(part_map, &qcom_smem_plat_map_list, link) {
		if (part_map->offset == offset)
			return part_map->va;
	}

	return NULL;
}

TEE_Result qcom_smem_plat_init(struct qcom_smem_plat_info *plat_info)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!plat_info)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_smem_host_id(QCOM_SMEM_PROC_TZ, 0, 0, 0,
				&plat_info->local_host);

	if (res)
		return res;

	plat_info->max_items = 0xFFFF;
	plat_info->smem_size = SMEM_SIZE;

	return TEE_SUCCESS;
}
