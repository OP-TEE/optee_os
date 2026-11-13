// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Qualcomm Shared Memory (SMEM) - TFA platform integration
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <mm/core_mmu.h>

#include "drivers/qcom/smem/smem.h"
#include "smem_plat.h"

struct qti_smem_part_map {
	SLIST_ENTRY(qti_smem_part_map) link;
	uint32_t offset;
	void *va;
	size_t size;
};

SLIST_HEAD(qti_smem_part_map_list, qti_smem_part_map);

static struct qti_smem_part_map_list qti_smem_plat_map_list =
	SLIST_HEAD_INITIALIZER(qti_smem_plat_map_list);

TEE_Result qti_smem_plat_map(uint32_t offset, size_t size, uint32_t flags)
{
	struct qti_smem_part_map *part_map;
	uintptr_t pa;
	void *va;

	(void)flags;

	if ((uint64_t)offset + (uint64_t)size > (uint64_t)SMEM_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	part_map = malloc(sizeof(*part_map));
	if (!part_map)
		return TEE_ERROR_OUT_OF_MEMORY;

	pa = (uintptr_t)SMEM_BASE + (uintptr_t)offset;
	va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, size);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	part_map->offset = offset;
	part_map->va = va;
	part_map->size = size;
	SLIST_INSERT_HEAD(&qti_smem_plat_map_list, part_map, link);

	return TEE_SUCCESS;
}

void *qti_smem_plat_get_addr(uint32_t offset)
{
	struct qti_smem_part_map *part_map;

	SLIST_FOREACH(part_map, &qti_smem_plat_map_list, link) {
		if (part_map->offset == offset)
			return part_map->va;
	}

	return NULL;
}

TEE_Result qti_smem_plat_init(struct qti_smem_plat_info *plat_info)
{
	TEE_Result ret;

	if (!plat_info)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = qti_smem_host_id(QTI_SMEM_PROC_TZ, 0, 0, 0,
			       &plat_info->local_host);

	if (ret != TEE_SUCCESS)
		return ret;

	plat_info->max_items = 0xFFFF;
	plat_info->smem_size = SMEM_SIZE;

	return TEE_SUCCESS;
}
