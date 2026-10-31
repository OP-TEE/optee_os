// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <malloc.h>
#include <mm/core_mmu.h>
#include <platform_pas.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "pas_subsys.h"

struct qcom_pas_subsys *qcom_pas_lookup(uint32_t pas_id)
{
	struct qcom_pas_subsys *subsys = NULL;
	size_t count = 0;

	subsys = qcom_pas_platform_subsys(&count);
	for (size_t i = 0; i < count; i++) {
		if (subsys[i].data.pas_id == pas_id)
			return &subsys[i];
	}

	return NULL;
}

TEE_Result qcom_pas_get_fw(uint32_t pas_id, paddr_t *fw_base, size_t *fw_size)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;
	if (!subsys->data.loaded)
		return TEE_ERROR_BAD_STATE;

	*fw_base = subsys->data.fw_base;
	*fw_size = subsys->data.fw_size;

	return TEE_SUCCESS;
}

static bool qcom_pas_is_loaded(uint32_t pas_id)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);

	return subsys && subsys->data.loaded;
}

/* Returns the first PAS_ID in @data->depends_on that isn't loaded, or 0. */
static uint32_t qcom_pas_missing_dep(const struct qcom_pas_data *data)
{
	if (!data->depends_on)
		return 0;

	for (size_t i = 0; data->depends_on[i]; i++)
		if (!qcom_pas_is_loaded(data->depends_on[i]))
			return data->depends_on[i];

	return 0;
}

/* Find a still-loaded subsystem that depends on @pas_id, or NULL. */
static struct qcom_pas_subsys *qcom_pas_loaded_dependent(uint32_t pas_id)
{
	struct qcom_pas_subsys *subsys = NULL;
	size_t count = 0;

	subsys = qcom_pas_platform_subsys(&count);
	for (size_t i = 0; i < count; i++) {
		const uint32_t *deps = subsys[i].data.depends_on;

		if (!subsys[i].data.loaded || !deps)
			continue;

		for (size_t j = 0; deps[j]; j++)
			if (deps[j] == pas_id)
				return &subsys[i];
	}

	return NULL;
}

static TEE_Result pas_map_controller_window(uint32_t pas_id,
					    struct qcom_pas_data *data)
{
	if (!data)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Map the controller */
	if (!data->size)
		return TEE_SUCCESS;

	if (!data->base.pa)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!data->base.va) {
		/* Reject rather than map with an unset/unintended type. */
		if (data->map_type != MEM_AREA_IO_SEC &&
		    data->map_type != MEM_AREA_IO_NSEC) {
			EMSG("PAS %#"PRIx32" has invalid map_type %d", pas_id,
			     data->map_type);
			return TEE_ERROR_BAD_STATE;
		}

		data->base.va = (vaddr_t)core_mmu_add_mapping(data->map_type,
							      data->base.pa,
							      data->size);
		if (!data->base.va)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_platform_is_supported(uint32_t pas_id)
{
	if (!qcom_pas_lookup(pas_id))
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

TEE_Result pas_platform_capabilities(uint32_t pas_id __unused)
{
	return TEE_SUCCESS;
}

TEE_Result pas_platform_init_image(uint32_t pas_id,
				   const struct pas_metadata *metadata)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);
	struct qcom_pas_data *data = NULL;
	struct elf_info e_info = { };
	size_t fw_size = 0;
	paddr_t fw_base = 0;
	uint8_t *metadata_copy = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!metadata || !metadata->data || !metadata->size)
		return TEE_ERROR_BAD_PARAMETERS;

	metadata_copy = malloc(metadata->size);
	if (!metadata_copy)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(metadata_copy, metadata->data, metadata->size);
	res = pas_elf_get_fw_range(metadata_copy, metadata->size, &e_info,
				   &fw_base, &fw_size);
	if (res)
		goto out;

	data = &subsys->data;
	data->fw_base = fw_base;
	data->fw_size = fw_size;
	data->relocatable = pas_elf_is_relocatable(metadata_copy, &e_info);
	res = pas_map_controller_window(pas_id, data);
	if (!res && subsys->ops->fw_init_image)
		res = subsys->ops->fw_init_image(data, metadata_copy, &e_info);
out:
	free(metadata_copy);
	return res;
}

TEE_Result pas_platform_mem_setup(uint32_t pas_id, uint32_t fw_size,
				  uint32_t fw_base_low, uint32_t fw_base_high)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);
	struct qcom_pas_data *data = NULL;

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	data = &subsys->data;
	if (!data->relocatable)
		return TEE_ERROR_SECURITY;

	data->fw_size = fw_size;
	data->fw_base = fw_base_low;
	data->fw_base |= SHIFT_U64(fw_base_high, 32);

	return pas_map_controller_window(pas_id, data);
}

TEE_Result pas_platform_get_resource_table(uint32_t pas_id,
					   struct resource_table *rt,
					   size_t *size)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);

	if (!subsys || !subsys->ops->get_resource_table)
		return TEE_ERROR_NOT_SUPPORTED;

	return subsys->ops->get_resource_table(rt, size);
}

TEE_Result pas_platform_set_remote_state(uint32_t pas_id, uint32_t state)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);

	if (!subsys || !subsys->ops->fw_set_state)
		return TEE_ERROR_NOT_IMPLEMENTED;

	return subsys->ops->fw_set_state(&subsys->data, state);
}

TEE_Result pas_platform_auth_and_reset(uint32_t pas_id)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);
	TEE_Result res = TEE_ERROR_GENERIC;
	struct qcom_pas_data *data = NULL;
	uint32_t missing = 0;

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	data = &subsys->data;
	if (!data->fw_base)
		return TEE_ERROR_NO_DATA;

	/* Every dependency must be loaded before fw_start() runs. */
	missing = qcom_pas_missing_dep(data);
	if (missing) {
		EMSG("PAS %#"PRIx32" depends on %#"PRIx32", not loaded",
		     pas_id, missing);
		return TEE_ERROR_BAD_STATE;
	}

	switch (subsys->reset_seq) {
	case QCOM_PAS_RESET_CLK_FULL:
		res = qcom_clock_enable(data->clk_group);
		if (res != TEE_SUCCESS)
			return res;

		res = subsys->ops->fw_start(data);
		if (res != TEE_SUCCESS)
			return res;

		res = qcom_clock_enable_pas_processor(data->clk_group);
		break;
	case QCOM_PAS_RESET_CLK_ENABLE:
		res = qcom_clock_enable(data->clk_group);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to enable clocks: %d", res);
			return res;
		}

		res = subsys->ops->fw_start(data);
		break;
	case QCOM_PAS_RESET_NONE:
		res = subsys->ops->fw_start(data);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (res == TEE_SUCCESS)
		data->loaded = true;

	return res;
}

TEE_Result pas_platform_shutdown(uint32_t pas_id)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);
	struct qcom_pas_subsys *dependent = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!subsys || !subsys->ops->fw_shutdown)
		return TEE_ERROR_NOT_SUPPORTED;

	dependent = qcom_pas_loaded_dependent(pas_id);
	if (dependent) {
		EMSG("PAS %#"PRIx32" still depended on by %#"PRIx32, pas_id,
		     dependent->data.pas_id);
		return TEE_ERROR_BAD_STATE;
	}

	res = subsys->ops->fw_shutdown(&subsys->data);
	if (!res) {
		subsys->data.fw_base = 0;
		subsys->data.fw_size = 0;
		subsys->data.loaded = false;
	}

	return res;
}
