// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/clk_qcom.h>
#include <mm/core_mmu.h>
#include <platform_pas.h>
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

bool qcom_pas_is_loaded(uint32_t pas_id)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);

	return subsys && subsys->data.loaded;
}

/*
 * qcom_pas_dependent() : find the subsystem that depends on @dtb_pas_id.
 *
 * @dtb_pas_id: PAS_ID to search for among the platform's dtb_pas_id fields.
 * Returns the dependent subsystem, or NULL if @dtb_pas_id is unset (0) or
 * nothing depends on it.
 */
static struct qcom_pas_subsys *qcom_pas_dependent(uint32_t dtb_pas_id)
{
	struct qcom_pas_subsys *subsys = NULL;
	size_t count = 0;

	if (!dtb_pas_id)
		return NULL;

	subsys = qcom_pas_platform_subsys(&count);
	for (size_t i = 0; i < count; i++)
		if (subsys[i].data.dtb_pas_id == dtb_pas_id)
			return &subsys[i];

	return NULL;
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

TEE_Result pas_platform_init_image(uint32_t pas_id)
{
	if (!qcom_pas_lookup(pas_id))
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

TEE_Result pas_platform_mem_setup(uint32_t pas_id, uint32_t fw_size,
				  uint32_t fw_base_low, uint32_t fw_base_high)
{
	struct qcom_pas_subsys *subsys = qcom_pas_lookup(pas_id);
	struct qcom_pas_data *data = NULL;

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	data = &subsys->data;
	data->fw_size = fw_size;
	data->fw_base = fw_base_low;
	data->fw_base |= SHIFT_U64(fw_base_high, 32);

	/*
	 * Subsystems with no MMIO controller window of their own (e.g. a
	 * DTB blob) have data->size == 0 and carry only fw_base/fw_size;
	 * skip mapping for them.
	 */
	if (data->size && !data->base.va) {
		enum teecore_memtypes type = data->map_secure ?
					      MEM_AREA_IO_SEC :
					      MEM_AREA_IO_NSEC;

		data->base.va = (vaddr_t)core_mmu_add_mapping(type,
							      data->base.pa,
							      data->size);
		if (!data->base.va)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
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

	if (!subsys)
		return TEE_ERROR_NOT_SUPPORTED;

	data = &subsys->data;
	if (!data->fw_base)
		return TEE_ERROR_NO_DATA;

	switch (subsys->reset_seq) {
	case QCOM_PAS_RESET_CLK_FULL:
		res = qcom_clock_pas_reset(data->clk_group);
		if (res != TEE_SUCCESS)
			return res;

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

	dependent = qcom_pas_dependent(pas_id);
	if (dependent && dependent->data.loaded) {
		EMSG("PAS %#"PRIx32" still depends on %#"PRIx32, pas_id,
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
