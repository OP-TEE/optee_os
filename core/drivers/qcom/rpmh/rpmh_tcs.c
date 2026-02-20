// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <kernel/tee_time.h>
#include <malloc.h>
#include <string.h>

#include "rpmh_drv_config.h"
#include "rpmh_hal.h"
#include "rpmh_tcs.h"

struct tcs_driver_state {
	struct tcs **tcs;
	uint32_t *mode;
};

static struct tcs_driver_state tcs_driver_state;

static uint64_t get_timestamp(void)
{
	TEE_Time time = { };

	tee_time_get_sys_time(&time);
	return (uint64_t)time.seconds * 1000000 + time.millis * 1000;
}

bool rpmh_tcs_drv_valid(enum rsc_drv_id drv_id)
{
	uint32_t i = 0;

	for (i = 0; i < g_drv_config_data->drvs_count; i++) {
		if (g_drv_config_data->drvs[i].drv_id == drv_id)
			return true;
	}

	return false;
}

TEE_Result rpmh_tcs_find_drv_index(enum rsc_drv_id drv_id,
				   uint32_t *drv_index)
{
	uint32_t i = 0;

	if (!drv_index)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < g_drv_config_data->drvs_count; i++) {
		if (g_drv_config_data->drvs[i].drv_id == drv_id) {
			*drv_index = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result rpmh_tcs_size(enum rsc_drv_id drv_id, uint32_t *size)
{
	const struct drv_config *drv = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t drv_index = 0;

	if (!size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = rpmh_tcs_find_drv_index(drv_id, &drv_index);
	if (res)
		return res;

	drv = &g_drv_config_data->drvs[drv_index];
	*size = drv->cmds;

	return TEE_SUCCESS;
}

static void update_mode(uint32_t drv_index, uint32_t mode)
{
	const struct drv_config *drv = &g_drv_config_data->drvs[drv_index];
	uint32_t i = 0;

	if (mode >= drv->modes_count)
		mode = 0;

	tcs_driver_state.mode[drv_index] = mode;

	for (i = 0; i < drv->tcs; i++) {
		struct tcs *tcs = &tcs_driver_state.tcs[drv_index][i];

		tcs->id = i + drv->tcs_offset;
		tcs->sent_at = 0;
		hal_rpmh_clear_amc_status(drv->hw_drv, tcs->id);

		if (i < drv->modes[mode]->amcs) {
			tcs->state = TCS_AMC_IDLE;
			hal_rpmh_convert_to_amc(drv->hw_drv, tcs->id);
		} else {
			tcs->state = TCS_NON_AMC;
			hal_rpmh_convert_to_tcs(drv->hw_drv, tcs->id);
		}
	}
}

TEE_Result rpmh_tcs_init(void)
{
	enum hal_status status = HAL_STATUS_SUCCESS;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	uint32_t cmds = 0;
	uint32_t tcs = 0;
	uint32_t i = 0;
	uint32_t j = 0;

	tcs_driver_state.tcs = calloc(g_drv_config_data->drvs_count,
				      sizeof(struct tcs *));
	if (!tcs_driver_state.tcs)
		return TEE_ERROR_OUT_OF_MEMORY;

	tcs_driver_state.mode = calloc(g_drv_config_data->drvs_count,
				       sizeof(uint32_t));
	if (!tcs_driver_state.mode)
		goto err_free_tcs;

	for (i = 0; i < g_drv_config_data->drvs_count; i++) {
		const struct drv_config *drv = &g_drv_config_data->drvs[i];

		tcs_driver_state.tcs[i] = calloc(drv->tcs, sizeof(struct tcs));
		if (!tcs_driver_state.tcs[i])
			goto err_free_tcs_array;

		tcs_driver_state.mode[i] = 0;

		if (drv->drv_id >= RSC_DRV_VIRTUAL_DRVS) {
			update_mode(i, 0);
			continue;
		}

		status = hal_rpmh_register_drv(drv->drv_id);
		if (status != HAL_STATUS_SUCCESS)
			goto err_free_tcs_array_i;

		status = hal_rpmh_read_config(drv->drv_id, &tcs, &cmds);
		if (status != HAL_STATUS_SUCCESS)
			goto err_free_tcs_array_i;

		hal_rpmh_update_epcb_timeout(drv->drv_id, 0xFFFF);
		hal_rpmh_toggle_epcb_timeout(drv->drv_id, true);
		update_mode(i, 0);
	}

	return TEE_SUCCESS;

err_free_tcs_array_i:
	res = TEE_ERROR_GENERIC;
	free(tcs_driver_state.tcs[i]);
err_free_tcs_array:
	for (j = 0; j < i; j++)
		free(tcs_driver_state.tcs[j]);
	free(tcs_driver_state.mode);
err_free_tcs:
	free(tcs_driver_state.tcs);
	return res;
}

bool rpmh_tcs_is_amc_free(enum rsc_drv_id drv_id)
{
	const struct drv_config *drv = NULL;
	uint32_t drv_index = 0;
	uint32_t amcs = 0;
	uint32_t i = 0;

	if (rpmh_tcs_find_drv_index(drv_id, &drv_index))
		return false;

	drv = &g_drv_config_data->drvs[drv_index];
	amcs = drv->modes[tcs_driver_state.mode[drv_index]]->amcs;

	for (i = 0; i < amcs; i++) {
		if (tcs_driver_state.tcs[drv_index][i].state == TCS_AMC_IDLE)
			return true;
	}

	return false;
}

bool rpmh_tcs_is_amc_finished(enum rsc_drv_id drv_id)
{
	enum hal_status status = HAL_STATUS_SUCCESS;
	const struct drv_config *drv = NULL;
	uint32_t drv_index = 0;
	bool finished = false;
	uint32_t amcs = 0;
	uint32_t i = 0;

	if (rpmh_tcs_find_drv_index(drv_id, &drv_index))
		return false;

	drv = &g_drv_config_data->drvs[drv_index];
	amcs = drv->modes[tcs_driver_state.mode[drv_index]]->amcs;

	for (i = 0; i < amcs; i++) {
		struct tcs *tcs = &tcs_driver_state.tcs[drv_index][i];

		if (tcs->state != TCS_AMC_WAIT_FOR_DONE)
			continue;

		status = hal_rpmh_get_amc_status(drv->hw_drv,
						 tcs->id,
						 &finished);
		if (status == HAL_STATUS_SUCCESS && finished)
			return true;
	}

	return false;
}

TEE_Result rpmh_tcs_send(struct rpmh_cmd *cmd, enum rsc_drv_id drv_id)
{
	enum hal_status status = HAL_STATUS_SUCCESS;
	const struct drv_config *drv = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t enable_mask = 0;
	uint32_t drv_index = 0;
	struct tcs *tcs = NULL;
	uint32_t amcs = 0;
	uint32_t i = 0;
	uint32_t j = 0;

	if (!cmd)
		return TEE_ERROR_BAD_PARAMETERS;

	res = rpmh_tcs_find_drv_index(drv_id, &drv_index);
	if (res)
		return res;

	drv = &g_drv_config_data->drvs[drv_index];
	amcs = drv->modes[tcs_driver_state.mode[drv_index]]->amcs;

	for (i = 0; i < amcs; i++) {
		tcs = &tcs_driver_state.tcs[drv_index][i];
		if (tcs->state == TCS_AMC_IDLE)
			break;
	}

	if (i == amcs)
		return TEE_ERROR_BUSY;

	for (j = 0; j < cmd->num_rcs; j++) {
		status = hal_rpmh_write_cmd(drv->hw_drv, tcs->id, j,
					    cmd->details[j].address,
					    cmd->details[j].data,
					    cmd->details[j].completion);
		if (status != HAL_STATUS_SUCCESS)
			return TEE_ERROR_GENERIC;
		enable_mask |= BIT(j);
	}

	hal_rpmh_clear_amc_status(drv->hw_drv, tcs->id);
	status = hal_rpmh_enable_amc_status(drv->hw_drv, tcs->id);
	if (status != HAL_STATUS_SUCCESS)
		return TEE_ERROR_GENERIC;

	tcs->state = TCS_AMC_WAIT_FOR_DONE;
	tcs->sent_at = get_timestamp();
	tcs->cmds = cmd;

	status = hal_rpmh_send_tcs(drv->hw_drv, tcs->id, enable_mask);
	if (status != HAL_STATUS_SUCCESS) {
		tcs->state = TCS_AMC_IDLE;
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result rpmh_tcs_finish_active_amc(struct rpmh_client **client,
				      struct rpmh_cmdq *cmdq,
				      enum rsc_drv_id drv_id,
				      uint32_t *req_id)
{
	enum hal_status status = HAL_STATUS_SUCCESS;
	const struct drv_config *drv = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t drv_index = 0;
	bool finished = false;
	uint32_t amcs = 0;
	uint32_t i = 0;

	if (!req_id)
		return TEE_ERROR_BAD_PARAMETERS;

	*req_id = 0;

	res = rpmh_tcs_find_drv_index(drv_id, &drv_index);
	if (res)
		return res;

	drv = &g_drv_config_data->drvs[drv_index];
	amcs = drv->modes[tcs_driver_state.mode[drv_index]]->amcs;

	for (i = 0; i < amcs; i++) {
		struct tcs *tcs = &tcs_driver_state.tcs[drv_index][i];

		if (tcs->state != TCS_AMC_WAIT_FOR_DONE)
			continue;

		status = hal_rpmh_get_amc_status(drv->hw_drv,
						 tcs->id,
						 &finished);
		if (status != HAL_STATUS_SUCCESS || !finished)
			continue;

		hal_rpmh_clear_amc_status(drv->hw_drv, tcs->id);

		if (tcs->cmds)
			*req_id = tcs->cmds->req_id;

		if (client && cmdq && tcs->cmds)
			*client = NULL;

		tcs->state = TCS_AMC_IDLE;
		tcs->cmds = NULL;

		return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result rpmh_tcs_slots_available(enum rsc_drv_id drv_id,
				    enum rpmh_set set,
				    uint32_t slots,
				    uint32_t *tcs_index)
{
	const struct tcs_config *mode = NULL;
	const struct drv_config *drv = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t drv_index = 0;
	struct tcs *tcs = NULL;
	uint32_t start = 0;
	uint32_t end = 0;
	uint32_t i = 0;

	if (!tcs_index)
		return TEE_ERROR_BAD_PARAMETERS;

	res = rpmh_tcs_find_drv_index(drv_id, &drv_index);
	if (res)
		return res;

	drv = &g_drv_config_data->drvs[drv_index];
	mode = drv->modes[tcs_driver_state.mode[drv_index]];

	if (slots > drv->cmds)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (set) {
	case RPMH_SET_SLEEP:
		start = mode->sleep_start;
		end = mode->wake_start;
		break;
	case RPMH_SET_WAKE:
		start = mode->wake_start;
		end = drv->tcs;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	for (i = start; i < end; i++) {
		tcs = &tcs_driver_state.tcs[drv_index][i];

		if (!tcs->cmds) {
			*tcs_index = i;
			return TEE_SUCCESS;
		}

		if (slots <= (drv->cmds - tcs->cmds->num_rcs)) {
			*tcs_index = i;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

bool rpmh_tcs_is_stuck(enum rsc_drv_id drv_id)
{
	enum hal_status status = HAL_STATUS_SUCCESS;
	const struct drv_config *drv = NULL;
	uint64_t current_time = 0;
	uint32_t drv_index = 0;
	bool is_idle = false;
	uint32_t amcs = 0;
	uint32_t i = 0;

	if (rpmh_tcs_find_drv_index(drv_id, &drv_index))
		return false;

	drv = &g_drv_config_data->drvs[drv_index];
	amcs = drv->modes[tcs_driver_state.mode[drv_index]]->amcs;
	current_time = get_timestamp();

	for (i = 0; i < amcs; i++) {
		struct tcs *tcs = &tcs_driver_state.tcs[drv_index][i];

		status = hal_rpmh_is_tcs_idle(drv->hw_drv, tcs->id, &is_idle);
		if (status != HAL_STATUS_SUCCESS)
			continue;

		if (is_idle || !tcs->sent_at)
			continue;

		if (current_time > (tcs->sent_at +
				    TCS_TIMEOUT_THRESHOLD))
			return true;
	}

	return false;
}

TEE_Result rpmh_tcs_get_finished_drv(enum rsc_drv_id hw_drv,
				     enum rsc_drv_id *finished_drv)
{
	const struct drv_config *drv = g_drv_config_data->drvs;
	uint32_t i = 0;

	if (!finished_drv)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hw_drv < RSC_DRV_VIRTUAL_DRVS) {
		*finished_drv = hw_drv;
		return TEE_SUCCESS;
	}

	for (i = 0; i < g_drv_config_data->drvs_count; i++, drv++) {
		if (drv->hw_drv != hw_drv)
			continue;

		if (rpmh_tcs_is_amc_finished(drv->drv_id)) {
			*finished_drv = drv->drv_id;
			return TEE_SUCCESS;
		}
	}

	*finished_drv = RSC_DRV_VIRTUAL_MAX;

	return TEE_ERROR_ITEM_NOT_FOUND;
}
