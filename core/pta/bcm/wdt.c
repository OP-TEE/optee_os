// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Broadcom
 */

#include <drivers/gic.h>
#include <drivers/sp805_wdt.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include <trace.h>

#define SEC_WD_SERVICE_UUID \
		{ 0x6272636D, 0x2019, 0x0801,  \
		{ 0x42, 0x43, 0x4D, 0x5F, 0x57, 0x44, 0x54, 0x30 } }

#define PTA_BCM_SEC_WD_CMD_CONFIG	0
#define PTA_BCM_SEC_WD_CMD_START	1
#define PTA_BCM_SEC_WD_CMD_PING		2
#define PTA_BCM_SEC_WD_CMD_STOP		3
#define PTA_BCM_SEC_WD_CMD_SET_TIMEOUT	4

#define SEC_WD_TA_NAME		"pta_bcm_sec_wd.ta"

static struct sp805_wdt_data wd_pd;

static void wd_isr_handler(struct wdt_chip *chip __unused)
{
	/* Do nothing */
	DMSG("Watchdog ISR handler !!!");
}

static TEE_Result pta_wd_config(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t timeout = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	timeout = params[0].value.a;

	sp805_wdt_init(&wd_pd, SEC_WDT_BASE, SEC_WDT_CLK_HZ, timeout);

	sp805_register_itr_handler(&wd_pd, GIC_SPI(SEC_WDT_INTR),
				   ITRF_TRIGGER_LEVEL, wd_isr_handler);
	wd_pd.chip.ops->start(&wd_pd.chip);

	return TEE_SUCCESS;
}

static TEE_Result pta_wd_start(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wd_pd.chip.ops->start(&wd_pd.chip);

	return TEE_SUCCESS;
}

static TEE_Result pta_wd_ping(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wd_pd.chip.ops->ping(&wd_pd.chip);

	return TEE_SUCCESS;
}

static TEE_Result pta_wd_stop(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wd_pd.chip.ops->stop(&wd_pd.chip);

	return TEE_SUCCESS;
}

static TEE_Result pta_wd_set_timeout(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t timeout = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	timeout = params[0].value.a;

	wd_pd.chip.ops->set_timeout(&wd_pd.chip, timeout);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, SEC_WD_TA_NAME);

	switch (cmd_id) {
	case PTA_BCM_SEC_WD_CMD_CONFIG:
		res = pta_wd_config(param_types, params);
		break;
	case PTA_BCM_SEC_WD_CMD_START:
		res = pta_wd_start(param_types, params);
		break;
	case PTA_BCM_SEC_WD_CMD_PING:
		res = pta_wd_ping(param_types, params);
		break;
	case PTA_BCM_SEC_WD_CMD_STOP:
		res = pta_wd_stop(param_types, params);
		break;
	case PTA_BCM_SEC_WD_CMD_SET_TIMEOUT:
		res = pta_wd_set_timeout(param_types, params);
		break;
	default:
		EMSG("cmd: %d Not supported %s", cmd_id, SEC_WD_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = SEC_WD_SERVICE_UUID,
		   .name = SEC_WD_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
