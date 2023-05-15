// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm_gpio.h>
#include <io.h>
#include <kernel/pseudo_ta.h>
#include <trace.h>

#define GPIO_SERVICE_UUID \
		{ 0x6272636D, 0x2018, 0x1101,  \
		{ 0x42, 0x43, 0x4D, 0x5F, 0x47, 0x50, 0x49, 0x4F } }

/*
 * Configure GPIO Pin
 *
 * [in]    value[0].a:    gpio pin number
 * [in]    value[0].b:    direction to configure
 */
#define PTA_BCM_GPIO_CMD_CFG	0

/*
 * Set GPIO pin
 *
 * [in]    value[0].a:    gpio pin number
 * [in]    value[0].b:    value drive on pin
 */
#define PTA_BCM_GPIO_CMD_SET	1

/*
 * Get GPIO pin
 *
 * [in]    value[0].a:    gpio pin number
 * [out]   value[1].a:    value read from gpio pin
 */
#define PTA_BCM_GPIO_CMD_GET	2

#define GPIO_TA_NAME		"pta_bcm_gpio.ta"

static TEE_Result pta_gpio_config(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t gpio_num = 0;
	struct bcm_gpio_chip *bcm_gc = NULL;
	struct gpio_chip *gc = NULL;
	bool dir = false;
	TEE_Result res = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	gpio_num = params[0].value.a;
	dir = params[0].value.b;

	bcm_gc = bcm_gpio_pin_to_chip(gpio_num);
	if (!bcm_gc) {
		EMSG("GPIO %u not supported", gpio_num);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	gc = &bcm_gc->chip;

	/* Make gpio secure. */
	iproc_gpio_set_secure(gpio_num);

	if (dir) {
		/* Set GPIO to output with default value to 0 */
		gc->ops->set_direction(NULL, gpio_num, GPIO_DIR_OUT);
		gc->ops->set_value(NULL, gpio_num, 0);
	} else {
		gc->ops->set_direction(NULL, gpio_num, GPIO_DIR_IN);
	}

	return res;
}

static TEE_Result pta_gpio_set(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t gpio_num = 0;
	uint32_t val = 0;
	TEE_Result res = TEE_SUCCESS;
	struct bcm_gpio_chip *bcm_gc = NULL;
	struct gpio_chip *gc = NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	gpio_num = params[0].value.a;
	val = !!params[0].value.b;

	bcm_gc = bcm_gpio_pin_to_chip(gpio_num);
	if (!bcm_gc) {
		EMSG("GPIO %u not supported", gpio_num);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	gc = &bcm_gc->chip;

	/*
	 * For setting a value to GPIO Pin,
	 * need to make sure the PIN is configured in
	 * output direction.
	 */
	if (gc->ops->get_direction(NULL, gpio_num) != GPIO_DIR_OUT) {
		EMSG("gpio pin %u is configured as INPUT", gpio_num);
		return TEE_ERROR_ACCESS_DENIED;
	}

	gc->ops->set_value(NULL, gpio_num, val);

	DMSG("GPIO(%d) value = 0x%08x", gpio_num,
	     gc->ops->get_value(NULL, gpio_num));

	return res;
}

static TEE_Result pta_gpio_get(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t gpio_num = 0;
	struct bcm_gpio_chip *bcm_gc = NULL;
	struct gpio_chip *gc = NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	gpio_num = params[0].value.a;

	bcm_gc = bcm_gpio_pin_to_chip(gpio_num);
	if (!bcm_gc) {
		EMSG("GPIO %u not supported", gpio_num);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	gc = &bcm_gc->chip;

	params[1].value.a = gc->ops->get_value(NULL, gpio_num);

	DMSG("gpio(%d) value = 0x%08x", gpio_num, params[1].value.a);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, GPIO_TA_NAME);

	switch (cmd_id) {
	case PTA_BCM_GPIO_CMD_CFG:
		res = pta_gpio_config(param_types, params);
		break;
	case PTA_BCM_GPIO_CMD_SET:
		res = pta_gpio_set(param_types, params);
		break;
	case PTA_BCM_GPIO_CMD_GET:
		res = pta_gpio_get(param_types, params);
		break;
	default:
		EMSG("cmd: %d Not supported %s\n", cmd_id, GPIO_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = GPIO_SERVICE_UUID,
		   .name = GPIO_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
