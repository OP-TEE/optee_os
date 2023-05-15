// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022, STMicroelectronics - All Rights Reserved
 */

#include <config.h>
#include <drivers/stm32_bsec.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx.h>
#include <kernel/user_ta.h>
#include <mm/vm.h>
#include <pta_stm32mp_bsec.h>
#include <string.h>
#include <util.h>

static_assert(IS_ENABLED(CFG_STM32_BSEC));

#define PTA_NAME "bsec.pta"

static TEE_Result bsec_check_access(uint32_t otp_id)
{
	if (!stm32_bsec_nsec_can_access_otp(otp_id))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result bsec_read_mem(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t *buf = (uint32_t *)params[1].memref.buffer;
	uint32_t otp_start = 0;
	size_t otp_length = 0;
	uint32_t otp_id = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t size = params[1].memref.size;
	bool locked = false;
	unsigned int otp_base_offset = params[0].value.a;
	unsigned int bsec_command = params[0].value.b;

	if (pt != exp_pt || !buf || !size ||
	    !IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check 32bits alignment */
	if (otp_base_offset % BSEC_BYTES_PER_WORD ||
	    size % BSEC_BYTES_PER_WORD)
		return TEE_ERROR_BAD_PARAMETERS;

	otp_start = otp_base_offset / BSEC_BYTES_PER_WORD;
	otp_length = size / BSEC_BYTES_PER_WORD;

	for (otp_id = otp_start; otp_id < otp_start + otp_length;
	     otp_id++, buf++) {
		res = bsec_check_access(otp_id);
		switch (bsec_command) {
		case PTA_BSEC_SHADOW_ACCESS:
			if (res) {
				/* Force 0 when access is not allowed */
				*buf = 0x0;
				continue;
			}
			/* Read shadow register */
			res = stm32_bsec_read_otp(buf, otp_id);
			FMSG("Read shadow %"PRIu32" val: %#"PRIx32, otp_id,
			     *buf);
			break;
		case PTA_BSEC_FUSE_ACCESS:
			/* Check access */
			if (res)
				goto out;
			/* Read fuse value */
			res = stm32_bsec_shadow_read_otp(buf, otp_id);
			FMSG("Read fuse %"PRIu32" val: %#"PRIx32, otp_id, *buf);
			break;
		case PTA_BSEC_LOCKS_ACCESS:
			if (res) {
				/* Force error when access is not allowed */
				*buf = PTA_BSEC_LOCK_ERROR;
				continue;
			}
			*buf = 0;
			/* Read lock value */
			res = stm32_bsec_read_permanent_lock(otp_id, &locked);
			if (res)
				goto out;

			if (locked)
				*buf |= PTA_BSEC_LOCK_PERM;

			res = stm32_bsec_read_sr_lock(otp_id, &locked);
			if (res)
				goto out;

			if (locked)
				*buf |= PTA_BSEC_LOCK_SHADOW_R;

			res = stm32_bsec_read_sw_lock(otp_id, &locked);
			if (res)
				goto out;

			if (locked)
				*buf |= PTA_BSEC_LOCK_SHADOW_W;

			res = stm32_bsec_read_sp_lock(otp_id, &locked);
			if (res)
				goto out;

			if (locked)
				*buf |= PTA_BSEC_LOCK_SHADOW_P;

			FMSG("Read lock %"PRIu32" val: %#"PRIx32, otp_id, *buf);
			break;
		default:
			FMSG("%"PRIu32" invalid operation: %"PRIu32, otp_id,
			     bsec_command);
			res = TEE_ERROR_BAD_PARAMETERS;
		}

		if (res)
			goto out;
	}

	FMSG("Buffer orig %p, size %zu", buf, size);

	res = TEE_SUCCESS;
out:
	return res;
}

static TEE_Result bsec_write_mem(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	uint32_t *buf = (uint32_t *)params[1].memref.buffer;
	size_t size = params[1].memref.size;
	uint32_t otp_start = 0;
	size_t otp_length = 0;
	uint32_t otp_id = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned int otp_base_offset = params[0].value.a;
	unsigned int bsec_command = params[0].value.b;

	if (pt != exp_pt || !buf || !size ||
	    !IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check 32bits alignment */
	if (otp_base_offset % BSEC_BYTES_PER_WORD ||
	    size % BSEC_BYTES_PER_WORD)
		return TEE_ERROR_BAD_PARAMETERS;

	otp_start = otp_base_offset / BSEC_BYTES_PER_WORD;
	otp_length = size / BSEC_BYTES_PER_WORD;

	/* Initial check to ensure that all BSEC words are available */
	for (otp_id = otp_start; otp_id < otp_start + otp_length; otp_id++) {
		res = bsec_check_access(otp_id);
		if (res)
			return res;
	}

	for (otp_id = otp_start; otp_id < otp_start + otp_length;
	     otp_id++, buf++) {
		switch (bsec_command) {
		case PTA_BSEC_SHADOW_ACCESS:
			/* Write shadow register */
			FMSG("Write shadow %"PRIx32" : %"PRIx32,
			     otp_id, *buf);
			res = stm32_bsec_write_otp(*buf, otp_id);
			break;

		case PTA_BSEC_FUSE_ACCESS:
			/* Write fuse value */
			FMSG("Write fuse %"PRIx32" : %08"PRIx32,
			     otp_id, *buf);
			res = stm32_bsec_program_otp(*buf, otp_id);
			break;

		case PTA_BSEC_LOCKS_ACCESS:
			if (*buf & PTA_BSEC_LOCK_PERM) {
				FMSG("Perm lock access OTP: %u", otp_id);
				res = stm32_bsec_permanent_lock_otp(otp_id);
				if (res)
					break;
			}

			if (*buf & PTA_BSEC_LOCK_SHADOW_R) {
				FMSG("Shadow read lock");
				res = stm32_bsec_set_sr_lock(otp_id);
				if (res)
					break;
			}

			if (*buf & PTA_BSEC_LOCK_SHADOW_W) {
				FMSG("Shadow write lock detected");
				res = stm32_bsec_set_sw_lock(otp_id);
				if (res)
					break;
			}

			if (*buf & PTA_BSEC_LOCK_SHADOW_P) {
				FMSG("Shadow programming lock detected");
				res = stm32_bsec_set_sp_lock(otp_id);
			}

			break;

		default:
			FMSG("OTP %"PRIx32" invalid operation: %"PRIx32,
			     otp_id, bsec_command);
			res = TEE_ERROR_BAD_PARAMETERS;
		}

		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result bsec_pta_state(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	enum stm32_bsec_sec_state state = BSEC_STATE_INVALID;
	enum stm32_bsec_pta_sec_state pta_state = PTA_BSEC_STATE_INVALID;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = stm32_bsec_get_state(&state);
	if (res)
		return res;

	switch (state) {
	case BSEC_STATE_SEC_CLOSED:
		pta_state = PTA_BSEC_STATE_SEC_CLOSE;
		break;
	case BSEC_STATE_SEC_OPEN:
		pta_state = PTA_BSEC_STATE_SEC_OPEN;
		break;
	default:
		pta_state = PTA_BSEC_STATE_INVALID;
		break;
	}

	params[0].value.a = pta_state;

	return TEE_SUCCESS;
}

static TEE_Result bsec_pta_invoke_command(void *pSessionContext __unused,
					  uint32_t cmd_id,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32,
	     cmd_id, param_types);

	switch (cmd_id) {
	case PTA_BSEC_CMD_READ_OTP:
		return bsec_read_mem(param_types, params);
	case PTA_BSEC_CMD_WRITE_OTP:
		return bsec_write_mem(param_types, params);
	case PTA_BSEC_CMD_GET_STATE:
		return bsec_pta_state(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result pta_bsec_open_session(uint32_t ptypes __unused,
					TEE_Param par[TEE_NUM_PARAMS] __unused,
					void **session __unused)
{
	uint32_t login = to_ta_session(ts_get_current_session())->clnt_id.login;

	if (login == TEE_LOGIN_REE_KERNEL)
		return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_DENIED;
}

pseudo_ta_register(.uuid = PTA_BSEC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = pta_bsec_open_session,
		   .invoke_command_entry_point = bsec_pta_invoke_command);
