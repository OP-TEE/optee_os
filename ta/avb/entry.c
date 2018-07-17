// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <ta_avb.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define DEFAULT_LOCK_STATE	0

static const uint32_t storageid = TEE_STORAGE_PRIVATE_RPMB;
static const char obj_name[] = "rb_state";

static TEE_Result get_slot_offset(size_t slot, size_t *offset)
{
	if (slot >= TA_AVB_MAX_ROLLBACK_LOCATIONS)
		return TEE_ERROR_BAD_PARAMETERS;

	*offset = sizeof(uint32_t) /* lock_state */ + slot * sizeof(uint64_t);
	return TEE_SUCCESS;
}

static TEE_Result create_state(uint32_t lock_state, TEE_ObjectHandle *h)
{
	const uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			       TEE_DATA_FLAG_ACCESS_WRITE |
			       TEE_DATA_FLAG_OVERWRITE;

	return TEE_CreatePersistentObject(storageid, obj_name, sizeof(obj_name),
					  flags, NULL, &lock_state,
					  sizeof(lock_state), h);
}

static TEE_Result open_state(uint32_t default_lock_state, TEE_ObjectHandle *h)
{
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	TEE_Result res;

	res = TEE_OpenPersistentObject(storageid, obj_name,
				       sizeof(obj_name), flags, h);
	if (!res)
		return TEE_SUCCESS;

	return create_state(default_lock_state, h);
}

static TEE_Result read_rb_idx(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	size_t slot_offset;
	uint64_t idx;
	uint32_t count;
	TEE_Result res;
	TEE_ObjectHandle h;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_slot_offset(params[0].value.a, &slot_offset);
	if (res)
		return res;

	res = open_state(DEFAULT_LOCK_STATE, &h);
	if (res)
		return res;

	res = TEE_SeekObjectData(h, slot_offset, TEE_DATA_SEEK_SET);
	if (res)
		goto out;

	res =  TEE_ReadObjectData(h, &idx, sizeof(idx), &count);
	if (res)
		goto out;
	if (count != sizeof(idx)) {
		idx = 0; /* Not yet written slots are reported as 0 */

		if (count) {
			/*
			 * Somehow the file didn't even hold a complete
			 * slot index entry.  Write it as 0.
			 */
			res = TEE_SeekObjectData(h, slot_offset,
						 TEE_DATA_SEEK_SET);
			if (res)
				goto out;
			res = TEE_WriteObjectData(h, &idx, sizeof(idx));
			if (res)
				goto out;
		}
	}

	params[1].value.a = idx >> 32;
	params[1].value.b = idx;
out:
	TEE_CloseObject(h);
	return res;
}

static TEE_Result write_rb_idx(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	size_t slot_offset;
	uint64_t widx;
	uint64_t idx;
	uint32_t count;
	TEE_Result res;
	TEE_ObjectHandle h;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_slot_offset(params[0].value.a, &slot_offset);
	if (res)
		return res;
	widx = ((uint64_t)params[1].value.a << 32) | params[1].value.b;

	res = open_state(DEFAULT_LOCK_STATE, &h);
	if (res)
		return res;

	res = TEE_SeekObjectData(h, slot_offset, TEE_DATA_SEEK_SET);
	if (res)
		goto out;

	res =  TEE_ReadObjectData(h, &idx, sizeof(idx), &count);
	if (res)
		goto out;
	if (count != sizeof(idx))
		idx = 0; /* Not yet written slots are reported as 0 */

	if (widx < idx) {
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	res = TEE_SeekObjectData(h, slot_offset, TEE_DATA_SEEK_SET);
	if (res)
		goto out;

	res = TEE_WriteObjectData(h, &widx, sizeof(widx));
out:
	TEE_CloseObject(h);
	return res;
}

static TEE_Result read_lock_state(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t lock_state;
	uint32_t count;
	TEE_Result res;
	TEE_ObjectHandle h;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = open_state(DEFAULT_LOCK_STATE, &h);
	if (res)
		return res;

	res =  TEE_ReadObjectData(h, &lock_state, sizeof(lock_state), &count);
	if (res)
		goto out;
	if (count != sizeof(lock_state)) {
		/*
		 * Client need write the lock state to recover, this can
		 * normally not happen.
		 */
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}

	params[0].value.a = lock_state;
out:
	TEE_CloseObject(h);
	return res;
}

static TEE_Result write_lock_state(uint32_t pt,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t wlock_state;
	uint32_t lock_state;
	uint32_t count;
	TEE_Result res;
	TEE_ObjectHandle h;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	wlock_state = params[0].value.a;

	res = open_state(wlock_state, &h);
	if (res)
		return res;

	res =  TEE_ReadObjectData(h, &lock_state, sizeof(lock_state), &count);
	if (res)
		goto out;
	if (count == sizeof(lock_state) && lock_state == wlock_state)
		goto out;

	res = create_state(wlock_state, &h);
out:
	TEE_CloseObject(h);
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param params[4] __unused,
				    void **session __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_AVB_CMD_READ_ROLLBACK_INDEX:
		return read_rb_idx(pt, params);
	case TA_AVB_CMD_WRITE_ROLLBACK_INDEX:
		return write_rb_idx(pt, params);
	case TA_AVB_CMD_READ_LOCK_STATE:
		return read_lock_state(pt, params);
	case TA_AVB_CMD_WRITE_LOCK_STATE:
		return write_lock_state(pt, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
