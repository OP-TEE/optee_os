// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <ta_avb.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <string.h>
#include <util.h>

#define DEFAULT_LOCK_STATE	0

static const uint32_t storageid = TEE_STORAGE_PRIVATE_RPMB;
static const char rb_obj_name[] = "rb_state";
static const char *named_value_prefix = "named_value_";

static TEE_Result get_slot_offset(size_t slot, size_t *offset)
{
	if (slot >= TA_AVB_MAX_ROLLBACK_LOCATIONS)
		return TEE_ERROR_BAD_PARAMETERS;

	*offset = sizeof(uint32_t) /* lock_state */ + slot * sizeof(uint64_t);
	return TEE_SUCCESS;
}

static TEE_Result create_rb_state(uint32_t lock_state, TEE_ObjectHandle *h)
{
	const uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			       TEE_DATA_FLAG_ACCESS_WRITE |
			       TEE_DATA_FLAG_OVERWRITE;

	return TEE_CreatePersistentObject(storageid, rb_obj_name,
					  sizeof(rb_obj_name), flags, NULL,
					  &lock_state, sizeof(lock_state), h);
}

static TEE_Result open_rb_state(uint32_t default_lock_state,
				TEE_ObjectHandle *h)
{
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE;
	TEE_Result res;

	res = TEE_OpenPersistentObject(storageid, rb_obj_name,
				       sizeof(rb_obj_name), flags, h);
	if (!res)
		return TEE_SUCCESS;

	return create_rb_state(default_lock_state, h);
}

static TEE_Result get_named_object_name(char *name_orig,
					uint32_t name_orig_size,
					char *name, uint32_t *name_size)
{
	size_t pref_len = strlen(named_value_prefix);

	if (name_orig_size + pref_len >
	    TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Start with prefix */
	TEE_MemMove(name, named_value_prefix, pref_len);

	/* Concatenate provided object name */
	TEE_MemMove(name + pref_len, name_orig, name_orig_size);

	*name_size = name_orig_size + pref_len;

	return TEE_SUCCESS;
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

	res = open_rb_state(DEFAULT_LOCK_STATE, &h);
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

	res = open_rb_state(DEFAULT_LOCK_STATE, &h);
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

	res = open_rb_state(DEFAULT_LOCK_STATE, &h);
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

	res = open_rb_state(wlock_state, &h);
	if (res)
		return res;

	res =  TEE_ReadObjectData(h, &lock_state, sizeof(lock_state), &count);
	if (res)
		goto out;
	if (count == sizeof(lock_state) && lock_state == wlock_state)
		goto out;

	res = create_rb_state(wlock_state, &h);
out:
	TEE_CloseObject(h);
	return res;
}

static TEE_Result write_persist_value(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	const uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			       TEE_DATA_FLAG_ACCESS_WRITE |
			       TEE_DATA_FLAG_OVERWRITE;
	char name_full[TEE_OBJECT_ID_MAX_LEN] = { };
	TEE_ObjectHandle h = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t name_full_sz = 0;
	uint32_t name_buf_sz = 0;
	uint32_t value_sz = 0;
	char *name_buf = NULL;
	char *value = NULL;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	name_buf = params[0].memref.buffer;
	name_buf_sz = params[0].memref.size;
	value_sz = params[1].memref.size;
	value = TEE_Malloc(value_sz, 0);
	if (!value)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(value, params[1].memref.buffer, value_sz);

	res = get_named_object_name(name_buf, name_buf_sz,
				    name_full, &name_full_sz);
	if (res)
		goto out;

	res = TEE_CreatePersistentObject(storageid, name_full,
					 name_full_sz,
					 flags, NULL, value,
					 value_sz, &h);
	if (res)
		EMSG("Can't create named object value, res = 0x%x", res);

	TEE_CloseObject(h);
out:
	TEE_Free(value);

	return res;
}

static TEE_Result read_persist_value(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE;
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle h = TEE_HANDLE_NULL;
	char name_full[TEE_OBJECT_ID_MAX_LEN];
	uint32_t name_full_sz = 0;
	uint32_t name_buf_sz = 0;
	char *name_buf = NULL;
	uint32_t value_sz = 0;
	char *value = NULL;
	uint32_t count = 0;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	name_buf = params[0].memref.buffer;
	name_buf_sz = params[0].memref.size;
	value_sz = params[1].memref.size;
	value = TEE_Malloc(value_sz, 0);
	if (!value)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = get_named_object_name(name_buf, name_buf_sz,
				    name_full, &name_full_sz);
	if (res)
		goto out_free;

	res = TEE_OpenPersistentObject(storageid, name_full,
				       name_full_sz, flags, &h);
	if (res) {
		EMSG("Can't open named object value, res = 0x%x", res);
		goto out_free;
	}

	res =  TEE_ReadObjectData(h, value, value_sz, &count);
	if (res) {
		EMSG("Can't read named object value, res = 0x%x", res);
		goto out;
	}

	TEE_MemMove(params[1].memref.buffer, value,
		    value_sz);

	params[1].memref.size = count;
out:
	TEE_CloseObject(h);
out_free:
	TEE_Free(value);

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
	case TA_AVB_CMD_READ_PERSIST_VALUE:
		return read_persist_value(pt, params);
	case TA_AVB_CMD_WRITE_PERSIST_VALUE:
		return write_persist_value(pt, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
