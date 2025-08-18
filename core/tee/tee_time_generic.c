// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#define TA_TIME_OFFS_ID "ta_time_offs"

#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>
#include <utee_defines.h>

struct tee_ta_time_offs {
	TEE_UUID uuid;
	TEE_Time offs;
	bool positive;
};

static struct tee_ta_time_offs *tee_time_offs;
static size_t tee_time_num_offs;
static struct mutex tee_time_mtx = MUTEX_INITIALIZER;

static TEE_Result tee_time_ta_set_offs_mem(const TEE_UUID *uuid,
					   const TEE_Time *offs,
					   bool positive, size_t *out_idx)
{
	size_t n = 0;
	struct tee_ta_time_offs *o = NULL;

	mutex_lock(&tee_time_mtx);
	for (n = 0; n < tee_time_num_offs; n++) {
		if (memcmp(uuid, &tee_time_offs[n].uuid,
			   sizeof(TEE_UUID)) == 0) {
			tee_time_offs[n].offs = *offs;
			tee_time_offs[n].positive = positive;
			if (out_idx)
				*out_idx = n;
			mutex_unlock(&tee_time_mtx);
			return TEE_SUCCESS;
		}
	}

	n = tee_time_num_offs + 1;
	o = realloc(tee_time_offs, n * sizeof(struct tee_ta_time_offs));
	if (!o) {
		mutex_unlock(&tee_time_mtx);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	tee_time_offs = o;
	tee_time_offs[tee_time_num_offs].uuid = *uuid;
	tee_time_offs[tee_time_num_offs].offs = *offs;
	tee_time_offs[tee_time_num_offs].positive = positive;
	tee_time_num_offs = n;
	if (out_idx)
		*out_idx = n - 1;
	mutex_unlock(&tee_time_mtx);
	return TEE_SUCCESS;
}

static TEE_Result tee_time_ta_storage_write(const TEE_UUID *uuid,
					    const TEE_Time *offs, bool positive)
{
	const struct tee_file_operations *fops =
		tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	struct tee_file_handle *fh = NULL;
	struct tee_pobj *po = NULL;
	struct tee_ta_time_offs o = { };
	TEE_Result res = TEE_SUCCESS;

	if (!fops)
		return TEE_ERROR_NOT_SUPPORTED;

	res = tee_pobj_get((TEE_UUID *)uuid, (void *)TA_TIME_OFFS_ID,
			   sizeof(TA_TIME_OFFS_ID) - 1,
			   TEE_DATA_FLAG_ACCESS_WRITE,
			   TEE_POBJ_USAGE_CREATE, fops, &po);

	if (res)
		return res;

	o.uuid = *uuid;
	o.offs = *offs;
	o.positive = positive;

	res = fops->create(po, true, NULL, 0, NULL, 0, &o, NULL, sizeof(o),
		&fh);

	if (!res) {
		fops->close(&fh);
		tee_pobj_create_final(po);
	}
	tee_pobj_release(po);
	return res;
}

static TEE_Result tee_time_ta_storage_read(const TEE_UUID *uuid,
					   TEE_Time *offs, bool *positive)
{
	const struct tee_file_operations *fops =
		tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
	struct tee_file_handle *fh = NULL;
	struct tee_pobj *po = NULL;
	TEE_Result res = TEE_SUCCESS;
	size_t sz = 0;
	struct tee_ta_time_offs o = { };

	if (!fops)
		return TEE_ERROR_TIME_NOT_SET;

	res = tee_pobj_get((TEE_UUID *)uuid, (void *)TA_TIME_OFFS_ID,
			   sizeof(TA_TIME_OFFS_ID) - 1,
			   TEE_DATA_FLAG_ACCESS_READ, TEE_POBJ_USAGE_OPEN,
			   fops, &po);

	if (res) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return TEE_ERROR_TIME_NOT_SET;
		return res;
	}

	res = fops->open(po, &sz, &fh);
	if (!res) {
		sz = sizeof(o);
		res = fops->read(fh, 0, &o, NULL, &sz);
		fops->close(&fh);
	}

	tee_pobj_release(po);

	if (res) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return TEE_ERROR_TIME_NOT_SET;
		return res;
	}

	if (sz != sizeof(o))
		return TEE_ERROR_TIME_NOT_SET;

	*offs = o.offs;
	*positive = o.positive;
	return TEE_SUCCESS;
}

static TEE_Result tee_time_ta_get_offs(const TEE_UUID *uuid,
				       const TEE_Time **offs, bool *positive)
{
	size_t n = 0;
	TEE_Time o;
	bool pos = false;
	size_t idx = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	mutex_lock(&tee_time_mtx);
	for (n = 0; n < tee_time_num_offs; n++) {
		if (memcmp(uuid, &tee_time_offs[n].uuid, sizeof(TEE_UUID))
				== 0) {
			*offs = &tee_time_offs[n].offs;
			*positive = tee_time_offs[n].positive;
			mutex_unlock(&tee_time_mtx);
			return TEE_SUCCESS;
		}
	}

	mutex_unlock(&tee_time_mtx);
	res = tee_time_ta_storage_read(uuid, &o, &pos);

	if (res)
		return res;

	res = tee_time_ta_set_offs_mem(uuid, &o, pos, &idx);
	if (res)
		return res;

	mutex_lock(&tee_time_mtx);
	*offs = &tee_time_offs[idx].offs;
	*positive = tee_time_offs[idx].positive;
	mutex_unlock(&tee_time_mtx);

	return TEE_SUCCESS;
}

static TEE_Result tee_time_ta_set_offs(const TEE_UUID *uuid,
				       const TEE_Time *offs, bool positive)
{
	size_t idx = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tee_time_ta_set_offs_mem(uuid, offs, positive, &idx);
	if (res)
		return res;
	return tee_time_ta_storage_write(uuid, offs, positive);
}

TEE_Result tee_time_get_ta_time(const TEE_UUID *uuid, TEE_Time *time)
{
	TEE_Result res;
	const TEE_Time *offs;
	bool positive;
	TEE_Time t;
	TEE_Time t2;

	res = tee_time_ta_get_offs(uuid, &offs, &positive);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_time_get_sys_time(&t);
	if (res != TEE_SUCCESS)
		return res;

	if (positive) {
		TEE_TIME_ADD(t, *offs, t2);

		/* Detect wrapping, the wrapped time should be returned. */
		if (TEE_TIME_LT(t2, t))
			res = TEE_ERROR_OVERFLOW;
	} else {
		TEE_TIME_SUB(t, *offs, t2);

		/* Detect wrapping, the wrapped time should be returned. */
		if (TEE_TIME_LE(t, t2))
			res = TEE_ERROR_OVERFLOW;
	}
	*time = t2;

	return res;
}

TEE_Result tee_time_set_ta_time(const TEE_UUID *uuid, const TEE_Time *time)
{
	TEE_Result res;
	TEE_Time offs;
	TEE_Time t;

	/* Check that time is normalized. */
	if (time->millis >= TEE_TIME_MILLIS_BASE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_time_get_sys_time(&t);
	if (res != TEE_SUCCESS)
		return res;

	if (TEE_TIME_LT(t, *time)) {
		TEE_TIME_SUB(*time, t, offs);
		return tee_time_ta_set_offs(uuid, &offs, true);
	} else {
		TEE_TIME_SUB(t, *time, offs);
		return tee_time_ta_set_offs(uuid, &offs, false);
	}
}

void tee_time_busy_wait(uint32_t milliseconds_delay)
{
	TEE_Time curr;
	TEE_Time delta;
	TEE_Time end;

	if (tee_time_get_sys_time(&curr) != TEE_SUCCESS)
		panic();
	delta.seconds = milliseconds_delay / 1000;
	delta.millis = milliseconds_delay % 1000;
	TEE_TIME_ADD(curr, delta, end);

	while (TEE_TIME_LT(curr, end))
		if (tee_time_get_sys_time(&curr) != TEE_SUCCESS)
			panic();
}
