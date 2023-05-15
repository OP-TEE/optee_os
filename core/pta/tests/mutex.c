// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <atomic.h>
#include <kernel/mutex.h>
#include <pta_invoke_tests.h>
#include <trace.h>

#include "misc.h"

static uint32_t before_lock_readers;
static uint32_t before_lock_writers;
static uint32_t during_lock_readers;
static uint32_t during_lock_writers;

static uint64_t val0;
static uint64_t val1;

struct mutex test_mutex = MUTEX_INITIALIZER;

static TEE_Result mutex_test_writer(TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n;

	params[1].value.a = atomic_inc32(&before_lock_writers);

	mutex_lock(&test_mutex);

	atomic_dec32(&before_lock_writers);

	params[1].value.b = atomic_inc32(&during_lock_writers);

	for (n = 0; n < params[0].value.b; n++) {
		val0++;
		val1++;
		val1++;
	}

	atomic_dec32(&during_lock_writers);
	mutex_unlock(&test_mutex);

	return TEE_SUCCESS;
}

static TEE_Result mutex_test_reader(TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	size_t n;

	params[1].value.a = atomic_inc32(&before_lock_readers);

	mutex_read_lock(&test_mutex);

	atomic_dec32(&before_lock_readers);

	params[1].value.b = atomic_inc32(&during_lock_readers);

	for (n = 0; n < params[0].value.b; n++) {
		if (val0 * 2 != val1)
			res = TEE_ERROR_BAD_STATE;
	}

	atomic_dec32(&during_lock_readers);
	mutex_read_unlock(&test_mutex);

	return res;
}

TEE_Result core_mutex_tests(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("bad parameter types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (params[0].value.a) {
	case PTA_MUTEX_TEST_WRITER:
		return mutex_test_writer(params);
	case PTA_MUTEX_TEST_READER:
		return mutex_test_reader(params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
