/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <string.h>
#include <trace.h>

#include <pta_gcov.h>
#include <tee_api.h>
#include <tee_api_types.h>

#include "int_gcov.h"

/*
 * Dump coverage data to REE FS
 *
 * The description is prepended to the filepath
 * Call the gcov PTA to perform the write of the data
 *
 * @desc           Description for storage, null terminated string
 * @filepath       Name of the coverage file
 * @cov_data       The coverage data to dump
 * @cov_data_size  Size of the coverage data
 */
static TEE_Result ta_direct_dump_data(const char *desc, const char *filepath,
				      void *cov_data, uint32_t cov_data_size)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_TASessionHandle sess = NULL;
	TEE_UUID pta_uuid = PTA_GCOV_UUID;
	uint32_t cRT = TEE_TIMEOUT_INFINITE;
	uint32_t paramTypes = 0;
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };
	uint32_t err_origin = 0;

	char new_filepath[COVERAGE_PATH_MAX] = { 0 };
	uint32_t filepath_size = 0;

	if (!desc || !filepath || !cov_data) {
		EMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Compute total size of new filepath:
	 * <desc>/<filepath>'\0'
	 */
	filepath_size = strlen(desc) + strlen(filepath) + 1;
	if (filepath_size >= COVERAGE_PATH_MAX) {
		EMSG("Not enough space to store new filepath");
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Create new_filepath with '<desc>/<filepath>'\0'' */
	filepath_size = 0;

	strcpy(new_filepath + filepath_size, desc);
	filepath_size += strlen(desc);

	strcpy(new_filepath + filepath_size, filepath);
	filepath_size += strlen(filepath);

	filepath_size++;

	/* Call gcov pta to dump the data */
	res = TEE_OpenTASession(&pta_uuid, cRT, 0, NULL, &sess, &err_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed with code 0x%x origin 0x%x", res,
		     err_origin);
		goto exit;
	}

	paramTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	/* new_filepath */
	params[0].memref.buffer = new_filepath;
	params[0].memref.size = filepath_size;

	/* coverage data */
	params[1].memref.buffer = cov_data;
	params[1].memref.size = cov_data_size;

	res = TEE_InvokeTACommand(sess, cRT, PTA_CMD_GCOV_DUMP, paramTypes,
				  params, &err_origin);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x",
		     res, err_origin);

	TEE_CloseTASession(sess);

exit:
	return res;
}

gcov_dump_file_fn g_gcov_dump_fn = ta_direct_dump_data;
