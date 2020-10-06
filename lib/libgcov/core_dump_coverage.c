/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#include <stdio.h>
#include <string.h>
#include <trace.h>

#include <gcov.h>
#include <optee_rpc_cmd.h>
#include <tee/tee_fs_rpc.h>
#include <tee_api_types.h>

#include "int_gcov.h"

/*
 * Dump coverage data to REE FS
 *
 * The description is prepended to the filepath
 * Sends the coverage data to the writer
 *
 * @desc           Description for storage, null terminated string
 * @filepath       Name of the coverage file
 * @cov_data       The coverage data to dump
 * @cov_data_size  Size of the coverage data
 */
static TEE_Result core_direct_dump_data(const char *desc, const char *filepath,
					void *cov_data, uint32_t cov_data_size)
{
	const char *core = "core/";
	char new_filepath[COVERAGE_PATH_MAX];
	uint32_t filepath_size = 0;

	if (!desc || !filepath || !cov_data) {
		EMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	filepath_size = strlen(core) + strlen(desc) + strlen(filepath) + 1;
	if (filepath_size >= COVERAGE_PATH_MAX) {
		EMSG("Not enough space to store new filepath");
		return TEE_ERROR_SHORT_BUFFER;
	}

	filepath_size = 0;
	strcpy(new_filepath + filepath_size, core);
	filepath_size += strlen(core);

	strcpy(new_filepath + filepath_size, desc);
	filepath_size += strlen(desc);

	strcpy(new_filepath + filepath_size, filepath);
	filepath_size += strlen(filepath);

	filepath_size++;

	return gcov_dump_coverage_data(new_filepath, cov_data, cov_data_size);
}

gcov_dump_file_fn g_gcov_dump_fn = core_direct_dump_data;
