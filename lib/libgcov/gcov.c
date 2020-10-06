/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#include <string.h>
#include <trace.h>

#include <gcov.h>

#include "int_gcov.h"

static gcov_dump_writer s_writer_fn;

static bool isnullterm(const char *string, size_t maxlen, size_t *len)
{
	size_t s_len = strnlen(string, maxlen);

	if (s_len == maxlen)
		return false;

	if (len)
		*len = s_len;

	return true;
}

void __gcov_init(void *cov_unit_info)
{
	if (!g_gcov_impl || !g_gcov_impl->init)
		EMSG("No implementation");
	else
		g_gcov_impl->init(cov_unit_info);
}

void __gcov_merge_add(void *ctrs, uint32_t nb_ctrs)
{
	if (!g_gcov_impl || !g_gcov_impl->merge_add)
		EMSG("No implementation");
	else
		g_gcov_impl->merge_add(ctrs, nb_ctrs);
}

void __gcov_exit(void)
{
	if (!g_gcov_impl || !g_gcov_impl->exit)
		EMSG("No implementation");
	else
		g_gcov_impl->exit();
}

TEE_Result gcov_get_version(uint32_t *version)
{
	/* We test if the implementation has implementeed the function */
	if (!g_gcov_impl || !g_gcov_impl->get_version) {
		EMSG("No implementation");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (version)
		*version = g_gcov_impl->get_version();

	return TEE_SUCCESS;
}

TEE_Result gcov_reset_coverage_data(void)
{
	TEE_Result res = TEE_SUCCESS;

	/* We test if the implementation has implementeed the function */
	if (!g_gcov_impl || !g_gcov_impl->reset_all_coverage_data) {
		EMSG("No implementation");
		res = TEE_ERROR_NOT_IMPLEMENTED;
	} else {
		res = g_gcov_impl->reset_all_coverage_data();
	}

	return res;
}

TEE_Result register_gcov_dump_writer(gcov_dump_writer writer_fn)
{
	s_writer_fn = writer_fn;

	return TEE_SUCCESS;
}

TEE_Result gcov_dump_coverage_data(const char *filepath, char *cov_data,
				   uint32_t cov_data_size)
{
	if (!filepath || !cov_data || !cov_data_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!s_writer_fn) {
		EMSG("Writer function not registered");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!isnullterm(filepath, COVERAGE_PATH_MAX, NULL)) {
		EMSG("filepath is not null terminated");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return s_writer_fn(filepath, cov_data, cov_data_size);
}

TEE_Result gcov_dump_all_coverage_data(const char *desc)
{
	TEE_Result res = TEE_SUCCESS;
	const char *slash = "/";

	if (!desc) {
		desc = slash;
	} else if (!isnullterm(desc, COVERAGE_PATH_MAX, NULL)) {
		EMSG("description is not null terminated");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* We test if the implementation has implementeed the function */
	if (!g_gcov_impl || !g_gcov_impl->dump_all_coverage_data ||
	    !g_gcov_dump_fn) {
		EMSG("No implementation");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (g_gcov_impl->start_dump_all_coverage_data) {
		res = g_gcov_impl->start_dump_all_coverage_data();
		if (res) {
			EMSG("Failed to start dump of coverage data");
			return res;
		}
	}

	res = g_gcov_impl->dump_all_coverage_data(g_gcov_dump_fn, desc);

	if (g_gcov_impl->start_dump_all_coverage_data &&
	    g_gcov_impl->end_dump_all_coverage_data)
		g_gcov_impl->end_dump_all_coverage_data();

	return res;
}
