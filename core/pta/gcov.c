/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#include <gcov.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <pta_gcov.h>

/*
 * Name of the TA
 */
#define TA_NAME "gcov.pta"

/*
 * Proxy function which calls gcov_get_version()
 *
 * @ptypes  The ptypes
 * @params  The parameters
 *          [out]    value[0].a	    version of gcov
 *          [none]
 *          [none]
 *          [none]
 */
static TEE_Result pta_gcov_get_version(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes) {
		EMSG("Wrong param_types, exp %x, got %x", exp_ptypes, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return gcov_get_version(&params[0].value.a);
}

/*
 * Proxy function which calls gcov_reset_coverage_data()
 *
 * @ptypes  The ptypes
 * @params  The parameters
 *          [none]
 *          [none]
 *          [none]
 *          [none]
 */
static TEE_Result pta_gcov_core_reset(uint32_t ptypes,
				      __unused TEE_Param params[4])
{
	uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes) {
		EMSG("Wrong param_types, exp %x, got %x", exp_ptypes, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return gcov_reset_coverage_data();
}

/*
 * Proxy function which calls gcov_dump_coverage_data()
 *
 * @ptypes  The ptypes
 * @params  The parameters
 *          [in]     memref[0]	    filepath
 *          [in]     memref[1]	    code coverage data
 *          [none]
 *          [none]
 */
static TEE_Result pta_gcov_dump(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					      TEE_PARAM_TYPE_MEMREF_INPUT,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes) {
		EMSG("Wrong param_types, exp %x, got %x", exp_ptypes, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Dump the data */
	return gcov_dump_coverage_data(params[0].memref.buffer,
				       params[1].memref.buffer,
				       params[1].memref.size);
}

/*
 * Proxy function which calls gcov_dump_coverage_data()
 *
 * @ptypes  The ptypes
 * @params  The parameters
 *          [in]     memref[0]	    description
 *          [none]
 *          [none]
 *          [none]
 */
static TEE_Result pta_gcov_core_dump_all(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE,
					      TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes) {
		EMSG("Wrong param_types, exp %x, got %x", exp_ptypes, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Dump the data */
	return gcov_dump_all_coverage_data(params[0].memref.buffer);
}

/*
 * @Handler function upon invocation of a command of the TA
 *
 * @psess   The Session
 * @cmd     The command to execute
 * @ptypes  The types of the parameters
 * @params  The parameters
 */
static TEE_Result invoke_command(void *psess __unused, uint32_t cmd,
				 uint32_t ptypes, TEE_Param params[4])
{
	switch (cmd) {
	case PTA_CMD_GCOV_GET_VERSION:
		return pta_gcov_get_version(ptypes, params);
	case PTA_CMD_GCOV_CORE_RESET:
		return pta_gcov_core_reset(ptypes, params);
	case PTA_CMD_GCOV_DUMP:
		return pta_gcov_dump(ptypes, params);
	case PTA_CMD_GCOV_CORE_DUMP_ALL:
		return pta_gcov_core_dump_all(ptypes, params);
	default:
		EMSG("Command %d not supported", cmd);
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/*
 * Register the PTA gcov with appropriate handler functions
 */
pseudo_ta_register(.uuid = PTA_GCOV_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
