/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef INT_GCOV_H
#define INT_GCOV_H

#include <tee_api_types.h>

/*
 * Maximum size of a coverage path
 */
#define COVERAGE_PATH_MAX 255

/*
 * Initialize the data from a coverage unit
 *
 * @cov_unit_info  The coverage data to initialize
 */
void __gcov_init(void *cov_unit_info);

/*
 * Perform the merge_data operation for @p hProfData
 *
 * @ctrs     List of counters to merge
 * @nb_ctrs  Number of counters to merge
 */
void __gcov_merge_add(void *ctrs, uint32_t nb_ctrs);

/*
 * Coverage processing can be stopped
 */
void __gcov_exit(void);

/*
 * Dump coverage data to REE FS
 *
 * The description is prepended to the filepath
 *
 * @desc           Description for storage, null terminated string
 * @filepath       Name of the coverage file
 * @cov_data       The coverage data to dump
 * @cov_data_size  Size of the coverage data
 */
typedef TEE_Result (*gcov_dump_file_fn)(const char *desc, const char *filepath,
					void *cov_data, uint32_t cov_data_size);

/*
 * static Implementation of dump function to use
 */
extern gcov_dump_file_fn g_gcov_dump_fn;

/*
 * Define the functions an implementation shall provide to process the coverage
 * data
 */
struct gcov_impl_t {
	/*
	 * Get the version of the implementation
	 */
	uint32_t (*get_version)(void);
	/*
	 * Initialize the data of the coverage unit
	 *
	 * @cov_unit_info  The coverage unit info to initialize
	 */
	void (*init)(void *cov_unit_info);

	/*
	 * Perform the merge_data operation for @p hProfData
	 *
	 * @ctrs     List of counters to merge
	 * @nb_ctrs  Number of counters to merge
	 */
	void (*merge_add)(void *ctrs, uint32_t nb_ctrs);

	/*
	 * Coverage processing can be stopped
	 */
	void (*exit)(void);

	/*
	 * Reset all the coverage data
	 */
	TEE_Result (*reset_all_coverage_data)(void);

	/*
	 * Start dump of all the coverage data
	 */
	TEE_Result (*start_dump_all_coverage_data)(void);

	/*
	 * Dump all the coverage data to filesystem
	 *
	 * @dump_fn  The function to call to dump data
	 * @desc     Description for storage, null terminated string
	 */
	TEE_Result (*dump_all_coverage_data)(gcov_dump_file_fn dump_fn,
					     const char *desc);

	/*
	 * End dump of all the coverage data
	 */
	void (*end_dump_all_coverage_data)(void);
};

/*
 * static Implementation of gcov to use
 */
extern const struct gcov_impl_t *g_gcov_impl;

/*
 * Macro to register the implementation of gcov
 */
#define REGISTR_GCOV_IMPL(p_impl) const struct gcov_impl_t *g_gcov_impl = p_impl

#endif /* INT_GCOV_H */
