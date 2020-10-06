/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef GCOV_H
#define GCOV_H

#include <tee_api_types.h>

/*
 * Print debug information about the gcov support
 *
 * @version  The version of the implementation
 */
TEE_Result gcov_get_version(uint32_t *version);

/*
 * Reset all the coverage data
 */
TEE_Result gcov_reset_coverage_data(void);

/*
 * Write the coverage data to filesystem in the file filepath
 *
 * @filepath      Path of the file to write
 * @cov_data      Coverage data to write
 * @cov_data_size Coverage data size
 */
typedef TEE_Result (*gcov_dump_writer)(const char *filepath, char *cov_data,
				       uint32_t cov_data_size);

TEE_Result register_gcov_dump_writer(gcov_dump_writer writer_fn);

/*
 * Dump coverage data to REE FS
 *
 * @filepath       Path of the coverage file
 * @cov_data       The coverage data to dump
 * @cov_data_size  Size of the coverage data
 */
TEE_Result gcov_dump_coverage_data(const char *filepath, char *cov_data,
				   uint32_t cov_data_size);

/*
 * Dump the current state of the coverage data to filesystem
 *
 * @desc  Description for storage, null terminated string
 */
TEE_Result gcov_dump_all_coverage_data(const char *desc);

#endif /* GCOV_H */
