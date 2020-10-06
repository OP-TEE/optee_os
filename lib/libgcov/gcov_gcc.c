/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#include <gcov.h>
#include <tee_api_types.h>
#include <string.h>
#include <malloc.h>
#include <compiler.h>
#include <trace.h>

#include "int_gcov.h"

#define MAGIC_VALUE(c1, c2, c3, c4) \
	(((uint32_t)c1 << 24) + ((uint32_t)c2 << 16) + ((uint32_t)c3 << 8) + \
	 (uint32_t)c4)

#define GCDA_MAGIC MAGIC_VALUE('g', 'c', 'd', 'a')

#define TAG_FUNCTION	    0x01000000
#define TAG_FUNCTION_LENGTH 3

#define GCC_VERSION_5  50000
#define GCC_VERSION_7  70000
#define GCC_VERSION_10 100000

/* The numbers of counters defined by GCC changes through time */
#if __GCC_VERSION < GCC_VERSION_5
#define NB_COUNTERS 0
#elif GCC_VERSION_5 <= __GCC_VERSION && __GCC_VERSION < GCC_VERSION_5
/* c77556a5d1e225024a4f9dafe5a1a6c316a86b83 basepoints/gcc-5-1775-gc77556a */
#define NB_COUNTERS 9
#elif GCC_VERSION_5 <= __GCC_VERSION && __GCC_VERSION < GCC_VERSION_7
/* afe0c5ee91ab504daf13f1c07ee5559b2ba5b6e4 basepoints/gcc-5-3943-gafe0c5e */
#define NB_COUNTERS 10
#elif GCC_VERSION_7 <= __GCC_VERSION && __GCC_VERSION < GCC_VERSION_10
/* 56b653f1a37372ceaba9ec6cbfc44ce09153c259 basepoints/gcc-7-3351-g56b653f */
#define NB_COUNTERS 9
#elif GCC_VERSION_10 <= __GCC_VERSION
/* e37333bad7b7df7fd9d2e5165f61c2a68b57a30d basepoints/gcc-10-929-ge37333b */
#define NB_COUNTERS 8
#endif

enum { CTR_ARCS = 0,
       CTR_V_INTERVAL,
       CTR_V_POW2,
       CTR_V_TOPN,
       CTR_V_INDIR,
       CTR_AVERAGE,
       CTR_IOR,
       TIME_PROFILER,
       START_CTR_SUPPORTED = CTR_ARCS,
       LAST_CTR_SUPPORTED = CTR_ARCS + 1,
};

static const uint32_t ctr_tags[LAST_CTR_SUPPORTED] = {
	[CTR_ARCS] = 0x01a10000,
};

/*
 * Structure create by gcc to hold code coverade data of an object
 *
 * __gcov_ctr_info (func gcc/gcc/coverage.c:build_fn_info_type):
 *   ctr_info::num: unsigned
 *   ctr_info::values: <int size> *
 *
 * __gcov_fn_info (func build_fn_info_type):
 *   key: const __gcov_info *
 *   ident: unsigned
 *   lineno_checksum: unsigned
 *   cfg checksum: unsigned
 *   counters: __gcov_ctr_info[number_of_gcov_counters_in_the_fn - 1]
 */
struct func_data {
	/* Pointer to object containing the function */
	const struct object_data *object;
	/* Identifier */
	uint32_t id;
	/* Checksum of the line */
	uint32_t line_chksum;
	/* Checksum of the configuration */
	uint32_t cfg_chksum;
	/* Array of counters data for each type of counter */
	struct ctr_data {
		/* Number of counters of the type */
		uint32_t nb_ctrs;
		/* Array of counters value */
		uint64_t *ctrs;
	} ctrs_data[];
};

typedef void (*merge_fn)(uint64_t *ctrs, uint32_t nb_ctrs);

/*
 * Structure create by gcc to hold code coverade data of an object
 *
 * __gcov_info (func gcc/gcc/coverage.c:build_fn_info):
 *   Version ident: unsigned
 *   next pointer: const __gcov_info *
 *   stamp: unsigned
 *   Filename: const char *
 *   merge fn array: void(*)(<int size>, unsigned)[number of gcov counters]
 *   n_functions: unsigned
 *   function_info pointer pointer: const
 */
struct object_data {
	/* version of gcc */
	uint32_t version;
	/* pointer for a liked list */
	struct object_data *next;
	/* Date of creation */
	uint32_t timestamp;
	/* Name of the object */
	const char *objectname;
	/* Functions to merge the counters */
	void (*merge_fn[NB_COUNTERS])(uint64_t *ctrs, uint32_t nb_ctrs);
	/* Number of functions in the object */
	uint32_t nb_functions;
	/* Array of pointers on function data */
	const struct func_data **arr_func_data;
};

/* Structure to hold data for the library */
static struct internal_data {
	/* Version of gcc */
	uint32_t gcc_version;
	/* Size of dump buffer, store the biggest size required */
	uint32_t dump_buf_size;
	/* Buffer to dump */
	void *dump_buf;
	/* List of all the objects covered */
	struct object_data *linked_list_objects;
	/* If a dry run is required */
	bool dry_run_done;
} s_int_data;

/*
 * See gcov_impl_t->get_version
 */
static uint32_t gcov_gcc_get_version(void)
{
	return s_int_data.gcc_version;
}

/*
 * See gcov_impl_t->init
 */
static void gcov_gcc_init(void *cov_object_info)
{
	struct object_data *od = cov_object_info;

	/* The objects are inserted in LIFO */
	if (!s_int_data.linked_list_objects) {
		s_int_data.linked_list_objects = od;
	} else {
		od->next = s_int_data.linked_list_objects;
		s_int_data.linked_list_objects = od;
	}

	if (!s_int_data.gcc_version)
		s_int_data.gcc_version = od->version;
}

/*
 * See gcov_impl_t->merge_add
 */
static void gcov_gcc_merge_add(void *ctrs, uint32_t nb_ctrs)
{
	(void)ctrs;
	(void)nb_ctrs;
}

static void gcov_gcc_exit(void)
{
	/* empty */
}

/*
 * See gcov_impl_t->reset_all_coverage_data
 */
static TEE_Result gcov_gcc_reset_all_coverage_data(void)
{
	struct object_data *od = s_int_data.linked_list_objects;
	const struct func_data *fd = NULL;
	const struct ctr_data *cd = NULL;
	uint32_t cur_fn = 0;
	uint32_t cur_ctr = 0;

	/* No object registered */
	if (!od)
		return TEE_SUCCESS;

	/* We loop over the object data */
	do {
		/* We loop over the function data */
		for (cur_fn = 0; cur_fn < od->nb_functions; cur_fn++) {
			fd = od->arr_func_data[cur_fn];

			/* We loop over the type of counters */
			for (cur_ctr = START_CTR_SUPPORTED;
			     cur_ctr <= LAST_CTR_SUPPORTED; cur_ctr++) {
				cd = &fd->ctrs_data[cur_ctr];

				/* We reset the enabled counters */
				if (od->merge_fn[cur_ctr])
					memset(cd->ctrs, 0,
					       sizeof(*cd->ctrs) * cd->nb_ctrs);
			}
		}
	} while ((od = od->next));

	return TEE_SUCCESS;
}

/*
 * See gcov_impl_t->start_dump_all_coverage_data
 */
static TEE_Result gcov_gcc_start_dump_all_coverage_data(void)
{
	/* Reuse the biggest buffer size if any */
	uint32_t buf_size = s_int_data.dump_buf_size;

	s_int_data.dump_buf = malloc(buf_size);
	if (!s_int_data.dump_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	s_int_data.dump_buf_size = buf_size;

	return TEE_SUCCESS;
}

/*
 * We will always be aligned on a word
 */
#define write_u32(buf, val, dry_run) \
	({ \
		if (!dry_run) { \
			*((uint32_t *)buf) = val; \
			buf = ((uint8_t *)buf) + sizeof(uint32_t); \
		} \
		(sizeof(uint32_t)); \
	})

/*
 * We are not always aligned on a word boundary else the use of memmove
 */
#define write_u64(buf, val, dry_run) \
	({ \
		if (!dry_run) { \
			uint64_t v = val; \
			memmove(buf, &v, sizeof(uint64_t)); \
			buf = ((uint8_t *)buf) + sizeof(uint64_t); \
		} \
		(sizeof(uint64_t)); \
	})

/*
 * Create a GCDA file in the buffer provided
 *
 * If the size of the buffer is zero, it returns the size required
 *
 * From gcc/gcc/gcov-dump.c
 *
 * A FUNCTION block is generally foloowed by blocks for counters, 1 bloc per
 * counter
 *
 * struct gcda_file {
 *     uint32_t magic;
 *     uint32_t version;
 *     uint32_t stamp;
 *
 *     struct {
 *         uint32_t tag;
 *         uint32_t len;
 *         union {
 *             {
 *                 uint32_t ident;
 *                 uint32_t lineno_checksum;
 *                 uint32_t cfg_checksum;
 *             } gcda_functions;
 *             {
 *                 uint64_t values;
 *             } gcda_counters;
 *         } *gcda_block;
 *     } gcda_data;
 * };
 */
static uint32_t gcov_gcc_create_gcda(const struct object_data *od, void *buffer)
{
	const struct func_data *fd = NULL;
	const struct ctr_data *cd = NULL;
	uint32_t cur_fn = 0;
	uint32_t cur_ctr = 0;
	bool dry_run = false;
	uint32_t size = 0;
	uint32_t ctr_size = 0;
	uint32_t i = 0;
	void *buf = buffer;

	if (!buffer)
		dry_run = true;

	/* Write file header */
	size += write_u32(buf, GCDA_MAGIC, dry_run);
	size += write_u32(buf, s_int_data.gcc_version, dry_run);
	size += write_u32(buf, od->timestamp, dry_run);

	/* We loop over the function data */
	for (cur_fn = 0; cur_fn < od->nb_functions; cur_fn++) {
		fd = od->arr_func_data[cur_fn];

		size += write_u32(buf, TAG_FUNCTION, dry_run);
		size += write_u32(buf, TAG_FUNCTION_LENGTH, dry_run);

		size += write_u32(buf, fd->id, dry_run);
		size += write_u32(buf, fd->line_chksum, dry_run);
		size += write_u32(buf, fd->cfg_chksum, dry_run);

		/* We loop over the type of counters */
		for (cur_ctr = START_CTR_SUPPORTED;
		     cur_ctr <= LAST_CTR_SUPPORTED; cur_ctr++) {
			cd = &fd->ctrs_data[cur_ctr];
			ctr_size = cd->nb_ctrs * 2;

			/* Pass to next type if no merge function */
			if (!od->merge_fn[cur_ctr])
				continue;

			size += write_u32(buf, ctr_tags[cur_ctr], dry_run);
			size += write_u32(buf, ctr_size, dry_run);

			/* Loop over counter values */
			for (i = 0; i < cd->nb_ctrs; i++)
				size += write_u64(buf, cd->ctrs[i], dry_run);
		}
	}

	return size;
}

/*
 * See gcov_impl_t->dump_all_coverage_data
 */
static TEE_Result gcov_gcc_dump_all_coverage_data(gcov_dump_file_fn dump_fn,
						  const char *desc)
{
	TEE_Result res = TEE_SUCCESS;
	struct object_data *od = s_int_data.linked_list_objects;
	bool dry_run = !s_int_data.dry_run_done;
	uint32_t size_required = 0;
	uint32_t size_written = 0;
	void **buf = &s_int_data.dump_buf;

	/* No object registered */
	if (!od)
		return res;

	/* We loop over the object data */
	do {
		/* Do a dry run */
		if (dry_run) {
			size_required = gcov_gcc_create_gcda(od, NULL);

			/* Check if we need to reallocate the buffer */
			if (size_required > s_int_data.dump_buf_size) {
				*buf = realloc(*buf, size_required);
				if (!s_int_data.dump_buf)
					return TEE_ERROR_OUT_OF_MEMORY;

				s_int_data.dump_buf_size = size_required;
			}
		}

		/* Create the gcda file in buffer */
		size_written = gcov_gcc_create_gcda(od, *buf);

		/* write the file */
		res = dump_fn(desc, od->objectname, *buf, size_written);

	} while ((od = od->next));

	s_int_data.dry_run_done = true;

	return TEE_SUCCESS;
}

/*
 * See gcov_impl_t->end_dump_all_coverage_data
 */
static void gcov_gcc_end_dump_all_coverage_data(void)
{
	/* We keep the size of buffer used from this dump */
	free(s_int_data.dump_buf);
}

/*
 * Implementation of gcov for GCC
 */
const struct gcov_impl_t gcov_gcc = {
	.get_version = gcov_gcc_get_version,
	.init = gcov_gcc_init,
	.exit = gcov_gcc_exit,
	.merge_add = gcov_gcc_merge_add,
	.reset_all_coverage_data = gcov_gcc_reset_all_coverage_data,
	.start_dump_all_coverage_data = gcov_gcc_start_dump_all_coverage_data,
	.dump_all_coverage_data = gcov_gcc_dump_all_coverage_data,
	.end_dump_all_coverage_data = gcov_gcc_end_dump_all_coverage_data,
};

REGISTR_GCOV_IMPL(&gcov_gcc);
