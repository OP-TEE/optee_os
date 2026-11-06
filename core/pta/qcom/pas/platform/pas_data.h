/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _PAS_DATA_H_
#define _PAS_DATA_H_

#include <drivers/clk_qcom.h>
#include <mm/core_memprot.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * struct pas_video_seed : seed segment of a video firmware image, see
 * pas_video.h.
 *
 * @valid:  set by pas_video_find_seed() for the image being loaded
 * @offset: offset of the seed from the start of the firmware region
 * @size:   size of the seed, 0 when the image has none
 */
struct pas_video_seed {
	bool valid;
	uint64_t offset;
	size_t size;
};

struct pas_iris_cfg;

struct qcom_pas_data {
	uint32_t pas_id;
	/* 0-terminated list of PAS_IDs this must load after, or NULL. */
	const uint32_t *depends_on;
	struct io_pa_va base;
	size_t size;
	paddr_t fw_base;
	size_t fw_size;
	/* Set once fw_start() succeeds; cleared once fw_shutdown() succeeds. */
	bool loaded;
	bool relocatable;
	enum qcom_clk_group clk_group;
	/* Memtype for the controller window: NSEC, or SEC if XPU-gated. */
	enum teecore_memtypes map_type;
	/* Video firmware seed of the image being loaded */
	struct pas_video_seed seed;
	/* Iris platform settings, see pas_iris.h */
	const struct pas_iris_cfg *iris;
};

#endif /* _PAS_DATA_H_ */
