/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_IRIS_H
#define PAS_IRIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types_ext.h>

#include "pas_subsys.h"

/*
 * struct pas_iris_seed : seed segment of the video firmware image being
 * loaded, see pas_iris.c.
 *
 * @valid:  set at PTA_QCOM_PAS_INIT_IMAGE for the image being loaded
 * @offset: offset of the seed from the start of the firmware region
 * @size:   size of the seed, 0 when the image has none
 */
struct pas_iris_seed {
	bool valid;
	uint64_t offset;
	size_t size;
};

/*
 * struct pas_iris_data : subsystem_data of an iris subsystem.
 *
 * @seed: seed of the image being loaded
 */
struct pas_iris_data {
	struct pas_iris_seed seed;
};

/*
 * Helpers for the iris firmware operations of each SoC. The registers are
 * mapped from the struct qcom_pas_data base (IRIS_BASE) and subsystem_data
 * points to the struct pas_iris_data of the subsystem; @base is IRIS_BASE
 * mapped.
 */

/* fw_init_image operation: find the seed of the image being loaded */
TEE_Result pas_iris_init_image(struct qcom_pas_data *data,
			       const struct pas_metadata *metadata,
			       const struct elf_info *e_info);

/* Fail unless the loaded firmware fits below the CP non-pixel window */
TEE_Result pas_iris_check_fw_size(struct qcom_pas_data *data);

/* At start, fill the seed of the loaded image; checks the firmware size */
TEE_Result pas_iris_fill_seed(struct qcom_pas_data *data);

/*
 * Program the CP layout for a firmware of @fw_size bytes, which must have
 * passed pas_iris_check_fw_size()
 */
void pas_iris_set_cp_layout(vaddr_t base, size_t fw_size);

/* Take the core out of reset */
void pas_iris_release_core(vaddr_t base);

/* fw_shutdown operation: hold the core in reset */
TEE_Result pas_iris_fw_shutdown(struct qcom_pas_data *data);

#endif /* PAS_IRIS_H */
