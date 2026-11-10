/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PAS_IRIS_H
#define PAS_IRIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
 * Firmware operations of an iris video codec subsystem, whose registers
 * are mapped from the struct qcom_pas_data base (IRIS_BASE) and whose
 * subsystem_data points to its struct pas_iris_data.
 */
extern const struct qcom_pas_ops pas_iris_ops;

#endif /* PAS_IRIS_H */
