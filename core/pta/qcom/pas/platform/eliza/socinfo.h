/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _SOCINFO_H_
#define _SOCINFO_H_

#include <stdint.h>
#include <tee_api_types.h>

struct qcom_socinfo {
	uint32_t id;
	uint32_t version;
	uint32_t platform;
	uint32_t platform_version;
	uint32_t platform_subtype;
};

/* Read the chip and platform identity XBL publishes in SMEM */
TEE_Result qcom_socinfo_read(struct qcom_socinfo *info);

#endif /* _SOCINFO_H_ */
