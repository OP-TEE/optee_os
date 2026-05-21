/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _VIDEO_H_
#define _VIDEO_H_

#include "pas_data.h"

#define IRIS_WRAPPER_TOP_TZ_REG_BASE	0x000c0000
#define IRIS_WRAPPER_TOP_REG_BASE	0x000b0000

TEE_Result venus_fw_start(struct qcom_pas_data *data);
TEE_Result venus_fw_shutdown(struct qcom_pas_data *data);
TEE_Result venus_fw_set_state(struct qcom_pas_data *data, bool power_on);

#endif /* _VIDEO_H_ */
