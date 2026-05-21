/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _Q6DSP_H_
#define _Q6DSP_H_

#include "pas_data.h"

TEE_Result wpss_fw_start(struct qcom_pas_data *data);
TEE_Result wpss_fw_shutdown(struct qcom_pas_data *data);

#endif /* _Q6DSP_H_ */
