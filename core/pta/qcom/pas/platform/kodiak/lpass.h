/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _LPASS_H_
#define _LPASS_H_

#include "pas_data.h"

TEE_Result lpass_fw_start(struct qcom_pas_data *data);
TEE_Result lpass_fw_shutdown(struct qcom_pas_data *data);

#endif /* _LPASS_H_ */
