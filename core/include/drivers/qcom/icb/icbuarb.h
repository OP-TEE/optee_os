/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef QTI_ICBUARB_H
#define QTI_ICBUARB_H
#ifdef CFG_QCOM_ICB_RPM
#include "icbuarb_rpm.h"
#else

#include <stdbool.h>
#include <stdint.h>

#include <drivers/qcom/icb/icbid.h>

struct icb_bw_req {
	uint64_t	ab;
	uint64_t	ib;
};

struct icb_client;

struct icb_client *icbuarb_create_client(enum icbid_master master,
					 enum icbid_slave slave);
bool icbuarb_issue_request(struct icb_client *handle, struct icb_bw_req *req);
bool icbuarb_destroy_client(struct icb_client *handle);
#endif
#endif /* QTI_ICBUARB_H */
