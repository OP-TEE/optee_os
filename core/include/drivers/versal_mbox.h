/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Foundries.io Ltd
 */
#ifndef __DRIVERS_VERSAL_MBOX_H
#define __DRIVERS_VERSAL_MBOX_H

#include <platform_config.h>
#include <tee_api_types.h>
#include <util.h>

#define MAX_IPI_BUF 5

struct ipi_buf {
	size_t len;
	void *p;
};

struct ipi_cmd {
	uint32_t data[8];
	struct ipi_buf ibuf[MAX_IPI_BUF];
};

TEE_Result versal_mbox_notify(struct ipi_cmd *cmd, struct ipi_cmd *rsp);

#endif /* __DRIVERS_VERSAL_MBOX_H */
