/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Foundries.io Ltd
 */
#ifndef __DRIVERS_VERSAL_MBOX_H
#define __DRIVERS_VERSAL_MBOX_H

#include <platform_config.h>
#include <tee_api_types.h>
#include <util.h>

#define VERSAL_MAX_IPI_BUF 7

struct versal_mbox_mem {
	size_t alloc_len;
	size_t len;
	void *buf;
};

struct versal_ipi_buf {
	struct versal_mbox_mem mem;
	bool only_cache;
};

struct versal_ipi_cmd {
	uint32_t data[8];
	struct versal_ipi_buf ibuf[VERSAL_MAX_IPI_BUF];
};

TEE_Result versal_mbox_notify(struct versal_ipi_cmd *cmd,
			      struct versal_ipi_cmd *rsp, uint32_t *err);
TEE_Result versal_mbox_alloc(size_t len, const void *init,
			     struct versal_mbox_mem *mem);
#endif /* __DRIVERS_VERSAL_MBOX_H */
