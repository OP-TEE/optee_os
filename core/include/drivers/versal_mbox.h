/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Foundries.io Ltd
 */
#ifndef __DRIVERS_VERSAL_MBOX_H
#define __DRIVERS_VERSAL_MBOX_H

#include <kernel/mutex.h>
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

struct versal_ipi {
	uint32_t lcl;
	uint32_t rmt;

	/* Exclusive access to the IPI shared buffer */
	struct mutex lock;

	vaddr_t regs;

	void *rsp;
	void *req;
};

/* IPI IDs */
#define IPI_ID_PMC	1
#define IPI_ID_0	2
#define IPI_ID_1	3
#define IPI_ID_2	4
#define IPI_ID_3	5
#define IPI_ID_4	6
#define IPI_ID_5	7

TEE_Result versal_mbox_open(uint32_t local, uint32_t remote,
			    struct versal_ipi *ipi);
TEE_Result versal_mbox_close(struct versal_ipi *ipi);

TEE_Result versal_mbox_notify(struct versal_ipi *ipi,
			      struct versal_ipi_cmd *cmd,
			      struct versal_ipi_cmd *rsp, uint32_t *err);

TEE_Result versal_mbox_notify_pmc(struct versal_ipi_cmd *cmd,
				  struct versal_ipi_cmd *rsp, uint32_t *err);

TEE_Result versal_mbox_alloc(size_t len, const void *init,
			     struct versal_mbox_mem *mem);
void versal_mbox_free(struct versal_mbox_mem *mem);

#endif /* __DRIVERS_VERSAL_MBOX_H */
