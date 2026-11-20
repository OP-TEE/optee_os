/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Foundries.io Ltd
 */
#ifndef __DRIVERS_VERSAL_MBOX_H
#define __DRIVERS_VERSAL_MBOX_H

#include <drivers/mailbox.h>
#include <kernel/mutex.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <util.h>

#define VERSAL_MAX_IPI_BUF 7
#define VERSAL_MAX_IPI_DATA 8

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
	uint32_t data[VERSAL_MAX_IPI_DATA];
	struct versal_ipi_buf ibuf[VERSAL_MAX_IPI_BUF];

#ifdef CFG_VERSAL_OCP
	/* newer fields, used by versal_ipi_cmd_*() functions, only: */

	/* number of valid entries in data[] */
	size_t data_count;
	/* number of valid entries in ibuf[] */
	size_t ibuf_count;
#endif
};

/* IPI IDs */
#define VERSAL_IPI_ID_PMC	1
#define VERSAL_IPI_ID_0		2
#define VERSAL_IPI_ID_1		3
#define VERSAL_IPI_ID_2		4
#define VERSAL_IPI_ID_3		5
#define VERSAL_IPI_ID_4		6
#define VERSAL_IPI_ID_5		7

/* IPI channel handle, filled by versal_mbox_open() */
struct versal_ipi {
	struct mbox_chan *chan;
};

/*
 * struct versal_mbox_req - Message passed to the mailbox framework
 * @cmd: Command to send
 * @rsp: Buffer receiving the response data, can be NULL
 * @err: Receives the remote status on error, can be NULL
 */
struct versal_mbox_req {
	struct versal_ipi_cmd *cmd;
	struct versal_ipi_cmd *rsp;
	uint32_t *err;
};

TEE_Result versal_mbox_open(uint32_t local, uint32_t remote,
			    struct versal_ipi *ipi);
TEE_Result versal_mbox_close(struct versal_ipi *ipi);

TEE_Result versal_mbox_notify(struct versal_ipi *ipi,
			      struct versal_ipi_cmd *cmd,
			      struct versal_ipi_cmd *rsp, uint32_t *err);

TEE_Result versal_mbox_alloc(size_t len, const void *init,
			     struct versal_mbox_mem *mem);
void versal_mbox_free(struct versal_mbox_mem *mem);

/* Versal IPI mailbox controller, implemented in versal_ipi.c */
TEE_Result versal_ipi_get_controller(struct mbox_controller **ctrl);
#endif /* __DRIVERS_VERSAL_MBOX_H */
