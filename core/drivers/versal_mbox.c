// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 *
 * Copyright (C) 2023 ProvenRun S.A.S
 */

#include <assert.h>
#include <drivers/mailbox.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <tee/cache.h>
#include "drivers/versal_mbox.h"

TEE_Result versal_mbox_open(uint32_t local, uint32_t remote,
			    struct versal_ipi *ipi)
{
	uint32_t args[] = { local, remote };
	struct mbox_controller *ctrl = NULL;
	TEE_Result res = TEE_SUCCESS;

	assert(ipi);

	res = versal_ipi_get_controller(&ctrl);
	if (res)
		return res;

	return mbox_request_channel(ctrl, args, ARRAY_SIZE(args), &ipi->chan);
}

TEE_Result versal_mbox_close(struct versal_ipi *ipi)
{
	assert(ipi && ipi->chan);

	mbox_free_channel(ipi->chan);
	ipi->chan = NULL;

	return TEE_SUCCESS;
}

TEE_Result versal_mbox_alloc(size_t len, const void *init,
			     struct versal_mbox_mem *mem)
{
	mem->buf = memalign(CACHELINE_LEN, ROUNDUP(len, CACHELINE_LEN));
	if (!mem->buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(mem->buf, 0, ROUNDUP(len, CACHELINE_LEN));

	if (init)
		memcpy(mem->buf, init, len);

	mem->alloc_len = ROUNDUP(len, CACHELINE_LEN);
	mem->len = len;

	return TEE_SUCCESS;
}

void versal_mbox_free(struct versal_mbox_mem *mem)
{
	assert(mem);

	free(mem->buf);
	mem->buf = NULL;
}

TEE_Result versal_mbox_notify(struct versal_ipi *ipi,
			      struct versal_ipi_cmd *cmd,
			      struct versal_ipi_cmd *rsp, uint32_t *err)
{
	struct versal_mbox_req req = { .cmd = cmd, .rsp = rsp, .err = err };

	assert(ipi && ipi->chan);

	return mbox_send_sync(ipi->chan, &req);
}
