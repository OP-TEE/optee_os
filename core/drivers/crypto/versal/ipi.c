// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <arm.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#include "ipi.h"

#define SEC_MODULE_SHIFT 8
#define SEC_MODULE_ID 5

#define CRYPTO_API_ID(__x) ((SEC_MODULE_ID << SEC_MODULE_SHIFT) | (__x))

TEE_Result versal_crypto_request(enum versal_crypto_api id,
				 struct cmd_args *arg, uint32_t *err)
{
	struct ipi_cmd cmd = { };
	size_t i = 0;

	cmd.data[i] = CRYPTO_API_ID(id);
	for (i = 1; i < arg->dlen + 1; i++)
		cmd.data[i] = arg->data[i - 1];

	/* src */
	if (!arg->ibuf[0].mem.buf)
		goto notify;

	cmd.data[i++] = virt_to_phys(arg->ibuf[0].mem.buf);
	cmd.data[i++] = virt_to_phys(arg->ibuf[0].mem.buf) >> 32;

	/* dst */
	if (!arg->ibuf[1].mem.buf)
		goto cache;

	if (arg->ibuf[1].only_cache)
		goto cache;

	cmd.data[i++] = virt_to_phys(arg->ibuf[1].mem.buf);
	cmd.data[i++] = virt_to_phys(arg->ibuf[1].mem.buf) >> 32;
cache:
	for (i = 0; i < MAX_IPI_BUF; i++)
		cmd.ibuf[i].mem = arg->ibuf[i].mem;
notify:
	return versal_mbox_notify(&cmd, NULL, err);
}
