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

static TEE_Result versal_sha3_request(enum versal_crypto_api id,
				      struct cmd_args *arg)
{
	struct ipi_cmd cmd = { };

	cmd.data[0] = CRYPTO_API_ID(id);
	if (arg->data[0]) {
		/* write */
		cmd.data[1] = virt_to_phys(arg->ibuf[0].mem.buf);
		cmd.data[2] = virt_to_phys(arg->ibuf[0].mem.buf) >> 32;
		cmd.data[3] = arg->data[0];

		cmd.ibuf[0].mem = arg->ibuf[0].mem;
	} else {
		/* read */
		cmd.data[4] = virt_to_phys(arg->ibuf[0].mem.buf);
		cmd.data[5] = virt_to_phys(arg->ibuf[0].mem.buf) >> 32;

		cmd.ibuf[0].mem = arg->ibuf[0].mem;
	}

	return versal_mbox_notify(&cmd, NULL, NULL);
}

static TEE_Result versal_aes_update_aad_request(enum versal_crypto_api id,
						struct cmd_args *arg)
{
	struct ipi_cmd cmd = { };

	cmd.data[0] = CRYPTO_API_ID(id);
	cmd.data[1] = virt_to_phys(arg->ibuf[0].mem.buf);
	cmd.data[2] = virt_to_phys(arg->ibuf[0].mem.buf) >> 32;
	cmd.data[3] = arg->data[0];

	cmd.ibuf[0].mem = arg->ibuf[0].mem;

	return versal_mbox_notify(&cmd, NULL, NULL);
}

TEE_Result versal_crypto_request(enum versal_crypto_api id,
				 struct cmd_args *arg, uint32_t *err)
{
	struct ipi_cmd cmd = { };
	size_t i = 0;

	if (id == SHA3_UPDATE)
		return versal_sha3_request(id, arg);

	if (id == AES_UPDATE_AAD)
		return versal_aes_update_aad_request(id, arg);

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
