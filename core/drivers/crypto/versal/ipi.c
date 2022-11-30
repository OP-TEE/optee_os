// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <arm.h>
#include <initcall.h>
#include <ipi.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <util.h>

#define SEC_MODULE_SHIFT 8
#define SEC_MODULE_ID 5

#define CRYPTO_API_ID(__x) ((SEC_MODULE_ID << SEC_MODULE_SHIFT) | (__x))

static TEE_Result versal_sha3_request(enum versal_crypto_api id,
				      struct versal_cmd_args *arg)
{
	struct versal_ipi_cmd cmd = { };
	uint32_t a = 0;
	uint32_t b = 0;

	cmd.data[0] = CRYPTO_API_ID(id);

	if (arg->data[0]) {
		/* write */
		reg_pair_from_64(virt_to_phys(arg->ibuf[0].mem.buf), &b, &a);
		cmd.data[1] = a;
		cmd.data[2] = b;
		cmd.data[3] = arg->data[0];

		cmd.ibuf[0].mem = arg->ibuf[0].mem;
	} else {
		/* read */
		reg_pair_from_64(virt_to_phys(arg->ibuf[0].mem.buf), &b, &a);
		cmd.data[4] = a;
		cmd.data[5] = b;

		cmd.ibuf[0].mem = arg->ibuf[0].mem;
	}

	return versal_mbox_notify(&cmd, NULL, NULL);
}

static TEE_Result versal_aes_update_aad_request(enum versal_crypto_api id,
						struct versal_cmd_args *arg)
{
	struct versal_ipi_cmd cmd = { };
	uint32_t a = 0;
	uint32_t b = 0;

	reg_pair_from_64(virt_to_phys(arg->ibuf[0].mem.buf), &b, &a);

	cmd.data[0] = CRYPTO_API_ID(id);
	cmd.data[1] = a;
	cmd.data[2] = b;
	cmd.data[3] = arg->data[0];

	cmd.ibuf[0].mem = arg->ibuf[0].mem;

	return versal_mbox_notify(&cmd, NULL, NULL);
}

TEE_Result versal_crypto_request(enum versal_crypto_api id,
				 struct versal_cmd_args *arg, uint32_t *err)
{
	struct versal_ipi_cmd cmd = { };
	uint32_t a = 0;
	uint32_t b = 0;
	size_t i = 0;

	if (id == VERSAL_SHA3_UPDATE)
		return versal_sha3_request(id, arg);

	if (id == VERSAL_AES_UPDATE_AAD)
		return versal_aes_update_aad_request(id, arg);

	cmd.data[0] = CRYPTO_API_ID(id);
	for (i = 1; i < arg->dlen + 1; i++)
		cmd.data[i] = arg->data[i - 1];

	/* src */
	if (!arg->ibuf[0].mem.buf)
		goto notify;

	reg_pair_from_64(virt_to_phys(arg->ibuf[0].mem.buf), &b, &a);
	cmd.data[i++] = a;
	cmd.data[i++] = b;

	/* dst */
	if (!arg->ibuf[1].mem.buf)
		goto cache;

	if (arg->ibuf[1].only_cache)
		goto cache;

	reg_pair_from_64(virt_to_phys(arg->ibuf[1].mem.buf), &b, &a);
	cmd.data[i++] = a;
	cmd.data[i++] = b;
cache:
	for (i = 0; i < VERSAL_MAX_IPI_BUF; i++)
		cmd.ibuf[i].mem = arg->ibuf[i].mem;
notify:
	return versal_mbox_notify(&cmd, NULL, err);
}
