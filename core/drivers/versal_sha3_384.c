// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <drivers/versal_sha3_384.h>
#include <initcall.h>
#include <ipi.h>
#include <mm/core_memprot.h>
#include <string.h>

#define VERSAL_SHA3_384_FIRST_PACKET		BIT(30)
#define VERSAL_SHA3_384_NEXT_PACKET		BIT(31)

static struct mutex lock = MUTEX_INITIALIZER;
static bool engine_ready;

static TEE_Result input_plaintext(const uint8_t *src, size_t src_len)
{
	uint32_t first = VERSAL_SHA3_384_FIRST_PACKET;
	struct versal_cmd_args arg = { .dlen = 1, };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	size_t len = 0;
	size_t i = 0;

	while (src_len && !ret) {
		len = MIN(src_len, SMALL_PAGE_SIZE);
		src_len -= len;
		versal_mbox_alloc(len, src + i * SMALL_PAGE_SIZE, &p);

		arg.data[0] = first | VERSAL_SHA3_384_NEXT_PACKET | len;
		arg.ibuf[0].mem = p;
		ret = versal_crypto_request(VERSAL_SHA3_UPDATE, &arg, NULL);
		if (ret)
			EMSG("VERSAL_SHA3_UPDATE [%ld, len = %zu]", i, len);

		free(p.buf);
		first = 0;
		i++;
	}

	return ret;
}

static TEE_Result get_ciphertext(uint8_t *dst, size_t dst_len)
{
	struct versal_cmd_args arg = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;

	versal_mbox_alloc(TEE_SHA384_HASH_SIZE, NULL, &p);

	arg.ibuf[0].mem = p;
	ret = versal_crypto_request(VERSAL_SHA3_UPDATE, &arg, NULL);
	if (!ret)
		memcpy(dst, p.buf, MIN(dst_len, (size_t)TEE_SHA384_HASH_SIZE));
	else
		EMSG("VERSAL_SHA3_UPDATE final");

	free(p.buf);

	return ret;
}

TEE_Result versal_sha3_384(const uint8_t *src, size_t src_len,
			   uint8_t *dst, size_t dst_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;

	if (!src_len || !dst_len || !src || !dst)
		return ret;

	if (!engine_ready)
		return TEE_ERROR_BAD_STATE;

	mutex_lock(&lock);

	ret = input_plaintext(src, src_len);
	if (!ret)
		ret = get_ciphertext(dst, dst_len);

	mutex_unlock(&lock);

	return ret;
}

static TEE_Result versal_sha3_384_init(void)
{
	struct versal_cmd_args arg = { };
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_crypto_request(VERSAL_SHA3_KAT, &arg, NULL);
	if (!ret)
		engine_ready = true;

	return ret;
}

/* Be available for the HUK */
service_init(versal_sha3_384_init);
