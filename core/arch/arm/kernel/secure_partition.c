// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Arm Limited.
 */
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/secure_partition.h>
#include <kernel/embedded_ts.h>
#include <kernel/ts_store.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <zlib.h>

static const struct embedded_ts *find_secure_partition(const TEE_UUID *uuid)
{
	const struct embedded_ts *sp = NULL;

	for_each_secure_partition(sp)
		if (!memcmp(&sp->uuid, uuid, sizeof(*uuid)))
			return sp;

	return NULL;
}

static TEE_Result secure_partition_open(const TEE_UUID *uuid,
					struct ts_store_handle **h)
{
	return emb_ts_open(uuid, h, find_secure_partition);
}

REGISTER_SP_STORE(2) = {
	.description = "SP store",
	.open = secure_partition_open,
	.get_size = emb_ts_get_size,
	.get_tag = emb_ts_get_tag,
	.read = emb_ts_read,
	.close = emb_ts_close,
};

static TEE_Result secure_partition_init(void)
{
	const struct embedded_ts *sp = NULL;
	char __maybe_unused msg[60] = { '\0', };

	for_each_secure_partition(sp) {
		if (sp->uncompressed_size)
			snprintf(msg, sizeof(msg),
				 " (compressed, uncompressed %u)",
				 sp->uncompressed_size);
		else
			msg[0] = '\0';
		DMSG("SP %pUl size %u%s", (void *)&sp->uuid, sp->size, msg);
	}

	return TEE_SUCCESS;
}

service_init(secure_partition_init);
