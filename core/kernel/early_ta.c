// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */
#include <crypto/crypto.h>
#include <initcall.h>
#include <kernel/early_ta.h>
#include <kernel/embedded_ts.h>
#include <kernel/ts_store.h>
#include <kernel/user_ta.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

static const struct embedded_ts *find_early_ta(const TEE_UUID *uuid)
{
	const struct embedded_ts *ta = NULL;

	for_each_early_ta(ta)
		if (!memcmp(&ta->uuid, uuid, sizeof(*uuid)))
			return ta;

	return NULL;
}

static TEE_Result early_ta_open(const TEE_UUID *uuid,
				struct ts_store_handle **h)
{
	return emb_ts_open(uuid, h, find_early_ta);
}

REGISTER_TA_STORE(2) = {
	.description = "early TA",
	.open = early_ta_open,
	.get_size = emb_ts_get_size,
	.get_tag = emb_ts_get_tag,
	.read = emb_ts_read,
	.close = emb_ts_close,
};

static TEE_Result early_ta_init(void)
{
	const struct embedded_ts *ta = NULL;
	char __maybe_unused msg[60] = { '\0', };

	for_each_early_ta(ta) {
		if (ta->uncompressed_size)
			snprintf(msg, sizeof(msg),
				 " (compressed, uncompressed %u)",
				 ta->uncompressed_size);
		else
			msg[0] = '\0';
		DMSG("Early TA %pUl size %u%s", (void *)&ta->uuid, ta->size,
		     msg);
	}

	return TEE_SUCCESS;
}

service_init(early_ta_init);
