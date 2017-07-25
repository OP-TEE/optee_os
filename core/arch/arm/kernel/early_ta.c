/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <initcall.h>
#include <kernel/early_ta.h>
#include <kernel/linker.h>
#include <kernel/user_ta.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "elf_load.h"

struct user_ta_store_handle {
	const struct early_ta *early_ta;
	size_t offs;
};

#define for_each_early_ta(_ta) \
	for (_ta = &__rodata_early_ta_start; _ta < &__rodata_early_ta_end; \
	     _ta = (const struct early_ta *)				   \
		   ROUNDUP((vaddr_t)_ta + sizeof(*_ta) + _ta->size,	   \
			   __alignof__(struct early_ta)))

static const struct early_ta *find_early_ta(const TEE_UUID *uuid)
{
	const struct early_ta *ta;

	for_each_early_ta(ta)
		if (!memcmp(&ta->uuid, uuid, sizeof(*uuid)))
			return ta;

	return NULL;
}

static TEE_Result early_ta_open(const TEE_UUID *uuid,
				struct user_ta_store_handle **h)
{
	const struct early_ta *ta;
	struct user_ta_store_handle *handle;

	ta = find_early_ta(uuid);
	if (!ta)
		return TEE_ERROR_ITEM_NOT_FOUND;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		return TEE_ERROR_OUT_OF_MEMORY;

	handle->early_ta = ta;
	*h = handle;

	return TEE_SUCCESS;
}

static TEE_Result early_ta_get_size(const struct user_ta_store_handle *h,
				    size_t *size)
{
	*size = h->early_ta->size;
	return TEE_SUCCESS;
}

static TEE_Result early_ta_read(struct user_ta_store_handle *h, void *data,
				size_t len)
{
	uint8_t *src = (uint8_t *)h->early_ta->ta + h->offs;

	if (h->offs + len > h->early_ta->size)
		return TEE_ERROR_BAD_PARAMETERS;
	if (data)
		memcpy(data, src, len);
	h->offs += len;

	return TEE_SUCCESS;
}

static void early_ta_close(struct user_ta_store_handle *h)
{
	free(h);
}

static struct user_ta_store_ops ops = {
	.description = "early TA",
	.open = early_ta_open,
	.get_size = early_ta_get_size,
	.read = early_ta_read,
	.close = early_ta_close,
	.priority = 5,
};

static TEE_Result early_ta_init(void)
{
	const struct early_ta *ta;

	for_each_early_ta(ta)
		DMSG("Early TA %pUl size %u", (void *)&ta->uuid, ta->size);

	return tee_ta_register_ta_store(&ops);
}

service_init(early_ta_init);
