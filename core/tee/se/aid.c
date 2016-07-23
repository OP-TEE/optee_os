/*
 * Copyright (c) 2014, Linaro Limited
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

#include <assert.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

#include <tee/se/aid.h>
#include <tee/se/util.h>

#include "aid_priv.h"

TEE_Result tee_se_aid_create(const char *name, struct tee_se_aid **aid)
{
	size_t str_length = strlen(name);
	size_t aid_length = str_length / 2;

	assert(aid);
	if (*aid)
		panic("aid already allocated");

	if (str_length < MIN_AID_LENGTH || str_length > MAX_AID_LENGTH)
		return TEE_ERROR_BAD_PARAMETERS;

	*aid = malloc(sizeof(struct tee_se_aid));
	if (!(*aid))
		return TEE_ERROR_OUT_OF_MEMORY;

	hex_decode(name, str_length, (*aid)->aid);
	(*aid)->length = aid_length;
	(*aid)->refcnt = 1;
	return TEE_SUCCESS;
}

TEE_Result tee_se_aid_create_from_buffer(uint8_t *id, size_t length,
		struct tee_se_aid **aid)
{
	*aid = malloc(sizeof(struct tee_se_aid));
	if (!(*aid))
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy((*aid)->aid, id, length);
	(*aid)->length = length;
	(*aid)->refcnt = 1;
	return TEE_SUCCESS;
}

void tee_se_aid_acquire(struct tee_se_aid *aid)
{
	assert(aid);
	aid->refcnt++;
}

int tee_se_aid_get_refcnt(struct tee_se_aid *aid)
{
	assert(aid);
	return aid->refcnt;
}

void tee_se_aid_release(struct tee_se_aid *aid)
{
	assert(aid);
	if (aid->refcnt <= 0)
		panic();
	aid->refcnt--;
	if (!aid->refcnt)
		free(aid);
}
