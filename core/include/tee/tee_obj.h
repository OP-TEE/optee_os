/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef TEE_OBJ_H
#define TEE_OBJ_H

#include <tee_api_types.h>
#include <kernel/tee_ta_manager.h>
#include <sys/queue.h>

#define TEE_USAGE_DEFAULT   0xffffffff

struct tee_obj {
	TAILQ_ENTRY(tee_obj) link;
	TEE_ObjectInfo info;
	bool busy;		/* true if used by an operation */
	uint32_t have_attrs;	/* bitfield identifying set properties */
	void *data;
	size_t data_size;
	void (*cleanup)(void *data, bool del); /* clear or delete data */
	struct tee_pobj *pobj;	/* ptr to persistant object */
	int fd;
	uint32_t ds_size;	/* data stream size */
	uint32_t flags;		/* permission flags for persistent objects */
};

void tee_obj_add(struct user_ta_ctx *utc, struct tee_obj *o);

TEE_Result tee_obj_get(struct user_ta_ctx *utc, uint32_t obj_id,
		       struct tee_obj **obj);

void tee_obj_close(struct user_ta_ctx *utc, struct tee_obj *o);

void tee_obj_close_all(struct user_ta_ctx *utc);

TEE_Result tee_obj_verify(struct tee_ta_session *sess, struct tee_obj *o);

#endif
