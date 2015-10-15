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

#include <tee/tee_obj.h>

#include <stdlib.h>
#include <tee_api_defines.h>
#include <mm/tee_mmu.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_pobj.h>
#include <trace.h>
#include <tee/tee_svc_storage.h>

void tee_obj_add(struct tee_ta_ctx *ctx, struct tee_obj *o)
{
	TAILQ_INSERT_TAIL(&ctx->objects, o, link);
}

TEE_Result tee_obj_get(struct tee_ta_ctx *ctx, uint32_t obj_id,
		       struct tee_obj **obj)
{
	struct tee_obj *o;

	TAILQ_FOREACH(o, &ctx->objects, link) {
		if (obj_id == (vaddr_t)o) {
			*obj = o;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

void tee_obj_close(struct tee_ta_ctx *ctx, struct tee_obj *o)
{
	TAILQ_REMOVE(&ctx->objects, o, link);

	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) && o->fd >= 0) {
		tee_file_ops.close(o->fd);
		tee_pobj_release(o->pobj);
	}

	if (o->cleanup)
		o->cleanup(o->data, true);
	free(o->data);
	free(o);
}

void tee_obj_close_all(struct tee_ta_ctx *ctx)
{
	struct tee_obj_head *objects = &ctx->objects;

	while (!TAILQ_EMPTY(objects))
		tee_obj_close(ctx, TAILQ_FIRST(objects));
}

TEE_Result tee_obj_verify(struct tee_ta_session *sess, struct tee_obj *o)
{
	TEE_Result res;
	char *file = NULL;
	char *dir = NULL;
	int fd = -1;
	int err = -1;

	file = storage_create_filename(sess, o->pobj->obj_id,
				       o->pobj->obj_id_len, false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	err = tee_file_ops.access(file, TEE_FS_F_OK);
	if (err) {
		/* file not found */
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
		goto err;
	}

	fd = tee_file_ops.open(&res, file, TEE_FS_O_RDONLY);
	if (fd < 0) {
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt\n");
			tee_obj_close(sess->ctx, o);
			tee_file_ops.unlink(file);
			dir = storage_create_dirname(sess);
			if (dir != NULL) {
				tee_file_ops.rmdir(dir);
				free(dir);
			}
		}
		goto err;
	}

	res = TEE_SUCCESS;

err:
	free(file);
	if (fd >= 0)
		tee_file_ops.close(fd);
exit:
	return res;
}
