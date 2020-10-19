// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <mm/vm.h>
#include <stdlib.h>
#include <tee_api_defines.h>
#include <tee/tee_fs.h>
#include <tee/tee_obj.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc_storage.h>
#include <trace.h>

void tee_obj_add(struct user_ta_ctx *utc, struct tee_obj *o)
{
	TAILQ_INSERT_TAIL(&utc->objects, o, link);
}

TEE_Result tee_obj_get(struct user_ta_ctx *utc, vaddr_t obj_id,
		       struct tee_obj **obj)
{
	struct tee_obj *o;

	TAILQ_FOREACH(o, &utc->objects, link) {
		if (obj_id == (vaddr_t)o) {
			*obj = o;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_STATE;
}

void tee_obj_close(struct user_ta_ctx *utc, struct tee_obj *o)
{
	TAILQ_REMOVE(&utc->objects, o, link);

	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		o->pobj->fops->close(&o->fh);
		tee_pobj_release(o->pobj);
	}

	tee_obj_free(o);
}

void tee_obj_close_all(struct user_ta_ctx *utc)
{
	struct tee_obj_head *objects = &utc->objects;

	while (!TAILQ_EMPTY(objects))
		tee_obj_close(utc, TAILQ_FIRST(objects));
}

TEE_Result tee_obj_verify(struct tee_ta_session *sess, struct tee_obj *o)
{
	TEE_Result res;
	const struct tee_file_operations *fops = o->pobj->fops;
	struct tee_file_handle *fh = NULL;

	if (!fops)
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;

	res = fops->open(o->pobj, NULL, &fh);
	if (res == TEE_ERROR_CORRUPT_OBJECT) {
		EMSG("Object corrupt");
		fops->remove(o->pobj);
		tee_obj_close(to_user_ta_ctx(sess->ts_sess.ctx), o);
	}

	fops->close(&fh);
	return res;
}

struct tee_obj *tee_obj_alloc(void)
{
	return calloc(1, sizeof(struct tee_obj));
}

void tee_obj_free(struct tee_obj *o)
{
	if (o) {
		tee_obj_attr_free(o);
		free(o->attr);
		free(o);
	}
}
