/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __TEE_TEE_OBJ_H
#define __TEE_TEE_OBJ_H

#include <kernel/tee_ta_manager.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define TEE_USAGE_DEFAULT   0xffffffff

struct tee_obj {
	TAILQ_ENTRY(tee_obj) link;
	TEE_ObjectInfo info;
	bool busy;		/* true if used by an operation */
	uint32_t have_attrs;	/* bitfield identifying set properties */
	void *attr;
	size_t ds_pos;
	struct tee_pobj *pobj;	/* ptr to persistant object */
	struct tee_file_handle *fh;
};

void tee_obj_add(struct user_ta_ctx *utc, struct tee_obj *o);

TEE_Result tee_obj_get(struct user_ta_ctx *utc, vaddr_t obj_id,
		       struct tee_obj **obj);

void tee_obj_close(struct user_ta_ctx *utc, struct tee_obj *o);

void tee_obj_close_all(struct user_ta_ctx *utc);

TEE_Result tee_obj_verify(struct tee_ta_session *sess, struct tee_obj *o);

struct tee_obj *tee_obj_alloc(void);
void tee_obj_free(struct tee_obj *o);

#endif
