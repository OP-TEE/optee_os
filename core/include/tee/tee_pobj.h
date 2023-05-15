/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_POBJ_H
#define TEE_POBJ_H

#include <stdint.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee/tee_fs.h>

struct tee_pobj {
	TAILQ_ENTRY(tee_pobj) link;
	uint32_t refcnt;
	TEE_UUID uuid;
	void *obj_id;
	uint32_t obj_id_len;
	uint32_t flags;
	bool temporary;	/* can be changed while creating == true */
	bool creating;	/* can only be changed with mutex held */
	/* Filesystem handling this object */
	const struct tee_file_operations *fops;
};

enum tee_pobj_usage {
	TEE_POBJ_USAGE_OPEN,
	TEE_POBJ_USAGE_RENAME,
	TEE_POBJ_USAGE_CREATE,
	TEE_POBJ_USAGE_ENUM,
};

TEE_Result tee_pobj_get(TEE_UUID *uuid, void *obj_id, uint32_t obj_id_len,
			uint32_t flags, enum tee_pobj_usage usage,
			const struct tee_file_operations *fops,
			struct tee_pobj **obj);

void tee_pobj_create_final(struct tee_pobj *obj);

TEE_Result tee_pobj_release(struct tee_pobj *obj);

TEE_Result tee_pobj_rename(struct tee_pobj *obj, void *obj_id,
			   uint32_t obj_id_len);

#endif
