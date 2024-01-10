// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/mutex.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_pobj.h>

static TAILQ_HEAD(tee_pobjs, tee_pobj) tee_pobjs =
		TAILQ_HEAD_INITIALIZER(tee_pobjs);
static struct mutex pobjs_mutex = MUTEX_INITIALIZER;
static struct mutex pobjs_usage_mutex = MUTEX_INITIALIZER;

static bool pobj_need_usage_lock(struct tee_pobj *obj)
{
	/* Only lock if we don't have exclusive access to the object */
	return obj->flags & (TEE_DATA_FLAG_SHARE_WRITE |
			     TEE_DATA_FLAG_SHARE_READ);
}

void tee_pobj_lock_usage(struct tee_pobj *obj)
{
	if (pobj_need_usage_lock(obj))
		mutex_lock(&pobjs_usage_mutex);
}

void tee_pobj_unlock_usage(struct tee_pobj *obj)
{
	if (pobj_need_usage_lock(obj))
		mutex_unlock(&pobjs_usage_mutex);
}

static TEE_Result tee_pobj_check_access(uint32_t oflags, uint32_t nflags)
{
	/* meta is exclusive */
	if ((oflags & TEE_DATA_FLAG_ACCESS_WRITE_META) ||
	    (nflags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		return TEE_ERROR_ACCESS_CONFLICT;

	/*
	 * Excerpt of TEE Internal Core API Specification v1.1:
	 * If more than one handle is opened on the same  object, and if any
	 * of these object handles was opened with the flag
	 * TEE_DATA_FLAG_ACCESS_READ, then all the object handles MUST have been
	 * opened with the flag TEE_DATA_FLAG_SHARE_READ
	 */
	if (((oflags & TEE_DATA_FLAG_ACCESS_READ) ||
	     (nflags & TEE_DATA_FLAG_ACCESS_READ)) &&
	    !((nflags & TEE_DATA_FLAG_SHARE_READ) &&
	      (oflags & TEE_DATA_FLAG_SHARE_READ)))
		return TEE_ERROR_ACCESS_CONFLICT;

	/*
	 * Excerpt of TEE Internal Core API Specification v1.1:
	 * An object can be opened with only share flags, which locks the access
	 * to an object against a given mode.
	 * An object can be opened with no flag set, which completely locks all
	 * subsequent attempts to access the object
	 */
	if ((nflags & TEE_DATA_FLAG_SHARE_READ) !=
	    (oflags & TEE_DATA_FLAG_SHARE_READ))
		return TEE_ERROR_ACCESS_CONFLICT;

	/* Same on WRITE access */
	if (((oflags & TEE_DATA_FLAG_ACCESS_WRITE) ||
	     (nflags & TEE_DATA_FLAG_ACCESS_WRITE)) &&
	    !((nflags & TEE_DATA_FLAG_SHARE_WRITE) &&
	      (oflags & TEE_DATA_FLAG_SHARE_WRITE)))
		return TEE_ERROR_ACCESS_CONFLICT;
	if ((nflags & TEE_DATA_FLAG_SHARE_WRITE) !=
	    (oflags & TEE_DATA_FLAG_SHARE_WRITE))
		return TEE_ERROR_ACCESS_CONFLICT;

	return TEE_SUCCESS;
}

TEE_Result tee_pobj_get(TEE_UUID *uuid, void *obj_id, uint32_t obj_id_len,
			uint32_t flags, enum tee_pobj_usage usage,
			const struct tee_file_operations *fops,
			struct tee_pobj **obj)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_pobj *o = NULL;

	*obj = NULL;

	mutex_lock(&pobjs_mutex);
	/* Check if file is open */
	TAILQ_FOREACH(o, &tee_pobjs, link) {
		if ((obj_id_len == o->obj_id_len) &&
		    (memcmp(obj_id, o->obj_id, obj_id_len) == 0) &&
		    (memcmp(uuid, &o->uuid, sizeof(TEE_UUID)) == 0) &&
		    (fops == o->fops)) {
			*obj = o;
		}
	}

	if (*obj) {
		if (usage == TEE_POBJ_USAGE_ENUM) {
			(*obj)->refcnt++;
			goto out;
		}
		if ((*obj)->creating || (usage == TEE_POBJ_USAGE_CREATE &&
					 !(flags & TEE_DATA_FLAG_OVERWRITE))) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto out;
		}
		res = tee_pobj_check_access((*obj)->flags, flags);
		if (res == TEE_SUCCESS)
			(*obj)->refcnt++;
		goto out;
	}

	/* new file */
	o = calloc(1, sizeof(struct tee_pobj));
	if (!o) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	o->refcnt = 1;
	memcpy(&o->uuid, uuid, sizeof(TEE_UUID));
	o->flags = flags;
	o->fops = fops;

	if (usage == TEE_POBJ_USAGE_CREATE) {
		o->temporary = true;
		o->creating = true;
	}

	o->obj_id = malloc(obj_id_len);
	if (o->obj_id == NULL) {
		free(o);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(o->obj_id, obj_id, obj_id_len);
	o->obj_id_len = obj_id_len;

	TAILQ_INSERT_TAIL(&tee_pobjs, o, link);
	*obj = o;

	res = TEE_SUCCESS;
out:
	if (res != TEE_SUCCESS)
		*obj = NULL;
	mutex_unlock(&pobjs_mutex);
	return res;
}

void tee_pobj_create_final(struct tee_pobj *po)
{
	mutex_lock(&pobjs_mutex);
	po->temporary = false;
	po->creating = false;
	mutex_unlock(&pobjs_mutex);
}

TEE_Result tee_pobj_release(struct tee_pobj *obj)
{
	if (obj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&pobjs_mutex);
	obj->refcnt--;
	if (obj->refcnt == 0) {
		TAILQ_REMOVE(&tee_pobjs, obj, link);
		free(obj->obj_id);
		free(obj);
	}
	mutex_unlock(&pobjs_mutex);

	return TEE_SUCCESS;
}

TEE_Result tee_pobj_rename(struct tee_pobj *obj, void *obj_id,
			   uint32_t obj_id_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *new_obj_id = NULL;

	if (obj == NULL || obj_id == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&pobjs_mutex);
	if (obj->refcnt != 1) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	new_obj_id = malloc(obj_id_len);
	if (new_obj_id == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	memcpy(new_obj_id, obj_id, obj_id_len);

	/* update internal data */
	free(obj->obj_id);
	obj->obj_id = new_obj_id;
	obj->obj_id_len = obj_id_len;
	new_obj_id = NULL;

exit:
	mutex_unlock(&pobjs_mutex);
	free(new_obj_id);
	return res;
}
