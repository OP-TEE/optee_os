// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <kernel/mutex.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <mm/tee_mmu.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_defines.h>
#include <tee/fs_dirfile.h>
#include <tee/tee_fs.h>
#include <tee/tee_obj.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>
#include <trace.h>

const struct tee_file_operations *tee_svc_storage_file_ops(uint32_t storage_id)
{

	switch (storage_id) {
	case TEE_STORAGE_PRIVATE:
#if defined(CFG_REE_FS)
		return &ree_fs_ops;
#elif defined(CFG_RPMB_FS)
		return &rpmb_fs_ops;
#else
#error At least one filesystem must be enabled.
#endif
#ifdef CFG_REE_FS
	case TEE_STORAGE_PRIVATE_REE:
		return &ree_fs_ops;
#endif
#ifdef CFG_RPMB_FS
	case TEE_STORAGE_PRIVATE_RPMB:
		return &rpmb_fs_ops;
#endif
	default:
		return NULL;
	}
}

/* Header of GP formated secure storage files */
struct tee_svc_storage_head {
	uint32_t attr_size;
	uint32_t keySize;
	uint32_t maxKeySize;
	uint32_t objectUsage;
	uint32_t objectType;
	uint32_t have_attrs;
};

struct tee_storage_enum {
	TAILQ_ENTRY(tee_storage_enum) link;
	struct tee_fs_dir *dir;
	const struct tee_file_operations *fops;
};

static TEE_Result tee_svc_storage_get_enum(struct user_ta_ctx *utc,
					   uint32_t enum_id,
					   struct tee_storage_enum **e_out)
{
	struct tee_storage_enum *e;

	TAILQ_FOREACH(e, &utc->storage_enums, link) {
		if (enum_id == (vaddr_t)e) {
			*e_out = e;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result tee_svc_close_enum(struct user_ta_ctx *utc,
				     struct tee_storage_enum *e)
{
	if (e == NULL || utc == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	TAILQ_REMOVE(&utc->storage_enums, e, link);

	if (e->fops)
		e->fops->closedir(e->dir);

	e->dir = NULL;
	e->fops = NULL;

	free(e);

	return TEE_SUCCESS;
}

/* "/TA_uuid/object_id" or "/TA_uuid/.object_id" */
TEE_Result tee_svc_storage_create_filename(void *buf, size_t blen,
					   struct tee_pobj *po, bool transient)
{
	uint8_t *file = buf;
	uint32_t pos = 0;
	uint32_t hslen = 1 /* Leading slash */
			+ TEE_B2HS_HSBUF_SIZE(sizeof(TEE_UUID) + po->obj_id_len)
			+ 1; /* Intermediate slash */

	/* +1 for the '.' (temporary persistent object) */
	if (transient)
		hslen++;

	if (blen < hslen)
		return TEE_ERROR_SHORT_BUFFER;

	file[pos++] = '/';
	pos += tee_b2hs((uint8_t *)&po->uuid, &file[pos],
			sizeof(TEE_UUID), hslen);
	file[pos++] = '/';

	if (transient)
		file[pos++] = '.';

	tee_b2hs(po->obj_id, file + pos, po->obj_id_len, hslen - pos);

	return TEE_SUCCESS;
}

#ifdef CFG_REE_FS
/* "/dirf.db" or "/<file number>" */
TEE_Result
tee_svc_storage_create_filename_dfh(void *buf, size_t blen,
				    const struct tee_fs_dirfile_fileh *dfh)
{
	char *file = buf;
	size_t pos = 0;
	size_t l;

	if (pos >= blen)
		return TEE_ERROR_SHORT_BUFFER;

	file[pos] = '/';
	pos++;
	if (pos >= blen)
		return TEE_ERROR_SHORT_BUFFER;

	l = blen - pos;
	return tee_fs_dirfile_fileh_to_fname(dfh, file + pos, &l);
}
#endif

/* "/TA_uuid" */
TEE_Result tee_svc_storage_create_dirname(void *buf, size_t blen,
					  const TEE_UUID *uuid)
{
	uint8_t *dir = buf;
	uint32_t hslen = TEE_B2HS_HSBUF_SIZE(sizeof(TEE_UUID)) + 1;

	if (blen < hslen)
		return TEE_ERROR_SHORT_BUFFER;

	dir[0] = '/';
	tee_b2hs((uint8_t *)uuid, dir + 1, sizeof(TEE_UUID), hslen);

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_storage_remove_corrupt_obj(
					struct tee_ta_session *sess,
					struct tee_obj *o)
{
	o->pobj->fops->remove(o->pobj);
	tee_obj_close(to_user_ta_ctx(sess->ctx), o);

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_storage_read_head(struct tee_obj *o)
{
	TEE_Result res = TEE_SUCCESS;
	size_t bytes;
	struct tee_svc_storage_head head;
	const struct tee_file_operations *fops = o->pobj->fops;
	void *attr = NULL;
	size_t size;
	size_t tmp = 0;

	assert(!o->fh);
	res = fops->open(o->pobj, &size, &o->fh);
	if (res != TEE_SUCCESS)
		goto exit;

	/* read head */
	bytes = sizeof(struct tee_svc_storage_head);
	res = fops->read(o->fh, 0, &head, &bytes);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_CORRUPT_OBJECT)
			EMSG("Head corrupt");
		goto exit;
	}

	if (ADD_OVERFLOW(sizeof(head), head.attr_size, &tmp)) {
		res = TEE_ERROR_OVERFLOW;
		goto exit;
	}
	if (tmp > size) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto exit;
	}

	if (bytes != sizeof(struct tee_svc_storage_head)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto exit;
	}

	res = tee_obj_set_type(o, head.objectType, head.maxKeySize);
	if (res != TEE_SUCCESS)
		goto exit;

	o->ds_pos = tmp;

	if (head.attr_size) {
		attr = malloc(head.attr_size);
		if (!attr) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		/* read meta */
		bytes = head.attr_size;
		res = fops->read(o->fh, sizeof(struct tee_svc_storage_head),
				 attr, &bytes);
		if (res == TEE_ERROR_OUT_OF_MEMORY)
			goto exit;
		if (res != TEE_SUCCESS || bytes != head.attr_size)
			res = TEE_ERROR_CORRUPT_OBJECT;
		if (res)
			goto exit;
	}

	res = tee_obj_attr_from_binary(o, attr, head.attr_size);
	if (res != TEE_SUCCESS)
		goto exit;

	o->info.dataSize = size - sizeof(head) - head.attr_size;
	o->info.keySize = head.keySize;
	o->info.objectUsage = head.objectUsage;
	o->info.objectType = head.objectType;
	o->have_attrs = head.have_attrs;

exit:
	free(attr);

	return res;
}

TEE_Result syscall_storage_obj_open(unsigned long storage_id, void *object_id,
			size_t object_id_len, unsigned long flags,
			uint32_t *obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o = NULL;
	char *file = NULL;
	struct tee_pobj *po = NULL;
	struct user_ta_ctx *utc;
	const struct tee_file_operations *fops =
			tee_svc_storage_file_ops(storage_id);

	if (!fops) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	if (object_id_len > TEE_OBJECT_ID_MAX_LEN) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto err;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_mmu_check_access_rights(utc,
					  TEE_MEMORY_ACCESS_READ,
					  (uaddr_t) object_id,
					  object_id_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, flags, false, fops, &po);
	if (res != TEE_SUCCESS)
		goto err;

	o = tee_obj_alloc();
	if (o == NULL) {
		tee_pobj_release(po);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->flags = flags;
	o->pobj = po;
	tee_obj_add(utc, o);

	res = tee_svc_storage_read_head(o);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt");
			goto err;
		}
		goto oclose;
	}

	res = tee_svc_copy_kaddr_to_uref(obj, o);
	if (res != TEE_SUCCESS)
		goto oclose;

	goto exit;

oclose:
	tee_obj_close(utc, o);
	o = NULL;

err:
	if (res == TEE_ERROR_NO_DATA || res == TEE_ERROR_BAD_FORMAT)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_ERROR_CORRUPT_OBJECT && o)
		tee_svc_storage_remove_corrupt_obj(sess, o);

exit:
	free(file);
	file = NULL;
	return res;
}

static TEE_Result tee_svc_storage_init_file(struct tee_obj *o,
					    struct tee_obj *attr_o, void *data,
					    uint32_t len)
{
	TEE_Result res = TEE_SUCCESS;
	struct tee_svc_storage_head head;
	const struct tee_file_operations *fops = o->pobj->fops;
	void *attr = NULL;
	size_t attr_size = 0;

	if (attr_o) {
		res = tee_obj_set_type(o, attr_o->info.objectType,
				       attr_o->info.maxKeySize);
		if (res)
			return res;
		res = tee_obj_attr_copy_from(o, attr_o);
		if (res)
			return res;
		o->have_attrs = attr_o->have_attrs;
		o->info.objectUsage = attr_o->info.objectUsage;
		o->info.keySize = attr_o->info.keySize;
		res = tee_obj_attr_to_binary(o, NULL, &attr_size);
		if (res)
			return res;
		if (attr_size) {
			attr = malloc(attr_size);
			if (!attr)
				return TEE_ERROR_OUT_OF_MEMORY;
			res = tee_obj_attr_to_binary(o, attr, &attr_size);
			if (res != TEE_SUCCESS)
				goto exit;
		}
	} else {
		res = tee_obj_set_type(o, TEE_TYPE_DATA, 0);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	o->ds_pos = sizeof(struct tee_svc_storage_head) + attr_size;

	/* write head */
	head.attr_size = attr_size;
	head.keySize = o->info.keySize;
	head.maxKeySize = o->info.maxKeySize;
	head.objectUsage = o->info.objectUsage;
	head.objectType = o->info.objectType;
	head.have_attrs = o->have_attrs;

	res = fops->create(o->pobj, !!(o->flags & TEE_DATA_FLAG_OVERWRITE),
			   &head, sizeof(head), attr, attr_size, data, len,
			   &o->fh);

	if (!res)
		o->info.dataSize = len;
exit:
	free(attr);
	return res;
}

TEE_Result syscall_storage_obj_create(unsigned long storage_id, void *object_id,
			size_t object_id_len, unsigned long flags,
			unsigned long attr, void *data, size_t len,
			uint32_t *obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o = NULL;
	struct tee_obj *attr_o = NULL;
	struct tee_pobj *po = NULL;
	struct user_ta_ctx *utc;
	const struct tee_file_operations *fops =
			tee_svc_storage_file_ops(storage_id);

	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (object_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_mmu_check_access_rights(utc,
					  TEE_MEMORY_ACCESS_READ,
					  (uaddr_t) object_id,
					  object_id_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, flags, true, fops, &po);
	if (res != TEE_SUCCESS)
		goto err;

	/* check rights of the provided buffer */
	if (len) {
		if (data) {
			res = tee_mmu_check_access_rights(utc,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (uaddr_t) data, len);

			if (res != TEE_SUCCESS)
				goto err;
		} else {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}
	}

	o = tee_obj_alloc();
	if (o == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->flags = flags;
	o->pobj = po;

	if (attr != TEE_HANDLE_NULL) {
		res = tee_obj_get(utc, tee_svc_uref_to_vaddr(attr),
				  &attr_o);
		if (res != TEE_SUCCESS)
			goto err;
	}

	res = tee_svc_storage_init_file(o, attr_o, data, len);
	if (res != TEE_SUCCESS)
		goto err;

	po = NULL; /* o owns it from now on */
	tee_obj_add(utc, o);

	res = tee_svc_copy_kaddr_to_uref(obj, o);
	if (res != TEE_SUCCESS)
		goto oclose;

	return TEE_SUCCESS;

oclose:
	tee_obj_close(utc, o);
	return res;

err:
	if (res == TEE_ERROR_NO_DATA || res == TEE_ERROR_BAD_FORMAT)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_ERROR_CORRUPT_OBJECT && po)
		fops->remove(po);
	if (o) {
		fops->close(&o->fh);
		tee_obj_free(o);
	}
	if (po)
		tee_pobj_release(po);

	return res;
}

TEE_Result syscall_storage_obj_del(unsigned long obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	struct user_ta_ctx *utc;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_obj_get(utc, tee_svc_uref_to_vaddr(obj), &o);
	if (res != TEE_SUCCESS)
		return res;

	if (!(o->flags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		return TEE_ERROR_ACCESS_CONFLICT;

	if (o->pobj == NULL || o->pobj->obj_id == NULL)
		return TEE_ERROR_BAD_STATE;

	res = o->pobj->fops->remove(o->pobj);
	tee_obj_close(utc, o);

	return res;
}

TEE_Result syscall_storage_obj_rename(unsigned long obj, void *object_id,
			size_t object_id_len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	struct tee_pobj *po = NULL;
	char *new_file = NULL;
	char *old_file = NULL;
	struct user_ta_ctx *utc;
	const struct tee_file_operations *fops;

	if (object_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_obj_get(utc, tee_svc_uref_to_vaddr(obj), &o);
	if (res != TEE_SUCCESS)
		return res;

	if (!(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	if (!(o->flags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	if (o->pobj == NULL || o->pobj->obj_id == NULL) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_READ,
					(uaddr_t) object_id, object_id_len);
	if (res != TEE_SUCCESS)
		goto exit;

	/* reserve dest name */
	fops = o->pobj->fops;
	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META,
			   false, fops, &po);
	if (res != TEE_SUCCESS)
		goto exit;

	/* move */
	res = fops->rename(o->pobj, po, false /* no overwrite */);
	if (res)
		goto exit;

	res = tee_pobj_rename(o->pobj, object_id, object_id_len);

exit:
	tee_pobj_release(po);

	free(new_file);
	free(old_file);

	return res;
}

TEE_Result syscall_storage_alloc_enum(uint32_t *obj_enum)
{
	struct tee_storage_enum *e;
	struct tee_ta_session *sess;
	TEE_Result res;
	struct user_ta_ctx *utc;

	if (obj_enum == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	e = malloc(sizeof(struct tee_storage_enum));
	if (e == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	e->dir = NULL;
	e->fops = NULL;
	TAILQ_INSERT_TAIL(&utc->storage_enums, e, link);

	return tee_svc_copy_kaddr_to_uref(obj_enum, e);
}

TEE_Result syscall_storage_free_enum(unsigned long obj_enum)
{
	struct tee_storage_enum *e;
	TEE_Result res;
	struct tee_ta_session *sess;
	struct user_ta_ctx *utc;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_svc_storage_get_enum(utc,
			tee_svc_uref_to_vaddr(obj_enum), &e);
	if (res != TEE_SUCCESS)
		return res;

	return tee_svc_close_enum(utc, e);
}

TEE_Result syscall_storage_reset_enum(unsigned long obj_enum)
{
	struct tee_storage_enum *e;
	TEE_Result res;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_storage_get_enum(to_user_ta_ctx(sess->ctx),
			tee_svc_uref_to_vaddr(obj_enum), &e);
	if (res != TEE_SUCCESS)
		return res;

	if (e->fops) {
		e->fops->closedir(e->dir);
		e->fops = NULL;
		e->dir = NULL;
	}
	assert(!e->dir);

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_storage_set_enum(struct tee_fs_dirent *d,
			const struct tee_file_operations *fops,
			struct tee_obj *o)
{
	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->info.objectUsage = TEE_USAGE_DEFAULT;

	if (d->oidlen > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_CORRUPT_OBJECT;

	o->pobj->obj_id = malloc(d->oidlen);
	if (!o->pobj->obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(o->pobj->obj_id, d->oid, d->oidlen);
	o->pobj->obj_id_len = d->oidlen;
	o->pobj->fops = fops;

	return TEE_SUCCESS;
}

TEE_Result syscall_storage_start_enum(unsigned long obj_enum,
				      unsigned long storage_id)
{
	struct tee_storage_enum *e;
	TEE_Result res;
	struct tee_ta_session *sess;
	const struct tee_file_operations *fops =
			tee_svc_storage_file_ops(storage_id);

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_storage_get_enum(to_user_ta_ctx(sess->ctx),
			tee_svc_uref_to_vaddr(obj_enum), &e);
	if (res != TEE_SUCCESS)
		return res;

	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	e->fops = fops;
	assert(!e->dir);
	return fops->opendir(&sess->ctx->uuid, &e->dir);
}

TEE_Result syscall_storage_next_enum(unsigned long obj_enum,
			TEE_ObjectInfo *info, void *obj_id, uint64_t *len)
{
	struct tee_storage_enum *e;
	struct tee_fs_dirent *d;
	TEE_Result res = TEE_SUCCESS;
	struct tee_ta_session *sess;
	struct tee_obj *o = NULL;
	uint64_t l;
	struct user_ta_ctx *utc;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_svc_storage_get_enum(utc,
			tee_svc_uref_to_vaddr(obj_enum), &e);
	if (res != TEE_SUCCESS)
		goto exit;

	/* check rights of the provided buffers */
	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(uaddr_t) info,
					sizeof(TEE_ObjectInfo));
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(uaddr_t) obj_id,
					TEE_OBJECT_ID_MAX_LEN);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!e->fops) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	res = e->fops->readdir(e->dir, &d);
	if (res != TEE_SUCCESS)
		goto exit;

	o = tee_obj_alloc();
	if (o == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	o->flags = TEE_DATA_FLAG_SHARE_READ;

	o->pobj = calloc(1, sizeof(struct tee_pobj));
	if (!o->pobj) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	o->pobj->uuid = sess->ctx->uuid;
	res = tee_svc_storage_set_enum(d, e->fops, o);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_svc_storage_read_head(o);
	if (res != TEE_SUCCESS)
		goto exit;

	memcpy(info, &o->info, sizeof(TEE_ObjectInfo));
	memcpy(obj_id, o->pobj->obj_id, o->pobj->obj_id_len);

	l = o->pobj->obj_id_len;
	res = tee_svc_copy_to_user(len, &l, sizeof(*len));

exit:
	if (o) {
		if (o->pobj) {
			if (o->pobj->fops)
				o->pobj->fops->close(&o->fh);
			free(o->pobj->obj_id);
		}
		free(o->pobj);
		tee_obj_free(o);
	}

	return res;
}

TEE_Result syscall_storage_obj_read(unsigned long obj, void *data, size_t len,
			uint64_t *count)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	uint64_t u_count;
	struct user_ta_ctx *utc;
	size_t bytes;
	size_t pos_tmp = 0;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_obj_get(utc, tee_svc_uref_to_vaddr(obj), &o);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	if (!(o->flags & TEE_DATA_FLAG_ACCESS_READ)) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	/* Guard o->info.dataPosition += bytes below from overflowing */
	if (ADD_OVERFLOW(o->info.dataPosition, len, &pos_tmp)) {
		res = TEE_ERROR_OVERFLOW;
		goto exit;
	}

	/* check rights of the provided buffer */
	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(uaddr_t) data, len);
	if (res != TEE_SUCCESS)
		goto exit;

	bytes = len;
	if (ADD_OVERFLOW(o->ds_pos, o->info.dataPosition, &pos_tmp)) {
		res = TEE_ERROR_OVERFLOW;
		goto exit;
	}
	res = o->pobj->fops->read(o->fh, pos_tmp, data, &bytes);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt");
			tee_svc_storage_remove_corrupt_obj(sess, o);
		}
		goto exit;
	}

	o->info.dataPosition += bytes;

	u_count = bytes;
	res = tee_svc_copy_to_user(count, &u_count, sizeof(*count));
exit:
	return res;
}

TEE_Result syscall_storage_obj_write(unsigned long obj, void *data, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	struct user_ta_ctx *utc;
	size_t pos_tmp = 0;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_obj_get(utc, tee_svc_uref_to_vaddr(obj), &o);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	if (!(o->flags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	/* Guard o->info.dataPosition += bytes below from overflowing */
	if (ADD_OVERFLOW(o->info.dataPosition, len, &pos_tmp)) {
		res = TEE_ERROR_OVERFLOW;
		goto exit;
	}

	/* check rights of the provided buffer */
	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(uaddr_t) data, len);
	if (res != TEE_SUCCESS)
		goto exit;

	if (ADD_OVERFLOW(o->ds_pos, o->info.dataPosition, &pos_tmp)) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}
	res = o->pobj->fops->write(o->fh, pos_tmp, data, len);
	if (res != TEE_SUCCESS)
		goto exit;

	o->info.dataPosition += len;
	if (o->info.dataPosition > o->info.dataSize)
		o->info.dataSize = o->info.dataPosition;

exit:
	return res;
}

TEE_Result syscall_storage_obj_trunc(unsigned long obj, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	size_t off;
	size_t attr_size;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_get(to_user_ta_ctx(sess->ctx),
			  tee_svc_uref_to_vaddr(obj), &o);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	if (!(o->flags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	res = tee_obj_attr_to_binary(o, NULL, &attr_size);
	if (res != TEE_SUCCESS)
		goto exit;

	if (ADD_OVERFLOW(sizeof(struct tee_svc_storage_head), attr_size,
				&off)) {
		res = TEE_ERROR_OVERFLOW;
		goto exit;
	}
	if (ADD_OVERFLOW(len, off, &off)) {
		res = TEE_ERROR_OVERFLOW;
		goto exit;
	}
	res = o->pobj->fops->truncate(o->fh, off);
	switch (res) {
	case TEE_SUCCESS:
		o->info.dataSize = len;
		break;
	case TEE_ERROR_CORRUPT_OBJECT:
		EMSG("Object corruption");
		(void)tee_svc_storage_remove_corrupt_obj(sess, o);
		break;
	default:
		res = TEE_ERROR_GENERIC;
		break;
	}

exit:
	return res;
}

TEE_Result syscall_storage_obj_seek(unsigned long obj, int32_t offset,
				    unsigned long whence)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	tee_fs_off_t new_pos;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(to_user_ta_ctx(sess->ctx),
			  tee_svc_uref_to_vaddr(obj), &o);
	if (res != TEE_SUCCESS)
		return res;

	if (!(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT))
		return TEE_ERROR_BAD_STATE;

	switch (whence) {
	case TEE_DATA_SEEK_SET:
		new_pos = offset;
		break;
	case TEE_DATA_SEEK_CUR:
		if (ADD_OVERFLOW(o->info.dataPosition, offset, &new_pos))
			return TEE_ERROR_OVERFLOW;
		break;
	case TEE_DATA_SEEK_END:
		if (ADD_OVERFLOW(o->info.dataSize, offset, &new_pos))
			return TEE_ERROR_OVERFLOW;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (new_pos < 0)
		new_pos = 0;

	if (new_pos > TEE_DATA_MAX_POSITION) {
		EMSG("Position is beyond TEE_DATA_MAX_POSITION");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	o->info.dataPosition = new_pos;

	return TEE_SUCCESS;
}

void tee_svc_storage_close_all_enum(struct user_ta_ctx *utc)
{
	struct tee_storage_enum_head *eh = &utc->storage_enums;

	/* disregard return value */
	while (!TAILQ_EMPTY(eh))
		tee_svc_close_enum(utc, TAILQ_FIRST(eh));
}
