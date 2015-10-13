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

#include <tee/tee_svc_storage.h>

#include <kernel/tee_ta_manager.h>
#include <tee_api_defines.h>
#include <kernel/tee_misc.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc.h>
#include <mm/tee_mmu.h>
#include <tee/tee_pobj.h>
#include <trace.h>

/* SSF (Secure Storage File version 00 */
#define TEE_SVC_STORAGE_MAGIC 0x53534600;

/* Header of GP formated secure storage files */
struct tee_svc_storage_head {
	uint32_t magic;
	uint32_t head_size;
	uint32_t meta_size;
	uint32_t ds_size;
};

struct tee_storage_enum {
	TAILQ_ENTRY(tee_storage_enum) link;
	tee_fs_dir *dir;
};

static TEE_Result tee_svc_storage_get_enum(struct tee_ta_ctx *ctx,
					   uint32_t enum_id,
					   struct tee_storage_enum **e_out)
{
	struct tee_storage_enum *e;

	TAILQ_FOREACH(e, &ctx->storage_enums, link) {
		if (enum_id == (vaddr_t)e) {
			*e_out = e;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result tee_svc_close_enum(struct tee_ta_ctx *ctx,
				     struct tee_storage_enum *e)
{
	int ret;

	if (e == NULL || ctx == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	TAILQ_REMOVE(&ctx->storage_enums, e, link);

	ret = tee_file_ops.closedir(e->dir);
	e->dir = NULL;

	free(e);

	if (ret != 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}

char *tee_svc_storage_create_filename(struct tee_ta_session *sess,
				      void *object_id,
				      uint32_t object_id_len,
				      bool transient)
{
	uint8_t *file = NULL;
	/* +1 for the '/' (default) */
	uint32_t hslen =
	    TEE_B2HS_HSBUF_SIZE(sizeof(TEE_UUID) + object_id_len) + 1;
	uint32_t pos;

	/* +1 for the '.' (temporary persistent object) */
	if (transient)
		hslen++;

	file = malloc(hslen);

	if (file == NULL)
		return NULL;

	pos = tee_b2hs((uint8_t *)&sess->ctx->uuid, file,
		       sizeof(TEE_UUID), hslen);
	file[pos] = '/';
	pos++;

	/* temporary persistent object : uuid/.object_id_len_of(object_id) */
	if (transient) {
		file[pos] = '.';
		pos++;
	}

	tee_b2hs(object_id, file + pos, object_id_len, hslen - pos);

	return (char *)file;
}

char *tee_svc_storage_create_dirname(struct tee_ta_session *sess)
{
	uint8_t *dir = NULL;
	uint32_t hslen = TEE_B2HS_HSBUF_SIZE(sizeof(TEE_UUID));

	dir = malloc(hslen);

	if (dir == NULL)
		return NULL;

	tee_b2hs((uint8_t *)&sess->ctx->uuid, dir, sizeof(TEE_UUID),
		 hslen);

	return (char *)dir;
}

static TEE_Result tee_svc_storage_remove_corrupt_obj(
					struct tee_ta_session *sess,
					struct tee_obj *o)
{
	TEE_Result res;
	char *file = NULL;
	char *dir = NULL;

	file = tee_svc_storage_create_filename(sess,
					       o->pobj->obj_id,
					       o->pobj->obj_id_len,
					       false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	tee_obj_close(sess->ctx, o);
	tee_file_ops.unlink(file);
	free(file);
	dir = tee_svc_storage_create_dirname(sess);
	if (dir != NULL) {
		tee_file_ops.rmdir(dir);
		free(dir);
	}

	res = TEE_SUCCESS;

exit:
	return res;
}

static uint32_t tee_svc_storage_conv_oflags(uint32_t flags)
{
	uint32_t out = 0;

	if (flags & (TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ)) {
		if (flags & (TEE_DATA_FLAG_ACCESS_WRITE |
			     TEE_DATA_FLAG_ACCESS_WRITE_META |
			     TEE_DATA_FLAG_SHARE_WRITE))
			out |= TEE_FS_O_RDWR;
		else
			out |= TEE_FS_O_RDONLY;
	} else {
		if (flags & (TEE_DATA_FLAG_ACCESS_WRITE |
			     TEE_DATA_FLAG_ACCESS_WRITE_META |
			     TEE_DATA_FLAG_SHARE_WRITE))
			out |= TEE_FS_O_WRONLY;
	}

	return out;
}

static int tee_svc_storage_conv_whence(TEE_Whence whence)
{
	switch (whence) {
	case TEE_DATA_SEEK_SET:
		return TEE_FS_SEEK_SET;
	case TEE_DATA_SEEK_CUR:
		return TEE_FS_SEEK_CUR;
	case TEE_DATA_SEEK_END:
		return TEE_FS_SEEK_END;
	default:
		return -1;
	}
}

static TEE_Result tee_svc_storage_create_file(struct tee_ta_session *sess,
					      char *file, int *fd)
{
	TEE_Result res = TEE_SUCCESS;
	char *dir = NULL;
	int tmp;
	int err;
	uint32_t cflags = TEE_FS_O_WRONLY |
			TEE_FS_O_CREATE | TEE_FS_O_TRUNC;

	dir = tee_svc_storage_create_dirname(sess);
	if (dir == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	/* try and make directory */
	err = tee_file_ops.access(dir, TEE_FS_F_OK);
	if (err) {
		/* directory does not exists */
		tmp = tee_file_ops.mkdir(dir, TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);

		if (tmp < 0) {
			/* error codes needs better granularity */
			res = TEE_ERROR_GENERIC;
			goto exit;
		}
	}

	/* try and open again */
	*fd = tee_file_ops.open(&res, file, cflags);

exit:
	free(dir);

	return res;
}

static TEE_Result tee_svc_storage_read_head(struct tee_ta_session *sess,
				     struct tee_obj *o)
{
	TEE_Result res = TEE_SUCCESS;
	int fd = -1;
	int err;
	struct tee_svc_storage_head head;
	char *file = NULL;

	if (o == NULL || o->pobj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	file = tee_svc_storage_create_filename(sess,
					       o->pobj->obj_id,
					       o->pobj->obj_id_len,
					       false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	fd = tee_file_ops.open(&res, file, TEE_FS_O_RDONLY);
	free(file);
	if (fd < 0)
		goto exit;

	/* read head */
	err = tee_file_ops.read(&res, fd, &head,
				sizeof(struct tee_svc_storage_head));
	if (err < 0) {
		if (res == TEE_ERROR_CORRUPT_OBJECT)
			EMSG("Head corrupt\n");
		goto exit;
	}

	if (err != sizeof(struct tee_svc_storage_head)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto exit;
	}

	o->data_size = head.meta_size;
	o->info.dataSize = head.ds_size;

	o->data = malloc(o->data_size);
	if (o->data == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	/* read meta */
	err = tee_file_ops.read(&res, fd, o->data, o->data_size);
	if (err != (int)o->data_size) {
		free(o->data);
		o->data = NULL;
	}

exit:
	if (fd >= 0)
		tee_file_ops.close(fd);

	return res;
}

static TEE_Result tee_svc_storage_init_file(struct tee_ta_session *sess,
					    struct tee_obj *o,
					    struct tee_obj *attr_o, void *data,
					    uint32_t len)
{
	TEE_Result res = TEE_SUCCESS;
	int fd = -1;
	int err = -1;
	struct tee_svc_storage_head head;
	char *tmpfile = NULL;

	if (o == NULL || o->pobj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	free(o->data);

	/* create temporary persistent object filename */
	tmpfile = tee_svc_storage_create_filename(sess,
						   o->pobj->obj_id,
						   o->pobj->obj_id_len,
						   true);

	if (tmpfile == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_svc_storage_create_file(sess, tmpfile, &fd);
	if (res != TEE_SUCCESS)
		goto exit;

	if (attr_o && attr_o->data_size) {
		o->data_size = attr_o->data_size;
		o->data = malloc(attr_o->data_size);
		if (o->data == NULL) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		memcpy(o->data, attr_o->data, attr_o->data_size);
		o->have_attrs = attr_o->have_attrs;
		o->info.objectUsage = attr_o->info.objectUsage;
		o->info.objectType = attr_o->info.objectType;
	} else {
		o->data = NULL;
		o->data_size = 0;
		o->have_attrs = 0;
		o->info.objectUsage = TEE_USAGE_DEFAULT;
		o->info.objectType = TEE_TYPE_DATA;
	}

	/* write head */
	head.magic = TEE_SVC_STORAGE_MAGIC;
	head.head_size = sizeof(struct tee_svc_storage_head);
	head.meta_size = o->data_size;
	head.ds_size = len;

	/* write head */
	err = tee_file_ops.write(&res, fd, &head,
			sizeof(struct tee_svc_storage_head));
	/* error codes needs better granularity */
	if (err != sizeof(struct tee_svc_storage_head))
		goto exit;

	/* write meta */
	err = tee_file_ops.write(&res, fd, o->data, o->data_size);
	if (err != (int)o->data_size)
		goto exit;

	/* write init data */
	o->info.dataSize = len;

	/* write data to fs if needed */
	if (data && len) {
		err = tee_file_ops.write(&res, fd, data, len);
		if (err != (int)len)
			goto exit;
	}

exit:
	free(tmpfile);
	tmpfile = NULL;
	if (fd != -1)
		tee_file_ops.close(fd);

	return res;
}

TEE_Result tee_svc_storage_obj_open(uint32_t storage_id, void *object_id,
				    uint32_t object_id_len, uint32_t flags,
				    uint32_t *obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	char *file = NULL;
	int fs_flags;
	int fd = -1;
	tee_fs_off_t off;
	tee_fs_off_t e_off;
	struct tee_pobj *po = NULL;
	int err = -1;

	if (storage_id != TEE_STORAGE_PRIVATE) {
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

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) object_id,
					  object_id_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, flags, &po);
	if (res != TEE_SUCCESS)
		goto err;

	fs_flags = tee_svc_storage_conv_oflags(flags);

	o = calloc(1, sizeof(*o));
	if (o == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->info.objectUsage = TEE_USAGE_DEFAULT;
	o->flags = flags;
	o->pobj = po;

	res = tee_svc_storage_read_head(sess, o);
	if (res != TEE_SUCCESS) {
		tee_obj_add(sess->ctx, o);
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt\n");
			res = tee_svc_storage_remove_corrupt_obj(sess, o);
			if (res != TEE_SUCCESS)
				goto exit;
			res = TEE_ERROR_CORRUPT_OBJECT;
			goto exit;
		}
		goto oclose;
	}

	file = tee_svc_storage_create_filename(sess, object_id,
					       object_id_len, false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	err = tee_file_ops.access(file, TEE_FS_F_OK);
	if (err) {
		/* file not found */
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
		goto err;
	}

	fd = tee_file_ops.open(&res, file, fs_flags);
	if (fd < 0) {
		goto err;
	}
	o->fd = fd;

	tee_obj_add(sess->ctx, o);

	res = tee_svc_copy_kaddr_to_user32(sess, obj, o);
	if (res != TEE_SUCCESS)
		goto oclose;

	e_off = sizeof(struct tee_svc_storage_head) + o->data_size;
	off = tee_file_ops.lseek(&res, fd, e_off, TEE_FS_SEEK_SET);
	if (off != e_off) {
		res = TEE_ERROR_NO_DATA;
		goto oclose;
	}

	goto exit;

oclose:
	tee_obj_close(sess->ctx, o);

err:
	if (res == TEE_ERROR_NO_DATA || res == TEE_ERROR_BAD_FORMAT)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_ERROR_CORRUPT_OBJECT)
		tee_file_ops.unlink(file);
	if (fd >= 0)
		tee_file_ops.close(fd);
	if (po)
		tee_pobj_release(po);

exit:
	free(file);
	file = NULL;
	return res;
}

TEE_Result tee_svc_storage_obj_create(uint32_t storage_id, void *object_id,
				      uint32_t object_id_len, uint32_t flags,
				      uint32_t attr, void *data, uint32_t len,
				      uint32_t *obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o = NULL;
	struct tee_obj *attr_o = NULL;
	char *file = NULL;
	int fd = -1;
	int fs_flags;
	tee_fs_off_t off;
	tee_fs_off_t e_off;
	struct tee_pobj *po = NULL;
	char *tmpfile = NULL;
	int err = -1;

	if (storage_id != TEE_STORAGE_PRIVATE)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (object_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) object_id,
					  object_id_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, flags, &po);
	if (res != TEE_SUCCESS)
		goto err;

	/* check rights of the provided buffer */
	if (data && len) {
		res = tee_mmu_check_access_rights(sess->ctx,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (tee_uaddr_t) data, len);

		if (res != TEE_SUCCESS)
			goto err;
	}

	o = calloc(1, sizeof(*o));
	if (o == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->flags = flags;
	o->pobj = po;

	if (attr != TEE_HANDLE_NULL) {
		/* init attributes  if provided */
		res = tee_obj_get(sess->ctx, attr, &attr_o);
		if (res != TEE_SUCCESS)
			goto err;
	}

	res = tee_svc_storage_init_file(sess, o, attr_o, data, len);
	if (res != TEE_SUCCESS)
		goto err;

	/* create persistent object filename */
	file = tee_svc_storage_create_filename(sess, object_id,
					       object_id_len, false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	err = tee_file_ops.access(file, TEE_FS_F_OK);
	if (!err) {
		/* file exists */
		if (!(flags & TEE_DATA_FLAG_OVERWRITE)) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto err;
		}
	}

	/* create temporary persistent object filename */
	tmpfile = tee_svc_storage_create_filename(sess, object_id,
						  object_id_len,
						  true);
	if (tmpfile == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* rename temporary persistent object filename */
	err = tee_file_ops.rename(tmpfile, file);
	if (err) {
		/* error codes needs better granularity */
		res = TEE_ERROR_GENERIC;
		goto rmfile;
	}

	fs_flags = tee_svc_storage_conv_oflags(flags);

	fd = tee_file_ops.open(&res, file, fs_flags);
	if (fd < 0) {
		goto err;
	}
	o->fd = fd;

	tee_obj_add(sess->ctx, o);

	res = tee_svc_copy_kaddr_to_user32(sess, obj, o);
	if (res != TEE_SUCCESS)
		goto oclose;

	e_off = sizeof(struct tee_svc_storage_head) + o->data_size;
	off = tee_file_ops.lseek(&res, fd, e_off, TEE_FS_SEEK_SET);
	if (off != e_off) {
		res = TEE_ERROR_NO_DATA;
		goto oclose;
	}

	goto exit;

oclose:
	tee_obj_close(sess->ctx, o);
	goto exit;

rmfile:
	tee_file_ops.unlink(tmpfile);

err:
	if (res == TEE_ERROR_NO_DATA || res == TEE_ERROR_BAD_FORMAT)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_ERROR_CORRUPT_OBJECT)
		tee_file_ops.unlink(file);
	if (fd >= 0)
		tee_file_ops.close(fd);
	if (po)
		tee_pobj_release(po);
	if (o)
		free(o);

exit:
	free(file);
	file = NULL;
	free(tmpfile);
	tmpfile = NULL;

	return res;
}

TEE_Result tee_svc_storage_obj_del(uint32_t obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int err;
	char *file;
	char *dir;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		return res;

	if (!(o->flags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		return TEE_ERROR_ACCESS_CONFLICT;

	if (o->pobj == NULL || o->pobj->obj_id == NULL)
		return TEE_ERROR_BAD_STATE;

	file = tee_svc_storage_create_filename(sess, o->pobj->obj_id,
						o->pobj->obj_id_len, false);
	if (file == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	tee_obj_close(sess->ctx, o);

	err = tee_file_ops.access(file, TEE_FS_F_OK);
	if (err)
		/* file not found */
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;

	err = tee_file_ops.unlink(file);
	free(file);
	if (err)
		/* error codes needs better granularity */
		return TEE_ERROR_GENERIC;

	/* try and remove dir */
	dir = tee_svc_storage_create_dirname(sess);
	if (dir == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	/* ignore result */
	tee_file_ops.rmdir(dir);
	free(dir);

	return TEE_SUCCESS;
}

TEE_Result tee_svc_storage_obj_rename(uint32_t obj, void *object_id,
				      uint32_t object_id_len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	struct tee_pobj *po = NULL;
	char *new_file = NULL;
	char *old_file = NULL;
	int err = -1;

	if (object_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_obj_get(sess->ctx, obj, &o);
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

	res = tee_mmu_check_access_rights(sess->ctx,
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t) object_id, object_id_len);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	/* get new ds name */
	new_file = tee_svc_storage_create_filename(sess, object_id,
						   object_id_len, false);
	if (new_file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	old_file = tee_svc_storage_create_filename(sess, o->pobj->obj_id,
						   o->pobj->obj_id_len, false);
	if (old_file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	/* reserve dest name */
	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META, &po);
	if (res != TEE_SUCCESS)
		goto exit;

	err = tee_file_ops.access(new_file, TEE_FS_F_OK);
	if (err == 0) {
		/* file exists */
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	/* move */
	err = tee_file_ops.rename(old_file, new_file);
	if (err) {
		/* error codes needs better granularity */
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	res = tee_pobj_rename(o->pobj, object_id, object_id_len);

exit:
	tee_pobj_release(po);

	free(new_file);
	free(old_file);

	return res;
}

TEE_Result tee_svc_storage_alloc_enum(uint32_t *obj_enum)
{
	struct tee_storage_enum *e;
	struct tee_ta_session *sess;
	TEE_Result res;

	if (!obj_enum) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	e = malloc(sizeof(struct tee_storage_enum));

	if (!e) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	e->dir = NULL;
	TAILQ_INSERT_TAIL(&sess->ctx->storage_enums, e, link);

	res = tee_svc_copy_kaddr_to_user32(sess, obj_enum, e);

exit:
	return res;
}

TEE_Result tee_svc_storage_free_enum(uint32_t obj_enum)
{
	struct tee_storage_enum *e;
	TEE_Result res;
	struct tee_ta_session *sess;

	if (obj_enum == TEE_HANDLE_NULL) {
		res = TEE_SUCCESS;
		goto exit;
	}

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_svc_storage_get_enum(sess->ctx, obj_enum, &e);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_svc_close_enum(sess->ctx, e);

exit:
	return res;
}

TEE_Result tee_svc_storage_reset_enum(uint32_t obj_enum)
{
	struct tee_storage_enum *e;
	int res;
	struct tee_ta_session *sess;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	if (obj_enum == TEE_HANDLE_NULL) {
		res = TEE_SUCCESS;
		goto exit;
	}

	res = tee_svc_storage_get_enum(sess->ctx, obj_enum, &e);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_file_ops.closedir(e->dir);
	e->dir = NULL;
	if (res) {
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

exit:
	return res;
}

static TEE_Result tee_svc_storage_set_enum(struct tee_obj *o, char *d_name)
{
	TEE_Result res;
	uint32_t blen;
	uint32_t hslen;

	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->info.objectUsage = TEE_USAGE_DEFAULT;

	hslen = strlen(d_name);
	blen = TEE_HS2B_BBUF_SIZE(hslen);
	o->pobj->obj_id = malloc(blen);
	if (!o->pobj->obj_id) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	tee_hs2b((uint8_t *)d_name, o->pobj->obj_id, hslen, blen);
	o->pobj->obj_id_len = blen;

	res = TEE_SUCCESS;

exit:
	return res;

}

static TEE_Result tee_svc_storage_verify_enum(struct tee_ta_session *sess,
					      struct tee_obj *o, char *d_name)
{
	TEE_Result res;

	/* allocate obj_id and set object */
	res = tee_svc_storage_set_enum(o, d_name);
	if (res != TEE_SUCCESS)
		goto exit;
	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;
	/* free obj_id */
	free(o->pobj->obj_id);

exit:
	return res;

}

TEE_Result tee_svc_storage_start_enum(uint32_t obj_enum, uint32_t storage_id)
{
	struct tee_storage_enum *e;
	char *dir;
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_fs_dirent *d = NULL;
	struct tee_obj *o = NULL;

	if (obj_enum == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_svc_storage_get_enum(sess->ctx, obj_enum, &e);
	if (res != TEE_SUCCESS)
		goto exit;

	if (storage_id != TEE_STORAGE_PRIVATE) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	dir = tee_svc_storage_create_dirname(sess);
	if (!dir) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	e->dir = tee_file_ops.opendir(dir);
	free(dir);

	if (!e->dir) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	/* verify object */
	o = calloc(1, sizeof(struct tee_obj));
	if (!o) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	o->pobj = calloc(1, sizeof(struct tee_pobj));
	if (!o->pobj) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	/* object enumeration loop */
	do {
		d = tee_file_ops.readdir(e->dir);
		if (d) {
			res = tee_svc_storage_verify_enum(sess, o, d->d_name);
			if (res != TEE_SUCCESS)
				goto exit;
			/* force obj_id to skip freeing at exit statement */
			o->pobj->obj_id = NULL;
		}
	} while (d);

	/* re-start */
	res = tee_file_ops.closedir(e->dir);
	e->dir = NULL;
	if (res) {
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	dir = tee_svc_storage_create_dirname(sess);
	if (!dir) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	e->dir = tee_file_ops.opendir(dir);
	free(dir);

exit:
	if (o) {
		if (o->pobj)
			free(o->pobj->obj_id);
		free(o->pobj);
		free(o->data);
	}
	free(o);

	return res;
}

TEE_Result tee_svc_storage_next_enum(uint32_t obj_enum, TEE_ObjectInfo *info,
				     void *obj_id, uint32_t *len)
{
	struct tee_storage_enum *e;
	struct tee_fs_dirent *d;
	TEE_Result res = TEE_SUCCESS;
	struct tee_ta_session *sess;
	struct tee_obj *o = NULL;

	if (obj_enum == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_svc_storage_get_enum(sess->ctx, obj_enum, &e);
	if (res != TEE_SUCCESS)
		goto exit;

	/* check rights of the provided buffers */
	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) info,
					  sizeof(TEE_ObjectInfo));
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_mmu_check_access_rights(sess->ctx,
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) obj_id,
					  TEE_OBJECT_ID_MAX_LEN);
	if (res != TEE_SUCCESS)
		goto exit;

	d = tee_file_ops.readdir(e->dir);
	if (!d) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	o = calloc(1, sizeof(struct tee_obj));
	if (!o) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	o->pobj = calloc(1, sizeof(struct tee_pobj));
	if (!o->pobj) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_svc_storage_set_enum(o, d->d_name);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_svc_storage_read_head(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	memcpy(info, &o->info, sizeof(TEE_ObjectInfo));
	memcpy(obj_id, o->pobj->obj_id, o->pobj->obj_id_len);

	res = tee_svc_copy_to_user(sess, len, &o->pobj->obj_id_len,
				   sizeof(uint32_t));

exit:
	if (o) {
		if (o->pobj)
			free(o->pobj->obj_id);
		free(o->pobj);
		free(o->data);
	}
	free(o);

	return res;
}

TEE_Result tee_svc_storage_obj_read(uint32_t obj, void *data, size_t len,
				    uint32_t *count)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int n_count;
	uint32_t u_count;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_get(sess->ctx, obj, &o);
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

	/* check rights of the provided buffer */
	res = tee_mmu_check_access_rights(sess->ctx,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t) data, len);
	if (res != TEE_SUCCESS)
		goto exit;

	n_count = tee_file_ops.read(&res, o->fd, data, len);
	if (n_count < 0) {
		EMSG("Error code=%x\n", (uint32_t)res);
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt\n");
			tee_svc_storage_remove_corrupt_obj(sess, o);
		}
		goto exit;
	}
	u_count = (uint32_t) ((n_count < 0) ? 0 : n_count);

	res = tee_svc_copy_to_user(sess, count, &u_count, sizeof(uint32_t));

	o->info.dataPosition += u_count;

	res = TEE_SUCCESS;

exit:
	return res;
}

TEE_Result tee_svc_storage_obj_write(uint32_t obj, void *data, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int err;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_get(sess->ctx, obj, &o);
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

	/* check rights of the provided buffer */
	res = tee_mmu_check_access_rights(sess->ctx,
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t) data, len);

	err = tee_file_ops.write(&res, o->fd, data, len);

	if (err != (int)len)
		goto exit;

	o->info.dataPosition += len;
	if (o->info.dataPosition > o->info.dataSize)
		o->info.dataSize = o->info.dataPosition;

	res = TEE_SUCCESS;
exit:
	return res;
}

TEE_Result tee_svc_storage_obj_trunc(uint32_t obj, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int err;
	tee_fs_off_t off;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_get(sess->ctx, obj, &o);
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

	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	off = sizeof(struct tee_svc_storage_head) + o->data_size;
	err = tee_file_ops.ftruncate(&res, o->fd, len + off);
	if (err) {
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt\n");
			res = tee_svc_storage_remove_corrupt_obj(sess, o);
			if (res != TEE_SUCCESS)
				goto exit;
			res = TEE_ERROR_CORRUPT_OBJECT;
			goto exit;
		} else
			res = TEE_ERROR_GENERIC;
	}

exit:
	return res;
}

TEE_Result tee_svc_storage_obj_seek(uint32_t obj, int32_t offset,
				    TEE_Whence whence)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int fw;
	tee_fs_off_t off;
	tee_fs_off_t e_off = 0;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_get(sess->ctx, obj, &o);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	fw = tee_svc_storage_conv_whence(whence);

	if (whence == TEE_DATA_SEEK_SET)
		e_off = sizeof(struct tee_svc_storage_head) + o->data_size;

	off = tee_file_ops.lseek(&res, o->fd, e_off + offset, fw);
	if (off > -1 && off >= e_off)
		o->info.dataPosition = off -
			(sizeof(struct tee_svc_storage_head) + o->data_size);
	else {
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	res = TEE_SUCCESS;

exit:
	return res;
}

void tee_svc_storage_close_all_enum(struct tee_ta_ctx *ctx)
{
	struct tee_storage_enum_head *eh = &ctx->storage_enums;

	/* disregard return value */
	while (!TAILQ_EMPTY(eh))
		tee_svc_close_enum(ctx, TAILQ_FIRST(eh));
}
