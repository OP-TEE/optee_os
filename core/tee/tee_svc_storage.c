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

#include <kernel/tee_ta_manager.h>
#include <kernel/tee_misc.h>
#include <mm/tee_mmu.h>
#include <tee/tee_fs.h>
#include <tee/tee_fs_defs.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc_storage.h>
#include <tee/tee_svc_cryp.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <trace.h>

/*
 * Returns the appropriate tee_file_operations for the specified storage ID.
 * The value TEE_STORAGE_PRIVATE will select the REE FS if available, otherwise
 * RPMB.
 */
static const struct tee_file_operations *file_ops(uint32_t storage_id)
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

/* SSF (Secure Storage File version 00 */
#define TEE_SVC_STORAGE_MAGIC 0x53534600;

/* Header of GP formated secure storage files */
struct tee_svc_storage_head {
	uint32_t magic;
	uint32_t head_size;
	uint32_t meta_size;
	uint32_t ds_size;
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
	int ret;

	if (e == NULL || utc == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	TAILQ_REMOVE(&utc->storage_enums, e, link);

	if (!e->fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	ret = e->fops->closedir(e->dir);
	e->dir = NULL;
	e->fops = NULL;

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
	const struct tee_file_operations *fops = o->pobj->fops;

	file = tee_svc_storage_create_filename(sess,
					       o->pobj->obj_id,
					       o->pobj->obj_id_len,
					       false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	tee_obj_close(to_user_ta_ctx(sess->ctx), o);
	fops->unlink(file);
	free(file);
	dir = tee_svc_storage_create_dirname(sess);
	if (dir != NULL) {
		fops->rmdir(dir);
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
			char *file,
			const struct tee_file_operations *fops,
			int *fd)
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
	err = fops->access(dir, TEE_FS_F_OK);
	if (err) {
		/* directory does not exists */
		tmp = fops->mkdir(dir, TEE_FS_S_IRUSR | TEE_FS_S_IWUSR);

		if (tmp < 0) {
			/* error codes needs better granularity */
			res = TEE_ERROR_GENERIC;
			goto exit;
		}
	}

	/* try and open again */
	*fd = fops->open(&res, file, cflags);

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
	const struct tee_file_operations *fops;
	void *attr = NULL;

	if (o == NULL || o->pobj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	fops = o->pobj->fops;

	file = tee_svc_storage_create_filename(sess,
					       o->pobj->obj_id,
					       o->pobj->obj_id_len,
					       false);
	if (file == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	fd = fops->open(&res, file, TEE_FS_O_RDONLY);
	free(file);
	if (fd < 0)
		goto exit;

	/* read head */
	err = fops->read(&res, fd, &head,
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

	res = tee_obj_set_type(o, head.objectType, head.maxKeySize);
	if (res != TEE_SUCCESS)
		goto exit;

	if (head.meta_size) {
		attr = malloc(head.meta_size);
		if (!attr) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto exit;
		}

		/* read meta */
		err = fops->read(&res, fd, attr, head.meta_size);
		if (err != (int)head.meta_size) {
			res = TEE_ERROR_CORRUPT_OBJECT;
			goto exit;
		}
	}

	res = tee_obj_attr_from_binary(o, attr, head.meta_size);
	if (res != TEE_SUCCESS)
		goto exit;

	o->info.dataSize = head.ds_size;
	o->info.keySize = head.keySize;
	o->info.objectUsage = head.objectUsage;
	o->info.objectType = head.objectType;
	o->have_attrs = head.have_attrs;

exit:
	free(attr);
	if (fd >= 0)
		fops->close(fd);

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
	const struct tee_file_operations *fops;
	void *attr = NULL;
	size_t attr_size = 0;

	if (o == NULL || o->pobj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	fops = o->pobj->fops;

	/* create temporary persistent object filename */
	tmpfile = tee_svc_storage_create_filename(sess,
						   o->pobj->obj_id,
						   o->pobj->obj_id_len,
						   true);

	if (tmpfile == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_svc_storage_create_file(sess, tmpfile, fops, &fd);
	if (res != TEE_SUCCESS)
		goto exit;

	if (attr_o) {
		res = tee_obj_set_type(o, attr_o->info.objectType,
				       attr_o->info.maxKeySize);
		if (res != TEE_SUCCESS)
			goto exit;
		res = tee_obj_attr_copy_from(o, attr_o);
		if (res != TEE_SUCCESS)
			goto exit;
		o->have_attrs = attr_o->have_attrs;
		o->info.objectUsage = attr_o->info.objectUsage;
		o->info.keySize = attr_o->info.keySize;
		res = tee_obj_attr_to_binary(o, NULL, &attr_size);
		if (res != TEE_SUCCESS)
			goto exit;
		if (attr_size) {
			attr = malloc(attr_size);
			if (!attr) {
				res = TEE_ERROR_OUT_OF_MEMORY;
				goto exit;
			}
			res = tee_obj_attr_to_binary(o, attr, &attr_size);
			if (res != TEE_SUCCESS)
				goto exit;
		}
	} else {
		res = tee_obj_set_type(o, TEE_TYPE_DATA, 0);
		if (res != TEE_SUCCESS)
			goto exit;
	}

	/* write head */
	head.magic = TEE_SVC_STORAGE_MAGIC;
	head.head_size = sizeof(struct tee_svc_storage_head);
	head.meta_size = attr_size;
	head.ds_size = len;
	head.keySize = o->info.keySize;
	head.maxKeySize = o->info.maxKeySize;
	head.objectUsage = o->info.objectUsage;
	head.objectType = o->info.objectType;
	head.have_attrs = o->have_attrs;

	/* write head */
	err = fops->write(&res, fd, &head,
			sizeof(struct tee_svc_storage_head));
	/* error codes needs better granularity */
	if (err != sizeof(struct tee_svc_storage_head))
		goto exit;

	/* write meta */
	err = fops->write(&res, fd, attr, attr_size);
	if (err != (int)attr_size)
		goto exit;

	/* write init data */
	o->info.dataSize = len;

	/* write data to fs if needed */
	if (data && len) {
		err = fops->write(&res, fd, data, len);
		if (err != (int)len)
			goto exit;
	}

exit:
	free(attr);
	free(tmpfile);
	tmpfile = NULL;
	if (fd != -1)
		fops->close(fd);

	return res;
}

TEE_Result syscall_storage_obj_open(unsigned long storage_id, void *object_id,
			size_t object_id_len, unsigned long flags,
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
	struct user_ta_ctx *utc;
	const struct tee_file_operations *fops = file_ops(storage_id);
	size_t attr_size;

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
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) object_id,
					  object_id_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, flags, fops, &po);
	if (res != TEE_SUCCESS)
		goto err;

	fs_flags = tee_svc_storage_conv_oflags(flags);

	o = tee_obj_alloc();
	if (o == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	o->info.handleFlags =
	    TEE_HANDLE_FLAG_PERSISTENT | TEE_HANDLE_FLAG_INITIALIZED;
	o->flags = flags;
	o->pobj = po;

	res = tee_svc_storage_read_head(sess, o);
	if (res != TEE_SUCCESS) {
		tee_obj_add(utc, o);
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

	err = fops->access(file, TEE_FS_F_OK);
	if (err) {
		/* file not found */
		res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
		goto err;
	}

	fd = fops->open(&res, file, fs_flags);
	if (fd < 0) {
		goto err;
	}
	o->fd = fd;

	tee_obj_add(utc, o);

	res = tee_svc_copy_kaddr_to_uref(obj, o);
	if (res != TEE_SUCCESS)
		goto oclose;

	res = tee_obj_attr_to_binary(o, NULL, &attr_size);
	if (res != TEE_SUCCESS && res)
		goto oclose;

	e_off = sizeof(struct tee_svc_storage_head) + attr_size;
	off = fops->lseek(&res, fd, e_off, TEE_FS_SEEK_SET);
	if (off != e_off) {
		res = TEE_ERROR_NO_DATA;
		goto oclose;
	}

	goto exit;

oclose:
	tee_obj_close(utc, o);

err:
	if (res == TEE_ERROR_NO_DATA || res == TEE_ERROR_BAD_FORMAT)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_ERROR_CORRUPT_OBJECT)
		fops->unlink(file);
	if (fd >= 0)
		fops->close(fd);
	if (po)
		tee_pobj_release(po);

exit:
	free(file);
	file = NULL;
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
	char *file = NULL;
	int fd = -1;
	int fs_flags;
	tee_fs_off_t off;
	tee_fs_off_t e_off;
	struct tee_pobj *po = NULL;
	char *tmpfile = NULL;
	int err = -1;
	int filedoesnotexist;
	struct user_ta_ctx *utc;
	const struct tee_file_operations *fops = file_ops(storage_id);
	size_t attr_size;

	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (object_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;
	utc = to_user_ta_ctx(sess->ctx);

	res = tee_mmu_check_access_rights(utc,
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (tee_uaddr_t) object_id,
					  object_id_len);
	if (res != TEE_SUCCESS)
		goto err;

	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, flags, fops, &po);
	if (res != TEE_SUCCESS)
		goto err;

	/* check rights of the provided buffer */
	if (data && len) {
		res = tee_mmu_check_access_rights(utc,
						  TEE_MEMORY_ACCESS_READ |
						  TEE_MEMORY_ACCESS_ANY_OWNER,
						  (tee_uaddr_t) data, len);

		if (res != TEE_SUCCESS)
			goto err;
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

	filedoesnotexist = fops->access(file, TEE_FS_F_OK);
	if (!filedoesnotexist) {
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

	/*
	 * remove the file if it exists, because rename does not perform
	 * this operation. Note that it delete and rename should be atomic,
	 * which is not the case currently.
	 * Fixme: unlink must be removed once rename() support prior deletion
	 * of the new file name when it already exists.
	 */
	if (!filedoesnotexist)
		fops->unlink(file);
	/* rename temporary persistent object filename */
	err = fops->rename(tmpfile, file);
	if (err) {
		/* error codes needs better granularity */
		res = TEE_ERROR_GENERIC;
		goto rmfile;
	}

	fs_flags = tee_svc_storage_conv_oflags(flags);

	fd = fops->open(&res, file, fs_flags);
	if (fd < 0) {
		goto err;
	}
	o->fd = fd;

	tee_obj_add(utc, o);

	res = tee_svc_copy_kaddr_to_uref(obj, o);
	if (res != TEE_SUCCESS)
		goto oclose;

	res = tee_obj_attr_to_binary(o, NULL, &attr_size);
	if (res != TEE_SUCCESS)
		goto oclose;

	e_off = sizeof(struct tee_svc_storage_head) + attr_size;
	off = fops->lseek(&res, fd, e_off, TEE_FS_SEEK_SET);
	if (off != e_off) {
		res = TEE_ERROR_NO_DATA;
		goto oclose;
	}

	goto exit;

oclose:
	tee_obj_close(utc, o);
	goto exit;

rmfile:
	fops->unlink(tmpfile);

err:
	if (res == TEE_ERROR_NO_DATA || res == TEE_ERROR_BAD_FORMAT)
		res = TEE_ERROR_CORRUPT_OBJECT;
	if (res == TEE_ERROR_CORRUPT_OBJECT)
		fops->unlink(file);
	if (fd >= 0)
		fops->close(fd);
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

TEE_Result syscall_storage_obj_del(unsigned long obj)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int err;
	char *file;
	char *dir;
	struct user_ta_ctx *utc;
	const struct tee_file_operations *fops;

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

	file = tee_svc_storage_create_filename(sess, o->pobj->obj_id,
						o->pobj->obj_id_len, false);
	if (file == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	fops = o->pobj->fops;
	tee_obj_close(utc, o);

	err = fops->access(file, TEE_FS_F_OK);
	if (err)
		/* file not found */
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;

	err = fops->unlink(file);
	free(file);
	if (err)
		/* error codes needs better granularity */
		return TEE_ERROR_GENERIC;

	/* try and remove dir */
	dir = tee_svc_storage_create_dirname(sess);
	if (dir == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	/* ignore result */
	fops->rmdir(dir);
	free(dir);

	return TEE_SUCCESS;
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
	int err = -1;
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
	fops = o->pobj->fops;
	res = tee_pobj_get((void *)&sess->ctx->uuid, object_id,
			   object_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META,
			   fops, &po);
	if (res != TEE_SUCCESS)
		goto exit;

	err = fops->access(new_file, TEE_FS_F_OK);
	if (err == 0) {
		/* file exists */
		res = TEE_ERROR_ACCESS_CONFLICT;
		goto exit;
	}

	/* move */
	err = fops->rename(old_file, new_file);
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

	res = e->fops->closedir(e->dir);
	e->dir = NULL;
	if (res != 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result tee_svc_storage_set_enum(char *d_name,
			const struct tee_file_operations *fops,
			struct tee_obj *o)
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
	o->pobj->fops = fops;

	res = TEE_SUCCESS;

exit:
	return res;

}

TEE_Result syscall_storage_start_enum(unsigned long obj_enum,
				      unsigned long storage_id)
{
	struct tee_storage_enum *e;
	char *dir;
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_fs_dirent *d = NULL;
	struct tee_obj *o = NULL;
	const struct tee_file_operations *fops = file_ops(storage_id);

	res = tee_ta_get_current_session(&sess);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_svc_storage_get_enum(to_user_ta_ctx(sess->ctx),
			tee_svc_uref_to_vaddr(obj_enum), &e);
	if (res != TEE_SUCCESS)
		return res;

	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	dir = tee_svc_storage_create_dirname(sess);
	if (dir == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	e->fops = fops;
	e->dir = fops->opendir(dir);
	free(dir);
	if (e->dir == NULL)
		/* error codes needs better granularity */
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* verify object */
	o = tee_obj_alloc();
	if (o == NULL) {
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
		d = fops->readdir(e->dir);
		if (d) {
			/* allocate obj_id and set object */
			res = tee_svc_storage_set_enum(d->d_name, fops, o);
			if (res != TEE_SUCCESS)
				goto exit;
			res = tee_obj_verify(sess, o);
			if (res != TEE_SUCCESS)
				goto exit;
			/* free obj_id for each iteration */
			free(o->pobj->obj_id);
			/* force obj_id to skip freeing at exit statement */
			o->pobj->obj_id = NULL;
		}
	} while (d);

	/* re-start */
	res = fops->closedir(e->dir);
	e->dir = NULL;
	if (res != 0) {
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	dir = tee_svc_storage_create_dirname(sess);
	if (dir == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	e->dir = fops->opendir(dir);
	free(dir);

exit:
	if (o) {
		if (o->pobj)
			free(o->pobj->obj_id);
		free(o->pobj);
		tee_obj_free(o);
	}

	return res;
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
					(tee_uaddr_t) info,
					sizeof(TEE_ObjectInfo));
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t) obj_id,
					TEE_OBJECT_ID_MAX_LEN);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!e->fops) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	d = e->fops->readdir(e->dir);
	if (d == NULL) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	o = tee_obj_alloc();
	if (o == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	o->pobj = calloc(1, sizeof(struct tee_pobj));
	if (!o->pobj) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	res = tee_svc_storage_set_enum(d->d_name, e->fops, o);
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

	l = o->pobj->obj_id_len;
	res = tee_svc_copy_to_user(len, &l, sizeof(*len));

exit:
	if (o) {
		if (o->pobj)
			free(o->pobj->obj_id);
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
	int n_count;
	uint64_t u_count;
	struct user_ta_ctx *utc;

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

	/* check rights of the provided buffer */
	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_WRITE |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t) data, len);
	if (res != TEE_SUCCESS)
		goto exit;

	n_count = o->pobj->fops->read(&res, o->fd, data, len);
	if (n_count < 0) {
		EMSG("Error code=%x\n", (uint32_t)res);
		if (res == TEE_ERROR_CORRUPT_OBJECT) {
			EMSG("Object corrupt\n");
			tee_svc_storage_remove_corrupt_obj(sess, o);
		}
		goto exit;
	}
	u_count = (uint64_t)((n_count < 0) ? 0 : n_count);

	res = tee_svc_copy_to_user(count, &u_count, sizeof(*count));

	o->info.dataPosition += u_count;

	res = TEE_SUCCESS;

exit:
	return res;
}

TEE_Result syscall_storage_obj_write(unsigned long obj, void *data, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int err;
	struct user_ta_ctx *utc;

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

	/* check rights of the provided buffer */
	res = tee_mmu_check_access_rights(utc,
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					(tee_uaddr_t) data, len);

	err = o->pobj->fops->write(&res, o->fd, data, len);

	if (err != (int)len)
		goto exit;

	o->info.dataPosition += len;
	if (o->info.dataPosition > o->info.dataSize)
		o->info.dataSize = o->info.dataPosition;

	res = TEE_SUCCESS;
exit:
	return res;
}

TEE_Result syscall_storage_obj_trunc(unsigned long obj, size_t len)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int err;
	tee_fs_off_t off;
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

	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_attr_to_binary(o, NULL, &attr_size);
	if (res != TEE_SUCCESS)
		goto exit;

	off = sizeof(struct tee_svc_storage_head) + attr_size;
	err = o->pobj->fops->ftruncate(&res, o->fd, len + off);
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

TEE_Result syscall_storage_obj_seek(unsigned long obj, long offset,
				    unsigned long whence)
{
	TEE_Result res;
	struct tee_ta_session *sess;
	struct tee_obj *o;
	int fw;
	tee_fs_off_t off;
	tee_fs_off_t e_off = 0;
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

	res = tee_obj_verify(sess, o);
	if (res != TEE_SUCCESS)
		goto exit;

	res = tee_obj_attr_to_binary(o, NULL, &attr_size);
	if (res != TEE_SUCCESS)
		goto exit;

	fw = tee_svc_storage_conv_whence(whence);

	if (whence == TEE_DATA_SEEK_SET)
		e_off = sizeof(struct tee_svc_storage_head) + attr_size;

	off = o->pobj->fops->lseek(&res, o->fd, e_off + offset, fw);
	if (off > -1 && off >= e_off)
		o->info.dataPosition = off -
			(sizeof(struct tee_svc_storage_head) + attr_size);
	else {
		res = TEE_ERROR_GENERIC;
		goto exit;
	}

	res = TEE_SUCCESS;

exit:
	return res;
}

void tee_svc_storage_close_all_enum(struct user_ta_ctx *utc)
{
	struct tee_storage_enum_head *eh = &utc->storage_enums;

	/* disregard return value */
	while (!TAILQ_EMPTY(eh))
		tee_svc_close_enum(utc, TAILQ_FIRST(eh));
}
