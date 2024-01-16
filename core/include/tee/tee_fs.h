/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __TEE_TEE_FS_H
#define __TEE_TEE_FS_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>

#define TEE_FS_NAME_MAX U(350)

typedef int64_t tee_fs_off_t;
typedef uint32_t tee_fs_mode_t;

struct tee_fs_dirent {
	uint8_t oid[TEE_OBJECT_ID_MAX_LEN];
	size_t oidlen;
};

struct tee_fs_dir;
struct tee_file_handle;
struct tee_pobj;

/*
 * tee_fs implements a POSIX like secure file system with GP extension
 */
struct tee_file_operations {
	TEE_Result (*open)(struct tee_pobj *po, size_t *size,
			   struct tee_file_handle **fh);
	TEE_Result (*create)(struct tee_pobj *po, bool overwrite,
			     const void *head, size_t head_size,
			     const void *attr, size_t attr_size,
			     const void *data_core, const void *data_user,
			     size_t data_size, struct tee_file_handle **fh);
	void (*close)(struct tee_file_handle **fh);
	TEE_Result (*read)(struct tee_file_handle *fh, size_t pos,
			   void *buf_core, void *buf_user, size_t *len);
	TEE_Result (*write)(struct tee_file_handle *fh, size_t pos,
			    const void *buf_core, const void *buf_user,
			    size_t len);
	TEE_Result (*rename)(struct tee_pobj *old_po, struct tee_pobj *new_po,
			     bool overwrite);
	TEE_Result (*remove)(struct tee_pobj *po);
	TEE_Result (*truncate)(struct tee_file_handle *fh, size_t size);

	TEE_Result (*opendir)(const TEE_UUID *uuid, struct tee_fs_dir **d);
	TEE_Result (*readdir)(struct tee_fs_dir *d, struct tee_fs_dirent **ent);
	void (*closedir)(struct tee_fs_dir *d);
};

#ifdef CFG_REE_FS
extern const struct tee_file_operations ree_fs_ops;
#endif
#ifdef CFG_RPMB_FS
extern const struct tee_file_operations rpmb_fs_ops;

TEE_Result tee_rpmb_fs_raw_open(const char *fname, bool create,
				struct tee_file_handle **fh);

/**
 * Weak function which can be overridden by platforms to indicate that the RPMB
 * key is ready to be written. Defaults to true, platforms can return false to
 * prevent a RPMB key write in the wrong state.
 */
bool plat_rpmb_key_is_ready(void);
#endif

/*
 * Returns the appropriate tee_file_operations for the specified storage ID.
 * The value TEE_STORAGE_PRIVATE will select the REE FS if available, otherwise
 * RPMB.
 */
static inline const struct tee_file_operations *
tee_svc_storage_file_ops(uint32_t storage_id)
{
	switch (storage_id) {
	case TEE_STORAGE_PRIVATE:
#if defined(CFG_REE_FS)
		return &ree_fs_ops;
#elif defined(CFG_RPMB_FS)
		return &rpmb_fs_ops;
#else
		return NULL;
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

#endif /*__TEE_TEE_FS_H*/
