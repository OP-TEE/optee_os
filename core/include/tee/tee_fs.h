/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_FS_H
#define TEE_FS_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define TEE_FS_NAME_MAX 350

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
			     const void *data, size_t data_size,
			     struct tee_file_handle **fh);
	void (*close)(struct tee_file_handle **fh);
	TEE_Result (*read)(struct tee_file_handle *fh, size_t pos,
			   void *buf, size_t *len);
	TEE_Result (*write)(struct tee_file_handle *fh, size_t pos,
			    const void *buf, size_t len);
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
#endif

#endif /*TEE_FS_H*/
