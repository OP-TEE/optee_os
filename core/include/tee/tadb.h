/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __TEE_TADB_H
#define __TEE_TADB_H

#include <tee/tee_fs.h>

struct tee_tadb_ta_write;
struct tee_tadb_ta_read;

/*
 * struct tee_tadb_property
 * @uuid:	UUID of Trusted Application (TA) or Security Domain (SD)
 * @version:	Version of TA or SD
 * @custom_size:Size of customized properties, prepended to the encrypted
 *		TA binary
 * @bin_size:	Size of the binary TA
 */
struct tee_tadb_property {
	TEE_UUID uuid;
	uint32_t version;
	uint32_t custom_size;
	uint32_t bin_size;
};

struct tee_fs_rpc_operation;

struct tee_tadb_file_operations {
	TEE_Result (*open)(uint32_t file_number, int *fd);
	TEE_Result (*create)(uint32_t file_number, int *fd);
	void (*close)(int fd);
	TEE_Result (*remove)(uint32_t file_number);

	TEE_Result (*read_init)(struct tee_fs_rpc_operation *op, int fd,
				size_t pos, uint8_t **data, size_t bytes);
	TEE_Result (*read_final)(struct tee_fs_rpc_operation *op,
				size_t *bytes);

	TEE_Result (*write_init)(struct tee_fs_rpc_operation *op, int fd,
				 size_t pos, uint8_t **data, size_t len);
	TEE_Result (*write_final)(struct tee_fs_rpc_operation *op);
};

TEE_Result tee_tadb_ta_create(const struct tee_tadb_property *property,
			      struct tee_tadb_ta_write **ta);
TEE_Result tee_tadb_ta_write(struct tee_tadb_ta_write *ta, const void *buf,
			     size_t len);
void tee_tadb_ta_close_and_delete(struct tee_tadb_ta_write *ta);
TEE_Result tee_tadb_ta_close_and_commit(struct tee_tadb_ta_write *ta);

TEE_Result tee_tadb_ta_delete(const TEE_UUID *uuid);

TEE_Result tee_tadb_ta_open(const TEE_UUID *uuid, struct tee_tadb_ta_read **ta);
const struct tee_tadb_property *
tee_tadb_ta_get_property(struct tee_tadb_ta_read *ta);
TEE_Result tee_tadb_get_tag(struct tee_tadb_ta_read *ta, uint8_t *tag,
			    unsigned int *tag_len);
TEE_Result tee_tadb_ta_read(struct tee_tadb_ta_read *ta, void *buf_core,
			    void *buf_user, size_t *len);
void tee_tadb_ta_close(struct tee_tadb_ta_read *ta);


#endif /*__TEE_TADB_H*/
