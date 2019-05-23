/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2019, Linaro Limited
 */
#ifndef __KERNEL_USER_TA_STORE_H
#define __KERNEL_USER_TA_STORE_H

#include <tee_api_types.h>

struct user_ta_store_handle;
struct user_ta_store_ops {
	/*
	 * Human-readable string to describe where the TA comes from.
	 * For debug purposes only.
	 */
	const char *description;
	/*
	 * Open a TA. Does not guarantee that the TA is valid or even exists.
	 */
	TEE_Result (*open)(const TEE_UUID *uuid,
			   struct user_ta_store_handle **h);
	/*
	 * Return the size of the unencrypted TA binary, that is: the TA
	 * header (struct ta_head) plus the ELF data.
	 */
	TEE_Result (*get_size)(const struct user_ta_store_handle *h,
			       size_t *size);

	/*
	 * Return the tag or hash of the TA binary. Used to uniquely
	 * identify the binary also if the binary happens to be updated.
	 */
	TEE_Result (*get_tag)(const struct user_ta_store_handle *h,
			      uint8_t *tag, unsigned int *tag_len);
	/*
	 * Read the TA sequentially, from the start of the TA header (struct
	 * ta_head) up to the end of the ELF.
	 * The TEE core is expected to read *exactly* get_size() bytes in total
	 * unless an error occurs. Therefore, an implementation may rely on the
	 * condition (current offset == total size) to detect the last call to
	 * this function.
	 * @data: pointer to secure memory where the TA bytes should be copied.
	 * If @data == NULL and @len != 0, the function should just skip @len
	 * bytes.
	 */
	TEE_Result (*read)(struct user_ta_store_handle *h, void *data,
			   size_t len);
	/*
	 * Close a TA handle. Do nothing if @h == NULL.
	 */
	void (*close)(struct user_ta_store_handle *h);
};

#endif /*__KERNEL_USER_TA_STORE_H*/
