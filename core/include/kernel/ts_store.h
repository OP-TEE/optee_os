/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */
#ifndef __KERNEL_TS_STORE_H
#define __KERNEL_TS_STORE_H

#include <tee_api_types.h>

struct ts_store_handle;
struct ts_store_ops {
	/*
	 * Human-readable string to describe where the TS comes from.
	 * For debug purposes only.
	 */
	const char *description;
	/*
	 * Open a TS. Does not guarantee that the TS is valid or even exists.
	 */
	TEE_Result (*open)(const TEE_UUID *uuid,
			   struct ts_store_handle **h);
	/*
	 * Return the size of the unencrypted TS binary, that is: the TS
	 * header (struct ta_head or sp_head) plus the ELF data.
	 */
	TEE_Result (*get_size)(const struct ts_store_handle *h,
			       size_t *size);

	/*
	 * Return the tag or hash of the TS binary. Used to uniquely
	 * identify the binary also if the binary happens to be updated.
	 */
	TEE_Result (*get_tag)(const struct ts_store_handle *h,
			      uint8_t *tag, unsigned int *tag_len);
	/*
	 * Read the TS sequentially, from the start of the TS header (struct
	 * ta_head or sp_head) up to the end of the ELF.
	 * The TEE core is expected to read *exactly* get_size() bytes in total
	 * unless an error occurs. Therefore, an implementation may rely on the
	 * condition (current offset == total size) to detect the last call to
	 * this function.
	 * @data_core: pointer to secure memory where the TS bytes should be
	 *             copied.
	 * @data_user: pointer to user memory where the TS bytes should be
	 *             copied.
	 * At least one of @data_core and @data_user are normally NULL, but
	 * both are also permitted to be non-NULL.
	 * If @data_core == NULL and @data_user == NULL and @len != 0, the
	 * function should just skip @len bytes.
	 */
	TEE_Result (*read)(struct ts_store_handle *h, void *data_core,
			   void *data_user, size_t len);
	/*
	 * Close a TS handle. Do nothing if @h == NULL.
	 */
	void (*close)(struct ts_store_handle *h);
};

/*
 * Registers a TA storage.
 *
 * A TA is loaded from the first TA storage in which the TA can be found.
 * TA storage is searched in order of priority, where lower values are
 * tried first.
 *
 * Note prio must be unique per storage in order to avoid dependency on
 * registration order. This is enforced by a deliberate linker error in
 * case of conflict.
 *
 * Also note that TA storage is sorted lexicographically instead of
 * numerically.
 */
#define REGISTER_TA_STORE(prio) \
	int __tee_ta_store_##prio __unused; \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(ta_stores, prio, \
					       struct ts_store_ops)

/*
 * Registers a SP storage.
 *
 * The SP store is separate from the TA store. The user of the stores knows if
 * it needs to access the TA store or if it needs to access the SP one.
 */
#define REGISTER_SP_STORE(prio) \
	int __tee_sp_store_##prio __unused; \
	SCATTERED_ARRAY_DEFINE_PG_ITEM_ORDERED(sp_stores, prio, \
					       struct ts_store_ops)
#endif /*__KERNEL_TS_STORE_H*/
