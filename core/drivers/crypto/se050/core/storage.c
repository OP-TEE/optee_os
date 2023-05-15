// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <mm/core_mmu.h>
#include <se050.h>
#include <se050_utils.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_obj.h>
#include <tee/tee_pobj.h>

TEE_Result crypto_storage_obj_del(struct tee_obj *o)
{
	sss_status_t status = kStatus_SSS_Success;
	uint32_t val = SE050_KEY_WATERMARK;
	TEE_Result ret = TEE_ERROR_GENERIC;
	sss_se05x_object_t k_object = { };
	uint8_t *data = NULL;
	uint8_t *p = NULL;
	bool found = false;
	size_t len = 0;

	if (!o)
		return TEE_ERROR_BAD_PARAMETERS;

	len = o->info.dataSize;

	/* Supported keys (ECC/RSA) require less than 4KB of storage */
	if (len > SMALL_PAGE_SIZE || len <= sizeof(uint64_t))
		return TEE_SUCCESS;

	data = calloc(1, len);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Read the object into memory */
	ret = o->pobj->fops->read(o->fh, o->info.dataPosition, data, &len);
	if (ret) {
		EMSG("se05x: can not read the object prior removal");
		free(data);
		goto out;
	}

	/* Scan the object for the watermark */
	p = data;
	while (len >= sizeof(uint32_t) && !found) {
		if (memcmp(p, &val, sizeof(val)) != 0) {
			p++;
			len--;
			continue;
		}
		found = true;
	}

	if (!found) {
		free(data);
		return TEE_SUCCESS;
	}

	/* Retrieve the object identifier */
	p = p - 4;
	memcpy((void *)&val, p, sizeof(val));
	free(data);

	if (val < OID_MIN || val > OID_MAX)
		return TEE_SUCCESS;

	status = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (status != kStatus_SSS_Success) {
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}

	status = sss_se05x_key_object_get_handle(&k_object, val);
	if (status != kStatus_SSS_Success) {
		EMSG("se05x: can not communicate with the secure element");
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}

	status = sss_se05x_key_store_erase_key(se050_kstore, &k_object);
	if (status != kStatus_SSS_Success) {
		EMSG("se05x: can not communicate with the secure element");
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}

out:
	/*
	 * Users can delete the SE05X NVM objects during boot using a built
	 * time configuration flag (CFG_CORE_SE05X_INIT_NVM).
	 *
	 * This could cause the deletion of the secure storage objects holding
	 * references to those IDs via crypto_storage_obj_del() to fail, leaving
	 * broken links in the file system.
	 *
	 * Therefore we only permit this call to block the deletion upon an
	 * additional specific config.
	 */
	if (ret && IS_ENABLED(CFG_CORE_SE05X_BLOCK_OBJ_DEL_ON_ERROR))
		return ret;

	return TEE_SUCCESS;
}
