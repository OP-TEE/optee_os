// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <se050.h>
#include <se050_utils.h>
#include <string.h>

void crypto_storage_obj_del(uint8_t *data, size_t len)
{
	sss_status_t status = kStatus_SSS_Success;
	uint32_t val = SE050_KEY_WATERMARK;
	sss_se05x_object_t k_object = { };
	bool found = false;
	uint8_t *p = data;

	if (!p)
		return;

	while (len > sizeof(uint64_t) && !found) {
		if (memcmp(p, &val, sizeof(val)) != 0) {
			p++;
			len--;
			continue;
		}
		found = true;
	}

	if (!found)
		return;

	p = p - 4;
	memcpy((void *)&val, p, sizeof(val));

	if (val < OID_MIN || val > OID_MAX)
		return;

	status = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (status != kStatus_SSS_Success)
		return;

	status = sss_se05x_key_object_get_handle(&k_object, val);
	if (status != kStatus_SSS_Success)
		return;

	sss_se05x_key_store_erase_key(se050_kstore, &k_object);
}
