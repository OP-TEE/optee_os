// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All rights reserved.
 *
 */

#include <assert.h>
#include <drivers/amd/asu_client.h>
#include <drivers/amd/asu_crypto_common.h>
#include <kernel/mutex.h>
#include <stdbool.h>
#include <tee_api_types.h>

/*
 * SHA2 and SHA3 engines each support one context at a time. Hash, HMAC, and
 * RSA padding (OAEP/PSS) all consume the same engines in ASUFW, so ownership
 * is tracked here in a location shared by the asu_driver crypto drivers
 * rather than in any single one of them.
 */
struct asu_shadev {
	bool sha2_available;
	bool sha3_available;
	struct mutex engine_lock; /* serializes SHA2/SHA3 engine claim */
};

static struct asu_shadev asu_shadev = {
	.sha2_available = true,
	.sha3_available = true,
	.engine_lock = MUTEX_INITIALIZER,
};

TEE_Result asu_shadev_acquire(uint8_t module)
{
	TEE_Result ret = TEE_SUCCESS;

	mutex_lock(&asu_shadev.engine_lock);
	if (module == ASU_MODULE_SHA2_ID && asu_shadev.sha2_available) {
		asu_shadev.sha2_available = false;
	} else if (module == ASU_MODULE_SHA3_ID && asu_shadev.sha3_available) {
		asu_shadev.sha3_available = false;
	} else {
		/* Engine busy; caller should fall back to software */
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}
	mutex_unlock(&asu_shadev.engine_lock);

	return ret;
}

void asu_shadev_release(uint8_t module)
{
	mutex_lock(&asu_shadev.engine_lock);
	if (module == ASU_MODULE_SHA2_ID) {
		assert(!asu_shadev.sha2_available);
		asu_shadev.sha2_available = true;
	} else if (module == ASU_MODULE_SHA3_ID) {
		assert(!asu_shadev.sha3_available);
		asu_shadev.sha3_available = true;
	}
	mutex_unlock(&asu_shadev.engine_lock);
}
