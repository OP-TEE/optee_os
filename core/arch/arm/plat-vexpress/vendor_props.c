// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited.
 */

#include <kernel/tee_common_otp.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/user_access.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_svc.h>
#include <user_ta_header.h>
#include <util.h>

/*
 * The data to hash is 48 bytes made up of:
 * - 16 bytes: the UUID of the calling TA.
 * - 32 bytes: the hardware device ID
 * The resulting endorsement seed is 32 bytes.
 *
 * The output buffer is the "binary" struct defined in
 * the "prop_value" union and therefore comprises:
 * -  4 bytes: the size of the binary value data (32)
 * - 32 bytes: the binary value data (endorsement seed)
 *
 * Note that this code assumes an endorsement seed
 * size == device ID size for convenience.
 */
static TEE_Result get_prop_endorsement(struct ts_session *sess,
				       void *buf, size_t *blen)
{
	TEE_Result res;
	uint32_t ta_endorsement_seed_size = 32;
	uint8_t data[sizeof(TEE_UUID) + ta_endorsement_seed_size];
	uint32_t bin[1 + ta_endorsement_seed_size / sizeof(uint32_t)];
	uint32_t *bin_len = (uint32_t *)bin;
	uint8_t *bin_val = (uint8_t *)(&bin[1]);

	if (*blen < sizeof(bin)) {
		*blen = sizeof(bin);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(bin);

	memcpy(data, &sess->ctx->uuid, sizeof(TEE_UUID));

	if (tee_otp_get_die_id(&data[sizeof(TEE_UUID)],
			       ta_endorsement_seed_size))
		return TEE_ERROR_BAD_STATE;

	res = tee_hash_createdigest(TEE_ALG_SHA256, data, sizeof(data),
				    bin_val, ta_endorsement_seed_size);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	*bin_len = ta_endorsement_seed_size;

	return copy_to_user(buf, bin, sizeof(bin));
}

static const struct tee_props vendor_propset_array_tee[] = {
	{
		.name = "com.microsoft.ta.endorsementSeed",
		.prop_type = USER_TA_PROP_TYPE_BINARY_BLOCK,
		.get_prop_func = get_prop_endorsement
	},
};

const struct tee_vendor_props vendor_props_tee = {
	.props = vendor_propset_array_tee,
	.len = ARRAY_SIZE(vendor_propset_array_tee),
};
