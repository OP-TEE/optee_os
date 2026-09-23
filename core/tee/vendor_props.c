// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2020, Linaro Limited.
 */

#include <kernel/huk_subkey.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/user_access.h>
#include <tee/tee_svc.h>
#include <user_ta_header.h>
#include <util.h>

#ifdef CFG_TEE_ENDORSEMENT_SEED
#define TA_ENDORSEMENT_SEED_SIZE	32

/*
 * The endorsement seed is a 32 byte subkey derived from the hardware unique
 * key, with the UUID of the calling TA as constant data so each TA gets a
 * distinct seed.
 *
 * The output buffer is the "binary" struct defined in
 * the "prop_value" union and therefore comprises:
 * -  4 bytes: the size of the binary value data (32)
 * - 32 bytes: the binary value data (endorsement seed)
 */
static TEE_Result get_prop_endorsement(struct ts_session *sess,
				       void *buf, size_t *blen)
{
	uint32_t bin[1 + TA_ENDORSEMENT_SEED_SIZE / sizeof(uint32_t)] = { };
	uint32_t *bin_len = (uint32_t *)bin;
	uint8_t *bin_val = (uint8_t *)(&bin[1]);

	if (*blen < sizeof(bin)) {
		*blen = sizeof(bin);
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = sizeof(bin);

	if (huk_subkey_derive(HUK_SUBKEY_TA_ENDORSEMENT, &sess->ctx->uuid,
			      sizeof(TEE_UUID), bin_val,
			      TA_ENDORSEMENT_SEED_SIZE))
		return TEE_ERROR_BAD_STATE;

	*bin_len = TA_ENDORSEMENT_SEED_SIZE;

	return copy_to_user(buf, bin, sizeof(bin));
}
#endif /*CFG_TEE_ENDORSEMENT_SEED*/

static const struct tee_props vendor_propset_array_tee[] = {
#ifdef CFG_TEE_ENDORSEMENT_SEED
	{
		.name = "com.microsoft.ta.endorsementSeed",
		.prop_type = USER_TA_PROP_TYPE_BINARY_BLOCK,
		.get_prop_func = get_prop_endorsement
	},
#endif
};

const struct tee_vendor_props vendor_props_tee = {
	.props = vendor_propset_array_tee,
	.len = ARRAY_SIZE(vendor_propset_array_tee),
};
