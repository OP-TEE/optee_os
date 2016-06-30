/*
 * Copyright (c) 2016, Linaro Limited.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <tee/tee_svc.h>
#include <user_ta_header.h>
#include <util.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_common_otp.h>
#include <tee/tee_cryp_utl.h>

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
static TEE_Result get_prop_endorsement(struct tee_ta_session *sess,
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

	return tee_svc_copy_to_user((void *)buf, bin, sizeof(bin));
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
