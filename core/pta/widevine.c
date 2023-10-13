// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, The ChromiumOS Authors
 */

#include <compiler.h>
#include <initcall.h>
#include <kernel/dt.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/ts_manager.h>
#include <kernel/user_ta.h>
#include <libfdt.h>
#include <pta_widevine.h>
#include <stdint.h>
#include <string.h>
#include <tee_api.h>
#include <util.h>

#define PTA_NAME "widevine.pta"

#define TPM_AUTH_PUB_MAX_SIZE 1024
#define WIDEVINE_PRIV_MAX_SIZE 32

#define CROS_HWSEC_TA_UUID                                             \
	{                                                              \
		0xed800e33, 0x3c58, 0x4cae,                            \
		{                                                      \
			0xa7, 0xc0, 0xfd, 0x16, 0x0e, 0x35, 0xe0, 0x0d \
		}                                                      \
	}
#define CROS_HDCP_PROV4_TA_UUID                                        \
	{                                                              \
		0x0feb839c, 0xee25, 0x4920,                            \
		{                                                      \
			0x8e, 0xe3, 0xac, 0x8d, 0xaa, 0x86, 0x0d, 0x3b \
		}                                                      \
	}
#define TA_OPTEE_OEMCRYPTO_UUID                                        \
	{                                                              \
		0xa92d116c, 0xce27, 0x4917,                            \
		{                                                      \
			0xb3, 0x0c, 0x4a, 0x41, 0x6e, 0x2d, 0x93, 0x51 \
		}                                                      \
	}

static const TEE_UUID allowed_ta_uuids[3] = {
	CROS_HWSEC_TA_UUID,
	CROS_HDCP_PROV4_TA_UUID,
	TA_OPTEE_OEMCRYPTO_UUID,
};

/*
 * The TPM auth public key. Used to communicate with the TPM from OP-TEE.
 * The format of data should be TPM2B_PUBLIC.
 * For more information, please reference the 12.2.5 section:
 * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
 */
static uint8_t tpm_auth_pub[TPM_AUTH_PUB_MAX_SIZE];
static uint32_t tpm_auth_pub_size;

/*
 * The Widevine root of trust secret. Used to sign the widevine
 * requests in OP-TEE. The value is an ECC NIST P-256 scalar.
 * For more information, please reference the G.1.2 section:
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
 */
static uint8_t widevine_priv[WIDEVINE_PRIV_MAX_SIZE];
static uint32_t widevine_priv_size;

static TEE_Result init_widevine_dt_data(void)
{
	int node = 0;
	int len = 0;
	void *fdt = NULL;
	const void *value = NULL;

	fdt = get_secure_dt();
	if (!fdt)
		return TEE_ERROR_NO_DATA;

	node = fdt_path_offset(fdt, "/options/op-tee/widevine");
	if (node < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	value = fdt_getprop(fdt, node, "tcg,tpm-auth-public-key", &len);
	if (!value)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len > TPM_AUTH_PUB_MAX_SIZE)
		return TEE_ERROR_OVERFLOW;

	memcpy(tpm_auth_pub, value, len);
	tpm_auth_pub_size = len;

	value = fdt_getprop(fdt, node, "google,widevine-root-of-trust-ecc-p256",
			    &len);
	if (!value)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (len > WIDEVINE_PRIV_MAX_SIZE)
		return TEE_ERROR_OVERFLOW;

	memcpy(widevine_priv, value, len);
	widevine_priv_size = len;

	return TEE_SUCCESS;
}

service_init(init_widevine_dt_data);

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	size_t i = 0;
	struct ts_session *session = ts_get_calling_session();

	/* Make sure we are called from a TA */
	if (!is_user_ta_ctx(session->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	/* Make sure we are called from an allowed TA */
	for (i = 0; i < ARRAY_SIZE(allowed_ta_uuids); i++)
		if (memcmp(&session->ctx->uuid, &allowed_ta_uuids[i],
			   sizeof(TEE_UUID)) == 0)
			return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result get_dt_data(uint32_t ptypes, TEE_Param params[TEE_NUM_PARAMS],
			      uint32_t cmd)
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	uint8_t *data = NULL;
	uint32_t data_length = 0;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (cmd == PTA_WIDEVINE_GET_TPM_PUBKEY) {
		data = tpm_auth_pub;
		data_length = tpm_auth_pub_size;
	} else if (cmd == PTA_WIDEVINE_GET_WIDEVINE_PRIVKEY) {
		data = widevine_priv;
		data_length = widevine_priv_size;
	} else {
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (data_length == 0)
		return TEE_ERROR_NO_DATA;

	if (data_length > params[0].memref.size) {
		params[0].memref.size = data_length;
		return TEE_ERROR_SHORT_BUFFER;
	}

	params[0].memref.size = data_length;
	memcpy(params[0].memref.buffer, data, data_length);

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */
static TEE_Result invoke_command(void *psess __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	return get_dt_data(ptypes, params, cmd);
}

pseudo_ta_register(.uuid = PTA_WIDEVINE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
