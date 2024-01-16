// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2023 NXP
 */

#include <assert.h>
#include <drivers/caam_extension.h>
#include <initcall.h>
#include <kernel/pseudo_ta.h>
#include <pta_imx_dek_blob.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>

#define PTA_NAME "dek_blob.pta"

/* Blob size padding in bytes */
#define BLOB_PAD_SIZE 48

/* HAB Blob header values */
#define HAB_HDR_TAG	 0x81
#define HAB_HDR_V4	 0x43
#define HAB_HDR_MODE_CCM 0x66
#define HAB_HDR_ALG_AES	 0x55

/*
 * DEK blobs are stored by the HAB in a secret key blob data structure. Notice
 * that the HAB supports a set of encryption algorithms, but the encrypted boot
 * protocol expects AES. The key length is a variable; it can be 128-bit,
 * 192-bit, or 256-bit.
 * For more info, see NXP application note AN12056
 */
struct dek_blob_header {
	uint8_t tag;	 /* Constant identifying HAB struct: 0x81 */
	uint8_t len_msb; /* Struct length in 8-bit msb */
	uint8_t len_lsb; /* Struct length in 8-bit lsb */
	uint8_t par;	 /* Constant value, HAB version: 0x43 */
	uint8_t mode;	 /* AES encryption CCM mode: 0x66 */
	uint8_t alg;	 /* AES encryption alg: 0x55 */
	uint8_t size;	 /* Unwrapped key value size in bytes */
	uint8_t flg;	 /* Key flags */
};

/*
 * Generate HAB DEK blob for encrypted boot
 *
 * payload	[in] Plain text key to encapsulate.
 * payload_size [in] Plain text key size. Must be 128, 192 or 256 bits.
 * blob		[out] DEK blob.
 * blob_size	[in/out] DEK blob size.
 */
static TEE_Result do_generate(const uint8_t *payload, size_t payload_size,
			      uint8_t *blob, size_t *blob_size)
{
	struct dek_blob_header *header = NULL;
	size_t expected_blob_size = 0;
	size_t dek_size = 0;

	/*
	 * Prevent against an unexpected padding of dek_blob_header structure
	 * that must remain packed. This structure will be seriailized to a
	 * buffer along the DEK blob.
	 */
	static_assert(sizeof(struct dek_blob_header) == 8 * sizeof(uint8_t));

	assert(payload && blob && payload_size && blob_size);
	assert(payload_size == (128 / 8) || payload_size == (192 / 8) ||
	       payload_size == (256 / 8));

	/*
	 * The DEK size is equals to input key size plus the required blob
	 * padding. The total output size is the DEK size plus its header
	 */
	dek_size = payload_size + BLOB_PAD_SIZE;
	expected_blob_size = sizeof(*header) + dek_size;

	/* Check that the output buffer has the required size */
	if (*blob_size < expected_blob_size) {
		*blob_size = expected_blob_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blob_size = expected_blob_size;

	/* Defined header */
	header = (struct dek_blob_header *)blob;
	header->tag = HAB_HDR_TAG;
	header->len_msb = 0;
	header->len_lsb = expected_blob_size;
	header->par = HAB_HDR_V4;
	header->mode = HAB_HDR_MODE_CCM;
	header->alg = HAB_HDR_ALG_AES;
	header->size = payload_size;
	header->flg = 0;

	/* Generate DEK */
	return caam_dek_generate(payload, payload_size, blob + sizeof(*header),
				 dek_size);
}

static TEE_Result cmd_dek_generate(uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size != (128 / 8) &&
	    params[0].memref.size != (192 / 8) &&
	    params[0].memref.size != (256 / 8))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(params[1].memref.buffer, 0, params[1].memref.size);

	return do_generate(params[0].memref.buffer, params[0].memref.size,
			   params[1].memref.buffer, &params[1].memref.size);
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_IMX_DEK_BLOB_CMD_GENERATE:
		return cmd_dek_generate(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_DEK_BLOB_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
