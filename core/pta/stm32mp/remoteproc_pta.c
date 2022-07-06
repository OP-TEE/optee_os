// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023, STMicroelectronics - All Rights Reserved
 */

#include <crypto/crypto.h>
#include <drivers/clk.h>
#include <drivers/rstctrl.h>
#include <drivers/stm32_remoteproc.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <drivers/stm32mp1_rcc.h>
#include <initcall.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <remoteproc_pta.h>
#include <string.h>

#include "rproc_pub_key.h"

#define PTA_NAME	"remoteproc.pta"

/*
 * UUID of the remoteproc Trusted application authorized to communicate with
 * the remoteproc pseudo TA. The UID should match the one defined in the
 * ta_remoteproc.h header file.
 */
#define TA_REMOTEPROC_UUID \
	{ 0x80a4c275, 0x0a47, 0x4905, \
		{ 0x82, 0x85, 0x14, 0x86, 0xa9, 0x77, 0x1a, 0x08} }

/*
 * Firmware states
 * REMOTEPROC_OFF: firmware is off
 * REMOTEPROC_ON: firmware is running
 */
enum rproc_load_state {
	REMOTEPROC_OFF = 0,
	REMOTEPROC_ON,
};

/* Currently supporting a single remote processor instance */
static enum rproc_load_state rproc_ta_state = REMOTEPROC_OFF;

static TEE_Result rproc_pta_capabilities(uint32_t pt,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!stm32_rproc_get(params[0].value.a))
		return TEE_ERROR_NOT_SUPPORTED;

	/* Support only ELF format */
	params[1].value.a = PTA_RPROC_HWCAP_FMT_ELF;

	/*
	 * Due to stm32mp1 pager, secure memory is too expensive. Support hash
	 * protected image only, so that firmware image can be loaded from
	 * non-secure memory.
	 */
	params[2].value.a = PTA_RPROC_HWCAP_PROT_HASH_TABLE;

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_load_segment(uint32_t pt,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t pa = 0;
	void *dst = NULL;
	uint8_t *src = params[1].memref.buffer;
	size_t size = params[1].memref.size;
	uint8_t *hash = params[3].memref.buffer;
	paddr_t da = (paddr_t)reg_pair_to_64(params[2].value.b,
					     params[2].value.a);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hash || params[3].memref.size != TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	/* Get the physical address in local context mapping */
	res = stm32_rproc_da_to_pa(params[0].value.a, da, size, &pa);
	if (res)
		return res;

	if (stm32_rproc_map(params[0].value.a, pa, size, &dst)) {
		EMSG("Can't map region %#"PRIxPA" size %zu", pa, size);
		return TEE_ERROR_GENERIC;
	}

	/* Copy the segment to the remote processor memory */
	memcpy(dst, src, size);

	/* Verify that loaded segment is valid */
	res = hash_sha256_check(hash, dst, size);
	if (res)
		memset(dst, 0, size);

	stm32_rproc_unmap(params[0].value.a, dst, size);

	return res;
}

static TEE_Result rproc_pta_set_memory(uint32_t pt,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t pa = 0;
	void *dst = NULL;
	paddr_t da = params[1].value.a;
	size_t size = params[2].value.a;
	uint8_t value = params[3].value.a && 0xFF;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	/* Get the physical address in CPU mapping */
	res = stm32_rproc_da_to_pa(params[0].value.a, da, size, &pa);
	if (res)
		return res;

	res = stm32_rproc_map(params[0].value.a, pa, size, &dst);
	if (res) {
		EMSG("Can't map region %#"PRIxPA" size %zu", pa, size);
		return TEE_ERROR_GENERIC;
	}

	memset(dst, value, size);

	return stm32_rproc_unmap(params[0].value.a, dst, size);
}

static TEE_Result rproc_pta_da_to_pa(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t da = params[1].value.a;
	size_t size = params[2].value.a;
	paddr_t pa = 0;

	DMSG("Conversion for address %#"PRIxPA" size %zu", da, size);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Target address is expected 32bit, ensure 32bit MSB are zero */
	if (params[1].value.b || params[2].value.b)
		return TEE_ERROR_BAD_PARAMETERS;

	res = stm32_rproc_da_to_pa(params[0].value.a, da, size, &pa);
	if (res)
		return res;

	reg_pair_from_64((uint64_t)pa, &params[3].value.b, &params[3].value.a);

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_start(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	res = stm32_rproc_start(params[0].value.a);
	if (res)
		return res;

	rproc_ta_state = REMOTEPROC_ON;

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_stop(uint32_t pt,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (rproc_ta_state != REMOTEPROC_ON)
		return TEE_ERROR_BAD_STATE;

	res = stm32_rproc_stop(params[0].value.a);
	if (res)
		return res;

	rproc_ta_state = REMOTEPROC_OFF;

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_verify_rsa_signature(TEE_Param *hash,
						 TEE_Param *sig, uint32_t algo)
{
	struct rsa_public_key key = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(rproc_pub_key_exponent);
	size_t hash_size = (size_t)hash->memref.size;
	size_t sig_size = (size_t)sig->memref.size;

	res = crypto_acipher_alloc_rsa_public_key(&key, sig_size);
	if (res)
		return res;

	res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res)
		goto out;

	res = crypto_bignum_bin2bn(rproc_pub_key_modulus,
				   rproc_pub_key_modulus_size, key.n);
	if (res)
		goto out;

	res = crypto_acipher_rsassa_verify(algo, &key, hash_size,
					   hash->memref.buffer, hash_size,
					   sig->memref.buffer, sig_size);

out:
	crypto_acipher_free_rsa_public_key(&key);

	return res;
}

static TEE_Result rproc_pta_verify_digest(uint32_t pt,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	struct rproc_pta_key_info *keyinfo = NULL;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!stm32_rproc_get(params[0].value.a))
		return TEE_ERROR_NOT_SUPPORTED;

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	keyinfo = params[1].memref.buffer;

	if (!keyinfo ||
	    rproc_pta_keyinfo_size(keyinfo) != params[1].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (keyinfo->algo != TEE_ALG_RSASSA_PKCS1_V1_5_SHA256)
		return TEE_ERROR_NOT_SUPPORTED;

	return rproc_pta_verify_rsa_signature(&params[2], &params[3],
					      keyinfo->algo);
}

static TEE_Result rproc_pta_invoke_command(void *session __unused,
					   uint32_t cmd_id,
					   uint32_t param_types,
					   TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_RPROC_HW_CAPABILITIES:
		return rproc_pta_capabilities(param_types, params);
	case PTA_RPROC_LOAD_SEGMENT_SHA256:
		return rproc_pta_load_segment(param_types, params);
	case PTA_RPROC_SET_MEMORY:
		return rproc_pta_set_memory(param_types, params);
	case PTA_RPROC_FIRMWARE_START:
		return rproc_pta_start(param_types, params);
	case PTA_RPROC_FIRMWARE_STOP:
		return rproc_pta_stop(param_types, params);
	case PTA_RPROC_FIRMWARE_DA_TO_PA:
		return rproc_pta_da_to_pa(param_types, params);
	case PTA_RPROC_VERIFY_DIGEST:
		return rproc_pta_verify_digest(param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

/*
 * Pseudo Trusted Application entry points
 */
static TEE_Result rproc_pta_open_session(uint32_t pt,
					 TEE_Param params[TEE_NUM_PARAMS],
					 void **sess_ctx __unused)
{
	struct ts_session *s = ts_get_calling_session();
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct ts_ctx *ctx = NULL;
	TEE_UUID ta_uuid = TA_REMOTEPROC_UUID;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	/* Check that we're called by the remoteproc Trusted application*/
	ctx = s->ctx;
	if (memcmp(&ctx->uuid, &ta_uuid, sizeof(TEE_UUID)))
		return TEE_ERROR_ACCESS_DENIED;

	if (!stm32_rproc_get(params[0].value.a))
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_RPROC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = rproc_pta_invoke_command,
		   .open_session_entry_point = rproc_pta_open_session);
