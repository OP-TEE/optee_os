/*
 * Copyright (c) 2015, STMicroelectronics International N.V.
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
#include <trace.h>
#include <tee/tee_cryp_provider.h>
#include <tee_api_defines.h>
#include <user_ta_header.h>

#define TA_NAME		"ecc_self_test.ta"

#define CMD_ECC_GEN_KEY_SELF_TESTS	0

#define ECC_SELF_TEST_UUID \
		{ 0xf34f4f3c, 0xab30, 0x4573,  \
		{ 0x91, 0xBF, 0x3C, 0x57, 0x02, 0x4D, 0x51, 0x99 } }

static TEE_Result create_ta(void)
{
	DMSG("create entry point for static ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for static ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
		TEE_Param pParams[4] __unused, void **ppSessionContext __unused)
{
	DMSG("open entry point for static ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for static ta \"%s\"", TA_NAME);
}

static TEE_Result ecc_check_size(struct bignum *n, uint32_t key_size_bits)
{
	uint32_t size = crypto_ops.bignum.num_bits(n);

	if ((size < key_size_bits-32) || (key_size_bits < size)) {
		EMSG("Generate keysize = %d, expected %d", size, key_size_bits);
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

static TEE_Result ecc_check_equal(struct bignum *p, struct bignum *q)
{
	if (crypto_ops.bignum.compare(p, q) == 0) {
		EMSG("Keys are equal");
		return TEE_ERROR_GENERIC;
	} else {
		return TEE_SUCCESS;
	}
}

static TEE_Result ecc_generate_key_curve(struct ecc_keypair *key1,
					 struct ecc_keypair *key2,
					 uint32_t curve)
{
	TEE_Result res;
	uint32_t key_size_bits;

	/* Generates 2 keys */
	key1->curve = curve;
	res = crypto_ops.acipher.gen_ecc_key(key1);
	if (res != TEE_SUCCESS) {
		if ((curve < TEE_ECC_CURVE_NIST_P192) ||
		    (curve > TEE_ECC_CURVE_NIST_P521)) {
			if (res != TEE_ERROR_NOT_SUPPORTED)
				EMSG("Error 0x%x", res);
		} else {
			EMSG("Error 0x%x - curve=%d", res, curve);
		}
		return res;
	}

	key2->curve = curve;
	res = crypto_ops.acipher.gen_ecc_key(key2);
	if (res != TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, curve);
		return res;
	}

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		key_size_bits = 192;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		key_size_bits = 224;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		key_size_bits = 256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		key_size_bits = 384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		key_size_bits = 521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Check the keys size */
	res = ecc_check_size(key1->x, key_size_bits);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_size(key1->y, key_size_bits);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_size(key1->d, key_size_bits);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_size(key2->x, key_size_bits);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_size(key2->y, key_size_bits);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_size(key2->d, key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

	/* Check the keys are not the same */
	res = ecc_check_equal(key1->x, key2->x);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_equal(key1->y, key2->y);
	if (res != TEE_SUCCESS)
		return res;
	res = ecc_check_equal(key1->d, key2->d);
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

/* ecc_algo is part of TEE_ECC_CURVE_NIST_PXXX */
static TEE_Result ecc_generate_key_tests(uint32_t ecc_algo)
{
	TEE_Result res;
	struct ecc_keypair key1;
	struct ecc_keypair key2;

	/* Allocate a keypair */
	res = crypto_ops.acipher.alloc_ecc_keypair(&key1, 521);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_ops.acipher.alloc_ecc_keypair() FAILED");
		return res;
	}

	res = crypto_ops.acipher.alloc_ecc_keypair(&key2, 521);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_ops.acipher.alloc_ecc_keypair() FAILED");
		crypto_ops.bignum.free(key1.x);
		crypto_ops.bignum.free(key1.y);
		crypto_ops.bignum.free(key1.d);
		return res;
	}

	/* Generates and check all the curves */
	res = ecc_generate_key_curve(&key1, &key2, ecc_algo);

	/* free the keys */
	crypto_ops.bignum.free(key1.x);
	crypto_ops.bignum.free(key1.y);
	crypto_ops.bignum.free(key1.d);
	crypto_ops.bignum.free(key2.x);
	crypto_ops.bignum.free(key2.y);
	crypto_ops.bignum.free(key2.d);
	return res;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
		uint32_t nCommandID,
		uint32_t nParamTypes __unused, TEE_Param pParams[4])
{
	DMSG("command entry point for static ta \"%s\"", TA_NAME);

	switch (nCommandID) {
	case CMD_ECC_GEN_KEY_SELF_TESTS:
		return ecc_generate_key_tests(pParams[0].value.a);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

__attribute__ ((section("ta_head_section")))
	const ta_static_head_t ecc_self_test_head = {

	.uuid = ECC_SELF_TEST_UUID,
	.name = (char *)TA_NAME,
	.create_entry_point = create_ta,
	.destroy_entry_point = destroy_ta,
	.open_session_entry_point = open_session,
	.close_session_entry_point = close_session,
	.invoke_command_entry_point = invoke_command,

};
