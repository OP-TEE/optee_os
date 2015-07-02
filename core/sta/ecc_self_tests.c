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
#include <util.h>
#include <malloc.h>
#include <string.h>

#define TA_NAME		"ecc_self_test.ta"

#define CMD_ECC_GEN_KEY_SELF_TESTS	0
#define CMD_ECC_DSA_TESTS		1
#define CMD_ECC_DH_TESTS		2

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

static TEE_Result ecc_get_size(uint32_t curve, uint32_t *key_size_bits)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*key_size_bits = 192;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*key_size_bits = 224;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*key_size_bits = 256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*key_size_bits = 384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*key_size_bits = 521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
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

	res = ecc_get_size(curve, &key_size_bits);
	if (res != TEE_SUCCESS)
		return res;

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

/* ecc_curve is part of TEE_ECC_CURVE_NIST_PXXX */
static TEE_Result ecc_generate_key_tests(uint32_t ecc_curve)
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
	res = ecc_generate_key_curve(&key1, &key2, ecc_curve);

	/* free the keys */
	crypto_ops.bignum.free(key1.x);
	crypto_ops.bignum.free(key1.y);
	crypto_ops.bignum.free(key1.d);
	crypto_ops.bignum.free(key2.x);
	crypto_ops.bignum.free(key2.y);
	crypto_ops.bignum.free(key2.d);
	return res;
}

static TEE_Result ecc_get_curve(uint32_t ecc_algo, uint32_t *ecc_curve)
{
	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */

	switch (ecc_algo) {
	case TEE_ALG_ECDSA_P192:
	case TEE_ALG_ECDH_P192:
		*ecc_curve = TEE_ECC_CURVE_NIST_P192;
		break;
	case TEE_ALG_ECDSA_P224:
	case TEE_ALG_ECDH_P224:
		*ecc_curve = TEE_ECC_CURVE_NIST_P224;
		break;
	case TEE_ALG_ECDSA_P256:
	case TEE_ALG_ECDH_P256:
		*ecc_curve = TEE_ECC_CURVE_NIST_P256;
		break;
	case TEE_ALG_ECDSA_P384:
	case TEE_ALG_ECDH_P384:
		*ecc_curve = TEE_ECC_CURVE_NIST_P384;
		break;
	case TEE_ALG_ECDSA_P521:
	case TEE_ALG_ECDH_P521:
		*ecc_curve = TEE_ECC_CURVE_NIST_P521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

/* ecc_algo is part of TEE_ALG_ECDSA_PXXX */
static TEE_Result ecc_dsa_tests(uint32_t ecc_algo)
{
	TEE_Result res;
	struct ecc_keypair key_private;
	struct ecc_public_key key_public;
	char msg[256];
	char msg_len;
	uint32_t key_size_bits;
	uint32_t key_size;
	uint8_t *pt_sig = 0;
	size_t sig_len;
	uint32_t ecc_curve = 0;

	/* create the private and public keys */
	res = crypto_ops.acipher.alloc_ecc_keypair(&key_private, 521);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_ops.acipher.alloc_ecc_keypair() FAILED");
		return res;
	}

	res = crypto_ops.acipher.alloc_ecc_public_key(&key_public, 521);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_ops.acipher.alloc_ecc_public_key() FAILED");
		goto error_freeprivate;
	}

	/* get the curve */
	res = ecc_get_curve(ecc_algo, &ecc_curve);
	if (res != TEE_SUCCESS) {
		EMSG("ecc_get_curve(%d) failed with 0x%x", ecc_curve, res);
		goto err;
	}

	/* create a random message */
	do {
		crypto_ops.prng.read(&msg_len, 1);

	} while (msg_len == 0);
	crypto_ops.prng.read(msg, msg_len);

	res = ecc_get_size(ecc_curve, &key_size_bits);
	if (res != TEE_SUCCESS)
		goto err;
	key_size = (key_size_bits + 7) / 8;

	/* create the private key */
	key_private.curve = ecc_curve;
	res = crypto_ops.acipher.gen_ecc_key(&key_private);
	if (res != TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		return res;
	}

	/* Populate public key */
	key_public.curve = key_private.curve;
	crypto_ops.bignum.copy(key_public.x, key_private.x);
	crypto_ops.bignum.copy(key_public.y, key_private.y);

	sig_len = 2 * key_size;
	pt_sig = malloc(sig_len);
	memset(pt_sig, 0, sig_len);
	res = crypto_ops.acipher.ecc_sign(ecc_algo, &key_private,
					  (const uint8_t *)msg, msg_len,
					  pt_sig, &sig_len);
	if (res != TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		goto err;
	}

	/* check signature is correct */
	res = crypto_ops.acipher.ecc_verify(ecc_algo, &key_public,
					    (const uint8_t *)msg, msg_len,
					    pt_sig, sig_len);
	if (res != TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		goto err;
	}

	/* check a wrong signature is not recognized */
	pt_sig[sig_len / 4] ^= 0xFF;
	res = crypto_ops.acipher.ecc_verify(ecc_algo, &key_public,
					    (const uint8_t *)msg, msg_len,
					    pt_sig, sig_len);
	pt_sig[sig_len / 4] ^= 0xFF;
	if (res == TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	/* check a wrong signature is not recognized */
	pt_sig[3 * sig_len / 4] ^= 0xFF;
	res = crypto_ops.acipher.ecc_verify(ecc_algo, &key_public,
					    (const uint8_t *)msg, msg_len,
					    pt_sig, sig_len);
	pt_sig[3 * sig_len / 4] ^= 0xFF;
	if (res == TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	/* check a wrong message is not recognized */
	msg[msg_len / 2] ^= 0xFF;
	res = crypto_ops.acipher.ecc_verify(ecc_algo, &key_public,
					    (const uint8_t *)msg, msg_len,
					    pt_sig, sig_len);
	msg[msg_len / 2] ^= 0xFF;
	if (res == TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	res = TEE_SUCCESS;
err:
	if (pt_sig)
		free(pt_sig);
	crypto_ops.bignum.free(key_public.x);
	crypto_ops.bignum.free(key_public.y);
error_freeprivate:
	crypto_ops.bignum.free(key_private.x);
	crypto_ops.bignum.free(key_private.y);
	crypto_ops.bignum.free(key_private.d);
	return res;
}

/*
 * Test vectors,
 * from http://csrc.nist.gov/groups/STM/cavp/documents/components/ecccdhtestvectors.zip
 */
struct testvector_ecdh_t {
	uint32_t algo;
	const char *QCAVSx;	/* public key x */
	const char *QCAVSy;	/* public key y */
	const char *dIUT;	/* private key */
	const char *ZIUT;	/* result */
};

struct testvector_ecdh_t testvector_ecdh[] = {
		{
			.algo = TEE_ALG_ECDH_P192,
			.QCAVSx = "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",
			.QCAVSy = "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523",
			.dIUT   = "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527",
			.ZIUT   = "803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0",
		},
		{
			.algo = TEE_ALG_ECDH_P224,
			.QCAVSx = "756dd806b9d9c34d899691ecb45b771af468ec004486a0fdd283411e",
			.QCAVSy = "4d02c2ca617bb2c5d9613f25dd72413d229fd2901513aa29504eeefb",
			.dIUT   = "5ad0dd6dbabb4f3c2ea5fe32e561b2ca55081486df2c7c15c9622b08",
			.ZIUT   = "3fcc01e34d4449da2a974b23fc36f9566754259d39149790cfa1ebd3",
		},
		{
			.algo = TEE_ALG_ECDH_P256,
			.QCAVSx = "a9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb",
			.QCAVSy = "f6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229",
			.dIUT   = "d8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8",
			.ZIUT   = "35aa9b52536a461bfde4e85fc756be928c7de97923f0416c7a3ac8f88b3d4489",
		},
		{
			.algo = TEE_ALG_ECDH_P384,
			.QCAVSx = "eb952e2d9ac0c20c6cc48fb225c2ad154f53c8750b003fd3b4ed8ed1dc0defac61bcdde02a2bcfee7067d75d342ed2b0",
			.QCAVSy = "f1828205baece82d1b267d0d7ff2f9c9e15b69a72df47058a97f3891005d1fb38858f5603de840e591dfa4f6e7d489e1",
			.dIUT   = "84ece6cc3429309bd5b23e959793ed2b111ec5cb43b6c18085fcaea9efa0685d98a6262ee0d330ee250bc8a67d0e733f",
			.ZIUT   = "ce7ba454d4412729a32bb833a2d1fd2ae612d4667c3a900e069214818613447df8c611de66da200db7c375cf913e4405",
		},
		{
			/*
			 * test vector has been updated by deleting extra
			 * zeros to match the key size
			 */
			.algo = TEE_ALG_ECDH_P521,
			.QCAVSx = "00fdd40d9e9d974027cb3bae682162eac1328ad61bc4353c45bf5afe76bf607d2894c8cce23695d920f2464fda4773d4693be4b3773584691bdb0329b7f4c86cc299",
			.QCAVSy = "0034ceac6a3fef1c3e1c494bfe8d872b183832219a7e14da414d4e3474573671ec19b033be831b915435905925b44947c592959945b4eb7c951c3b9c8cf52530ba23",
			.dIUT   = "00e548a79d8b05f923b9825d11b656f222e8cb98b0f89de1d317184dc5a698f7c71161ee7dc11cd31f4f4f8ae3a981e1a3e78bdebb97d7c204b9261b4ef92e0918e0",
			.ZIUT   = "00fbbcd0b8d05331fef6086f22a6cce4d35724ab7a2f49dd8458d0bfd57a0b8b70f246c17c4468c076874b0dff7a0336823b19e98bf1cec05e4beffb0591f97713c6",
		},
};

static unsigned char ecc_value(char c)
{
	if (('0' <= c) && (c <= '9'))
		return c - '0';
	if (('a' <= c) && (c <= 'f'))
		return c - 'a' + 10;
	if (('A' <= c) && (c <= 'F'))
		return c - 'A' + 10;
	return 0;
}

static void ecc_convert_binnumber(const char *string, char *binnumber,
				  int keysize_bytes)
{
	int i;

	for (i = 0; i < keysize_bytes; i++)
		binnumber[i] = (ecc_value(string[2*i]) << 4) +
			       (ecc_value(string[2*i + 1]));
}

/* ecc_algo is part of TEE_ALG_ECDSA_PXXX */
static TEE_Result ecc_dh_tests(uint32_t ecc_algo)
{
	TEE_Result res;
	struct ecc_keypair key_private;
	struct ecc_public_key key_public;
	uint32_t key_size_bits;
	uint32_t key_size;
	uint8_t *pt_sig = 0;
	unsigned long sig_len;
	uint32_t ecc_curve = 0;
	unsigned long i, n;
	char binnumber[256];

	for (n = 0; n < ARRAY_SIZE(testvector_ecdh); n++)
		if (testvector_ecdh[n].algo == ecc_algo)
			break;
	if (n == ARRAY_SIZE(testvector_ecdh))
		return TEE_ERROR_NOT_SUPPORTED;

	/* create the private and public keys */
	res = crypto_ops.acipher.alloc_ecc_keypair(&key_private, 521);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_ops.acipher.alloc_ecc_keypair() FAILED");
		return res;
	}

	res = crypto_ops.acipher.alloc_ecc_public_key(&key_public, 521);
	if (res != TEE_SUCCESS) {
		EMSG("crypto_ops.acipher.alloc_ecc_public_key() FAILED");
		goto error_freeprivate;
	}

	/* get the curve */
	res = ecc_get_curve(ecc_algo, &ecc_curve);
	if (res != TEE_SUCCESS) {
		EMSG("ecc_get_curve(%d) failed with 0x%x", ecc_curve, res);
		goto err;
	}

	res = ecc_get_size(ecc_curve, &key_size_bits);
	if (res != TEE_SUCCESS)
		goto err;
	key_size = (key_size_bits + 7) / 8;

	/* create the private key */
	key_private.curve = ecc_curve;
	ecc_convert_binnumber(testvector_ecdh[n].dIUT, binnumber, key_size);
	crypto_ops.bignum.bin2bn((unsigned char *)binnumber,
				 key_size, key_private.d);

	/* Populate public key */
	key_public.curve = key_private.curve;
	ecc_convert_binnumber(testvector_ecdh[n].QCAVSx, binnumber, key_size);
	crypto_ops.bignum.bin2bn((unsigned char *)binnumber,
				 key_size, key_public.x);
	ecc_convert_binnumber(testvector_ecdh[n].QCAVSy, binnumber, key_size);
	crypto_ops.bignum.bin2bn((unsigned char *)binnumber,
				 key_size, key_public.y);

	sig_len = key_size;
	pt_sig = malloc(sig_len);
	memset(pt_sig, 0, sig_len);
	res = crypto_ops.acipher.ecc_shared_secret(&key_private, &key_public,
						   pt_sig, &sig_len);
	if (res != TEE_SUCCESS) {
		EMSG("Error 0x%x - curve=%d", res, ecc_curve);
		goto err;
	}

	/* check signature is correct */
	ecc_convert_binnumber(testvector_ecdh[n].ZIUT, binnumber, key_size);
	for (i = 0; i < sig_len; i++)
		EMSG("PASCAL 0x%x  vs  0x%x", pt_sig[i], binnumber[i]);

	if (memcmp(pt_sig, binnumber, key_size) == 0)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_GENERIC;

err:
	if (pt_sig)
		free(pt_sig);
	crypto_ops.bignum.free(key_public.x);
	crypto_ops.bignum.free(key_public.y);
error_freeprivate:
	crypto_ops.bignum.free(key_private.x);
	crypto_ops.bignum.free(key_private.y);
	crypto_ops.bignum.free(key_private.d);
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
	case CMD_ECC_DSA_TESTS:
		return ecc_dsa_tests(pParams[0].value.a);
	case CMD_ECC_DH_TESTS:
		return ecc_dh_tests(pParams[0].value.a);
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
