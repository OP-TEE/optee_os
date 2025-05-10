// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) ProvenRun SAS 2023.
 */

#include <config.h>
#include <crypto/crypto_impl.h>
#include <drivers/versal_trng.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <ecc.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <rng_support.h>
#include <stdint.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>

/* PKI Engine TRNG driver */
#define TRNG_BASE            UINT64_C(0x20400051000)
#define TRNG_SIZE            0x10000

static struct versal_trng ecc_pki_trng = {
	.cfg.base = TRNG_BASE,
	.cfg.len = TRNG_SIZE,
	.cfg.version = TRNG_V2,
};

static TEE_Result versal_ecc_trng_init(void)
{
	const uint8_t pers_str[TRNG_PERS_STR_LEN] = {
		0xB2, 0x80, 0x7E, 0x4C, 0xD0, 0xE4, 0xE2, 0xA9,
		0x2F, 0x1F, 0x5D, 0xC1, 0xA2, 0x1F, 0x40, 0xFC,
		0x1F, 0x24, 0x5D, 0x42, 0x61, 0x80, 0xE6, 0xE9,
		0x71, 0x05, 0x17, 0x5B, 0xAF, 0x70, 0x30, 0x18,
		0xBC, 0x23, 0x18, 0x15, 0xCB, 0xB8, 0xA6, 0x3E,
		0x83, 0xB8, 0x4A, 0xFE, 0x38, 0xFC, 0x25, 0x87,
	};

	/* configure in hybrid mode with derivative function enabled */
	struct trng_usr_cfg usr_cfg = {
		.mode = TRNG_HRNG,
		.seed_life = CFG_VERSAL_TRNG_SEED_LIFE,
		.predict_en = false,
		.df_disable = false,
		.dfmul = CFG_VERSAL_TRNG_DF_MUL,
		.iseed_en = false,
		.pstr_en = true,
	};

	memcpy(usr_cfg.pstr, pers_str, TRNG_PERS_STR_LEN);

	return versal_trng_hw_init(&ecc_pki_trng, &usr_cfg);
}

static TEE_Result versal_ecc_trng_get_random_bytes(void *buf, size_t len)
{
	return versal_trng_get_random_bytes(&ecc_pki_trng, buf, len);
}

#define FPD_PKI_CRYPTO_BASEADDR		UINT64_C(0x20400000000)
#define FPD_PKI_CTRLSTAT_BASEADDR	UINT64_C(0x20400050000)

#define FPD_PKI_SIZE			0x10000

#define PKI_ENGINE_GEN_CTRL_OFFSET	UINT64_C(0x00000000)
#define PKI_ENGINE_GEN_CTRL_TZ		0x100

#define PKI_ENGINE_CTRL_OFFSET		UINT64_C(0x00000C00)
#define PKI_ENGINE_CTRL_CM_MASK		0x1

#define PKI_CRYPTO_SOFT_RESET_OFFSET	UINT64_C(0x00000038)
#define PKI_CRYPTO_IRQ_STATUS_OFFSET	UINT64_C(0x00000088)
#define PKI_CRYPTO_IRQ_ENABLE_OFFSET	UINT64_C(0x00000090)
#define PKI_CRYPTO_IRQ_RESET_OFFSET	UINT64_C(0x000000A0)
#define PKI_RQ_CFG_PAGE_ADDR_IN_OFFSET	UINT64_C(0x00000100)
#define PKI_RQ_CFG_PAGE_ADDR_OUT_OFFSET	UINT64_C(0x00000108)
#define PKI_RQ_CFG_PAGE_SIZE_OFFSET	UINT64_C(0x00000120)
#define PKI_RQ_CFG_CQID_OFFSET		UINT64_C(0x00000128)
#define PKI_RQ_CFG_PERMISSIONS_OFFSET	UINT64_C(0x00000130)
#define PKI_RQ_CFG_QUEUE_DEPTH_OFFSET	UINT64_C(0x00000140)
#define PKI_CQ_CFG_ADDR_OFFSET		UINT64_C(0x00001100)
#define PKI_CQ_CFG_SIZE_OFFSET		UINT64_C(0x00001108)
#define PKI_CQ_CFG_IRQ_IDX_OFFSET	UINT64_C(0x00001110)
#define PKI_RQ_CTL_NEW_REQUEST_OFFSET	UINT64_C(0x00002000)
#define PKI_CQ_CTL_TRIGPOS_OFFSET	UINT64_C(0x00002028)

#define PKI_RQ_CFG_PERMISSIONS_SAFE	0x0
#define PKI_RQ_CFG_PAGE_SIZE_1024	0x10
#define PKI_RQ_CFG_CQID			0x0
#define	PKI_CQ_CFG_SIZE_4096		0xC
#define PKI_CQ_CFG_IRQ_ID_VAL		0x0
#define PKI_RQ_CFG_QUEUE_DEPTH_VAL	0x80
#define PKI_IRQ_ENABLE_VAL		0xFFFF
#define PKI_CQ_CTL_TRIGPOS_VAL		0x201

#define PKI_IRQ_DONE_STATUS_VAL		0x1

#define PKI_NEW_REQUEST_MASK		0x00000FFF

#define PKI_MAX_RETRY_COUNT		10000

#define PKI_QUEUE_BUF_SIZE		0x1000

struct versal_pki {
	vaddr_t regs;

	uint8_t *rq_in;
	uint8_t *rq_out;
	uint8_t *cq;
};

static struct versal_pki versal_pki;

/*
 * PKI Engine Descriptors
 */

#define PKI_DESC_LEN_BYTES		0x20

#define PKI_DESC_TAG_START		0x00000002
#define PKI_DESC_TAG_TFRI(sz)		((sz) << 16 | 0x0006)
#define PKI_DESC_TAG_TFRO(sz)		((sz) << 16 | 0x000E)
#define PKI_DESC_TAG_NTFY(id)		((id) << 16 | 0x0016)

#define PKI_DESC_OPTYPE_MOD_ADD		0x01
#define PKI_DESC_OPTYPE_ECC_POINTMUL	0x22
#define PKI_DESC_OPTYPE_ECDSA_SIGN	0x30
#define PKI_DESC_OPTYPE_ECDSA_VERIFY	0x31

#define PKI_DESC_ECC_FIELD_GFP		0x0

#define PKI_DESC_OPSIZE_P256		0x1F
#define PKI_DESC_OPSIZE_P384		0x2F
#define PKI_DESC_OPSIZE_P521		0x41

#define PKI_DESC_SELCURVE_P256		0x1
#define PKI_DESC_SELCURVE_P384		0x2
#define PKI_DESC_SELCURVE_P521		0x3

#define PKI_DESC_TAG_START_CMD(op, opsize, selcurve, field) \
	((op) | ((field) << 7) | ((opsize) << 8) | ((selcurve) << 20))

#define PKI_SIGN_INPUT_OP_COUNT		3
#define PKI_VERIFY_INPUT_OP_COUNT	5
#define PKI_MOD_ADD_INPUT_OP_COUNT	3
#define PKI_ECC_POINTMUL_INPUT_OP_COUNT	3

#define PKI_SIGN_OUTPUT_OP_COUNT		2
#define PKI_VERIFY_OUTPUT_OP_COUNT		0
#define PKI_MOD_ADD_OUTPUT_OP_COUNT		1
#define PKI_ECC_POINTMUL_OUTPUT_OP_COUNT	2

#define PKI_SIGN_P521_PADD_BYTES	2
#define PKI_VERIFY_P521_PADD_BYTES	6

#define PKI_DEFAULT_REQID		UINT16_C(0xB04EU)

#define PKI_EXPECTED_CQ_STATUS		0
#define PKI_EXPECTED_CQ_VALUE		(SHIFT_U32(PKI_DEFAULT_REQID, 16) | 0x1)

#define PKI_RESET_DELAY_US		10

static TEE_Result pki_get_opsize(uint32_t curve, uint32_t op, size_t *in_sz,
				 size_t *out_sz)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bits = 0;
	size_t bytes = 0;

	ret = versal_ecc_get_key_size(curve, &bytes, &bits);
	if (ret)
		return ret;

	switch (op) {
	case PKI_DESC_OPTYPE_ECDSA_SIGN:
		*in_sz = bytes * PKI_SIGN_INPUT_OP_COUNT;
		*out_sz = bytes * PKI_SIGN_OUTPUT_OP_COUNT;
		break;
	case PKI_DESC_OPTYPE_ECDSA_VERIFY:
		*in_sz = bytes * PKI_VERIFY_INPUT_OP_COUNT;
		*out_sz = bytes * PKI_VERIFY_OUTPUT_OP_COUNT;
		break;
	case PKI_DESC_OPTYPE_MOD_ADD:
		*in_sz = bytes * PKI_MOD_ADD_INPUT_OP_COUNT;
		*out_sz = bytes * PKI_MOD_ADD_OUTPUT_OP_COUNT;
		break;
	case PKI_DESC_OPTYPE_ECC_POINTMUL:
		*in_sz = bytes * PKI_ECC_POINTMUL_INPUT_OP_COUNT;
		*out_sz = bytes * PKI_ECC_POINTMUL_OUTPUT_OP_COUNT;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result pki_build_descriptors(uint32_t curve, uint32_t op,
					uint32_t *descs)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t in_sz = 0;
	size_t out_sz = 0;
	uint32_t opsize = 0;
	uint32_t selcurve = 0;

	ret = pki_get_opsize(curve, op, &in_sz, &out_sz);
	if (ret)
		return ret;

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P256:
		opsize = PKI_DESC_OPSIZE_P256;
		selcurve = PKI_DESC_SELCURVE_P256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		opsize = PKI_DESC_OPSIZE_P384;
		selcurve = PKI_DESC_SELCURVE_P384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		opsize = PKI_DESC_OPSIZE_P521;
		selcurve = PKI_DESC_SELCURVE_P521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* SelCurve must be zero for ModAdd */
	if (op == PKI_DESC_OPTYPE_MOD_ADD)
		selcurve = 0;

	descs[0] = PKI_DESC_TAG_START;
	descs[1] = PKI_DESC_TAG_START_CMD(op, opsize, selcurve,
					  PKI_DESC_ECC_FIELD_GFP);
	descs[2] = PKI_DESC_TAG_TFRI(in_sz);
	descs[3] = 0;
	descs[4] = PKI_DESC_TAG_TFRO(out_sz);
	descs[5] = 0x10000;
	descs[6] = PKI_DESC_TAG_NTFY(PKI_DEFAULT_REQID);
	descs[7] = 0;

	return TEE_SUCCESS;
}

static TEE_Result pki_start_operation(uint32_t reqval)
{
	uint32_t retries = PKI_MAX_RETRY_COUNT;

	/* Soft reset */
	io_write32(versal_pki.regs + PKI_CRYPTO_SOFT_RESET_OFFSET, 1);
	udelay(PKI_RESET_DELAY_US);
	io_write32(versal_pki.regs + PKI_CRYPTO_SOFT_RESET_OFFSET, 0);

	cache_operation(TEE_CACHEFLUSH, versal_pki.rq_in, PKI_QUEUE_BUF_SIZE);
	cache_operation(TEE_CACHEFLUSH, versal_pki.rq_out, PKI_QUEUE_BUF_SIZE);
	cache_operation(TEE_CACHEFLUSH, versal_pki.cq, PKI_QUEUE_BUF_SIZE);

	io_write32(versal_pki.regs + PKI_RQ_CFG_PERMISSIONS_OFFSET,
		   PKI_RQ_CFG_PERMISSIONS_SAFE);
	io_write64(versal_pki.regs + PKI_RQ_CFG_PAGE_ADDR_IN_OFFSET,
		   virt_to_phys(versal_pki.rq_in));
	io_write64(versal_pki.regs + PKI_RQ_CFG_PAGE_ADDR_OUT_OFFSET,
		   virt_to_phys(versal_pki.rq_out));
	io_write64(versal_pki.regs + PKI_CQ_CFG_ADDR_OFFSET,
		   virt_to_phys(versal_pki.cq));
	io_write32(versal_pki.regs + PKI_RQ_CFG_PAGE_SIZE_OFFSET,
		   PKI_RQ_CFG_PAGE_SIZE_1024);
	io_write32(versal_pki.regs + PKI_RQ_CFG_CQID_OFFSET, PKI_RQ_CFG_CQID);
	io_write32(versal_pki.regs + PKI_CQ_CFG_SIZE_OFFSET,
		   PKI_CQ_CFG_SIZE_4096);
	io_write32(versal_pki.regs + PKI_CQ_CFG_IRQ_IDX_OFFSET,
		   PKI_CQ_CFG_IRQ_ID_VAL);
	io_write32(versal_pki.regs + PKI_RQ_CFG_QUEUE_DEPTH_OFFSET,
		   PKI_RQ_CFG_QUEUE_DEPTH_VAL);
	io_write64(versal_pki.regs + PKI_CRYPTO_IRQ_ENABLE_OFFSET,
		   PKI_IRQ_ENABLE_VAL);

	io_write32(versal_pki.regs + PKI_CQ_CTL_TRIGPOS_OFFSET,
		   PKI_CQ_CTL_TRIGPOS_VAL);
	io_write64(versal_pki.regs + PKI_RQ_CTL_NEW_REQUEST_OFFSET, reqval);

	/* Wait for completion */
	while (retries--) {
		uint64_t irq_status = io_read64(versal_pki.regs +
						PKI_CRYPTO_IRQ_STATUS_OFFSET);
		if (irq_status == PKI_IRQ_DONE_STATUS_VAL) {
			io_write64(versal_pki.regs +
				   PKI_CRYPTO_IRQ_RESET_OFFSET,
				   PKI_IRQ_DONE_STATUS_VAL);
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_TIMEOUT;
}

static TEE_Result pki_check_status(void)
{
	uint32_t cq_status = 0;
	uint32_t cq_value = 0;

	cache_operation(TEE_CACHEFLUSH, versal_pki.cq, PKI_QUEUE_BUF_SIZE);

	cq_status = io_read32((vaddr_t)versal_pki.cq);
	cq_value = io_read32((vaddr_t)versal_pki.cq + 4);

	if (cq_status != PKI_EXPECTED_CQ_STATUS ||
	    cq_value != PKI_EXPECTED_CQ_VALUE)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_verify(uint32_t algo, struct ecc_public_key *key,
			     const uint8_t *msg, size_t msg_len,
			     const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bits = 0;
	size_t bytes = 0;
	size_t len = 0;
	uint8_t *addr = versal_pki.rq_in;
	uint32_t descriptors[8] = { };

	ret = versal_ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret)
		return ret;

	/* Copy public key */
	versal_crypto_bignum_bn2bin_eswap(key->curve, key->x, addr);
	addr += bytes;
	versal_crypto_bignum_bn2bin_eswap(key->curve, key->y, addr);
	addr += bytes;

	/* Copy signature */
	versal_memcpy_swp(addr, sig, sig_len / 2);
	addr += sig_len / 2;
	versal_memcpy_swp(addr, sig + sig_len / 2, sig_len / 2);
	addr += sig_len / 2;

	/* Copy hash */
	ret = versal_ecc_prepare_msg(algo, msg, msg_len, &len, addr);
	if (ret)
		return ret;
	if (len < bytes)
		memset(addr + len, 0, bytes - len);
	addr += bytes;

	if (key->curve == TEE_ECC_CURVE_NIST_P521) {
		memset((uint8_t *)addr, 0, PKI_VERIFY_P521_PADD_BYTES);
		addr += PKI_VERIFY_P521_PADD_BYTES;
	}

	/* Build descriptors */
	if (!IS_ALIGNED_WITH_TYPE(addr, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	ret = pki_build_descriptors(key->curve, PKI_DESC_OPTYPE_ECDSA_VERIFY,
				    descriptors);
	if (ret)
		return ret;

	memcpy(addr, descriptors, 8 * sizeof(uint32_t));

	ret = pki_start_operation(PKI_NEW_REQUEST_MASK & ((uintptr_t)addr + 1));
	if (ret)
		return ret;

	ret = pki_check_status();
	if (ret)
		return ret;

	/* Clear memory */
	memset(versal_pki.rq_in, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.cq, 0, PKI_QUEUE_BUF_SIZE);

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_sign(uint32_t algo, struct ecc_keypair *key,
			   const uint8_t *msg, size_t msg_len,
			   uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bits = 0;
	size_t bytes = 0;
	struct ecc_keypair ephemeral = { };

	ret = versal_ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret)
		return ret;

	/* Ephemeral private key */
	ret = drvcrypt_asym_alloc_ecc_keypair(&ephemeral,
					      TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		EMSG("Versal, can't allocate the ephemeral key");
		return ret;
	}

	ephemeral.curve = key->curve;
	ret = versal_ecc_gen_keypair(&ephemeral);
	if (ret) {
		EMSG("Versal, can't generate the ephemeral key");
		goto out;
	}

	ret = versal_ecc_sign_ephemeral(algo, bytes, key, &ephemeral, msg,
					msg_len, sig, sig_len);

out:
	crypto_bignum_free(&ephemeral.d);
	crypto_bignum_free(&ephemeral.x);
	crypto_bignum_free(&ephemeral.y);

	return ret;
}

TEE_Result versal_ecc_sign_ephemeral(uint32_t algo, size_t bytes,
				     struct ecc_keypair *key,
				     struct ecc_keypair *ephemeral,
				     const uint8_t *msg, size_t msg_len,
				     uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t len = 0;
	uintptr_t addr = (uintptr_t)versal_pki.rq_in;

	/* Copy private key */
	versal_crypto_bignum_bn2bin_eswap(key->curve, key->d, (uint8_t *)addr);
	addr += bytes;

	/* Copy ephemeral key */
	versal_crypto_bignum_bn2bin_eswap(key->curve, ephemeral->d,
					  (uint8_t *)addr);
	addr += bytes;

	/* Copy hash */
	ret = versal_ecc_prepare_msg(algo, msg, msg_len, &len, (uint8_t *)addr);
	if (ret)
		return ret;
	if (len < bytes)
		memset((uint8_t *)addr + len, 0, bytes - len);
	addr += bytes;

	if (key->curve == TEE_ECC_CURVE_NIST_P521) {
		memset((uint8_t *)addr, 0, PKI_SIGN_P521_PADD_BYTES);
		addr += PKI_SIGN_P521_PADD_BYTES;
	}

	/* Build descriptors */
	ret = pki_build_descriptors(key->curve, PKI_DESC_OPTYPE_ECDSA_SIGN,
				    (uint32_t *)addr);
	if (ret)
		return ret;

	ret = pki_start_operation(PKI_NEW_REQUEST_MASK & (addr + 1));
	if (ret)
		return ret;

	ret = pki_check_status();
	if (ret)
		return ret;

	/* Copy signature back */
	*sig_len = 2 * bytes;

	cache_operation(TEE_CACHEFLUSH, versal_pki.rq_out, PKI_QUEUE_BUF_SIZE);

	versal_memcpy_swp(sig, versal_pki.rq_out, bytes);
	versal_memcpy_swp(sig + bytes, versal_pki.rq_out + bytes, bytes);

	/* Clear memory */
	memset(versal_pki.rq_in, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.rq_out, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.cq, 0, PKI_QUEUE_BUF_SIZE);

	return ret;
}

static const uint8_t order_p256[] = {
	0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3,
	0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

static const uint8_t order_p384[] = {
	0x73, 0x29, 0xc5, 0xcc, 0x6a, 0x19, 0xec, 0xec,
	0x7a, 0xa7, 0xb0, 0x48, 0xb2, 0x0d, 0x1a, 0x58,
	0xdf, 0x2d, 0x37, 0xf4, 0x81, 0x4d, 0x63, 0xc7,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static const uint8_t order_p521[] = {
	0x09, 0x64, 0x38, 0x91, 0x1e, 0xb7, 0x6f, 0xbb,
	0xae, 0x47, 0x9c, 0x89, 0xb8, 0xc9, 0xb5, 0x3b,
	0xd0, 0xa5, 0x09, 0xf7, 0x48, 0x01, 0xcc, 0x7f,
	0x6b, 0x96, 0x2f, 0xbf, 0x83, 0x87, 0x86, 0x51,
	0xfa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x01
};

static const uint8_t ecdsa_gpoint_p256_gx[] = {
	0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4,
	0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
	0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
	0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b
};

static const uint8_t ecdsa_gpoint_p256_gy[] = {
	0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb,
	0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
	0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
	0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f
};

static const uint8_t ecdsa_gpoint_p384_gx[] = {
	0xb7, 0x0a, 0x76, 0x72, 0x38, 0x5e, 0x54, 0x3a,
	0x6c, 0x29, 0x55, 0xbf, 0x5d, 0xf2, 0x02, 0x55,
	0x38, 0x2a, 0x54, 0x82, 0xe0, 0x41, 0xf7, 0x59,
	0x98, 0x9b, 0xa7, 0x8b, 0x62, 0x3b, 0x1d, 0x6e,
	0x74, 0xad, 0x20, 0xf3, 0x1e, 0xc7, 0xb1, 0x8e,
	0x37, 0x05, 0x8b, 0xbe, 0x22, 0xca, 0x87, 0xaa
};

static const uint8_t ecdsa_gpoint_p384_gy[] = {
	0x5f, 0x0e, 0xea, 0x90, 0x7c, 0x1d, 0x43, 0x7a,
	0x9d, 0x81, 0x7e, 0x1d, 0xce, 0xb1, 0x60, 0x0a,
	0xc0, 0xb8, 0xf0, 0xb5, 0x13, 0x31, 0xda, 0xe9,
	0x7c, 0x14, 0x9a, 0x28, 0xbd, 0x1d, 0xf4, 0xf8,
	0x29, 0xdc, 0x92, 0x92, 0xbf, 0x98, 0x9e, 0x5d,
	0x6f, 0x2c, 0x26, 0x96, 0x4a, 0xde, 0x17, 0x36
};

static const uint8_t ecdsa_gpoint_p521_gx[] = {
	0x66, 0xbd, 0xe5, 0xc2, 0x31, 0x7e, 0x7e, 0xf9,
	0x9b, 0x42, 0x6a, 0x85, 0xc1, 0xb3, 0x48, 0x33,
	0xde, 0xa8, 0xff, 0xa2, 0x27, 0xc1, 0x1d, 0xfe,
	0x28, 0x59, 0xe7, 0xef, 0x77, 0x5e, 0x4b, 0xa1,
	0xba, 0x3d, 0x4d, 0x6b, 0x60, 0xaf, 0x28, 0xf8,
	0x21, 0xb5, 0x3f, 0x05, 0x39, 0x81, 0x64, 0x9c,
	0x42, 0xb4, 0x95, 0x23, 0x66, 0xcb, 0x3e, 0x9e,
	0xcd, 0xe9, 0x04, 0x04, 0xb7, 0x06, 0x8e, 0x85,
	0xc6, 0x00
};

static const uint8_t ecdsa_gpoint_p521_gy[] = {
	0x50, 0x66, 0xd1, 0x9f, 0x76, 0x94, 0xbe, 0x88,
	0x40, 0xc2, 0x72, 0xa2, 0x86, 0x70, 0x3c, 0x35,
	0x61, 0x07, 0xad, 0x3f, 0x01, 0xb9, 0x50, 0xc5,
	0x40, 0x26, 0xf4, 0x5e, 0x99, 0x72, 0xee, 0x97,
	0x2c, 0x66, 0x3e, 0x27, 0x17, 0xbd, 0xaf, 0x17,
	0x68, 0x44, 0x9b, 0x57, 0x49, 0x44, 0xf5, 0x98,
	0xd9, 0x1b, 0x7d, 0x2c, 0xb4, 0x5f, 0x8a, 0x5c,
	0x04, 0xc0, 0x3b, 0x9a, 0x78, 0x6a, 0x29, 0x39,
	0x18, 0x01
};

static TEE_Result versal_ecc_gen_private_key(uint32_t curve, uint8_t *priv,
					     size_t bytes)
{
	TEE_Result ret = TEE_SUCCESS;
	const uint8_t *order = NULL;
	uintptr_t addr = (uintptr_t)versal_pki.rq_in;

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P256:
		order = order_p256;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		order = order_p384;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		order = order_p521;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Copy curve order N */
	memcpy((uint8_t *)addr, order, bytes);
	addr += bytes;

	/* Copy A = random */
	ret = versal_ecc_trng_get_random_bytes((uint8_t *)addr, bytes);
	if (ret)
		return ret;
	addr += bytes;

	/* Copy B = 1 */
	memset((uint8_t *)addr, 1, 1);
	memset((uint8_t *)addr + 1, 0, bytes - 1);
	addr += bytes;

	if (curve == TEE_ECC_CURVE_NIST_P521) {
		memset((uint8_t *)addr, 0, PKI_SIGN_P521_PADD_BYTES);
		addr += PKI_SIGN_P521_PADD_BYTES;
	}

	/* Build descriptors */
	ret = pki_build_descriptors(curve, PKI_DESC_OPTYPE_MOD_ADD,
				    (uint32_t *)addr);
	if (ret)
		return ret;

	/* Use PKI engine to compute A+B mod N */
	ret = pki_start_operation(PKI_NEW_REQUEST_MASK & (addr + 1));
	if (ret)
		return ret;

	ret = pki_check_status();
	if (ret)
		return ret;

	cache_operation(TEE_CACHEFLUSH, versal_pki.rq_out, PKI_QUEUE_BUF_SIZE);

	/* Copy back result */
	memcpy(priv, versal_pki.rq_out, bytes);

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_gen_keypair(struct ecc_keypair *s)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bytes = 0;
	size_t bits = 0;
	const uint8_t *gx = NULL;
	const uint8_t *gy = NULL;
	uintptr_t addr = (uintptr_t)versal_pki.rq_in;

	ret = versal_ecc_get_key_size(s->curve, &bytes, &bits);
	if (ret)
		return ret;

	switch (s->curve) {
	case TEE_ECC_CURVE_NIST_P256:
		gx = ecdsa_gpoint_p256_gx;
		gy = ecdsa_gpoint_p256_gy;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		gx = ecdsa_gpoint_p384_gx;
		gy = ecdsa_gpoint_p384_gy;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		gx = ecdsa_gpoint_p521_gx;
		gy = ecdsa_gpoint_p521_gy;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Generate private key */
	ret = versal_ecc_gen_private_key(s->curve, (uint8_t *)addr, bytes);
	if (ret)
		return ret;
	addr += bytes;

	/* Copy generator point x coordinate */
	memcpy((uint8_t *)addr, gx, bytes);
	addr += bytes;

	/* Copy generator point y coordinate */
	memcpy((uint8_t *)addr, gy, bytes);
	addr += bytes;

	if (s->curve == TEE_ECC_CURVE_NIST_P521) {
		memset((uint8_t *)addr, 0, PKI_SIGN_P521_PADD_BYTES);
		addr += PKI_SIGN_P521_PADD_BYTES;
	}

	/* Build descriptors */
	ret = pki_build_descriptors(s->curve, PKI_DESC_OPTYPE_ECC_POINTMUL,
				    (uint32_t *)addr);
	if (ret)
		return ret;

	/* Use PKI engine to compute Q = priv * G */
	ret = pki_start_operation(PKI_NEW_REQUEST_MASK & (addr + 1));
	if (ret)
		return ret;

	ret = pki_check_status();
	if (ret)
		return ret;

	cache_operation(TEE_CACHEFLUSH, versal_pki.rq_out, PKI_QUEUE_BUF_SIZE);

	/* Copy private and public keys back */
	versal_crypto_bignum_bin2bn_eswap(versal_pki.rq_in, bytes, s->d);
	versal_crypto_bignum_bin2bn_eswap(versal_pki.rq_out, bytes, s->x);
	versal_crypto_bignum_bin2bn_eswap(versal_pki.rq_out + bytes,
					  bytes, s->y);

	/* Clear memory */
	memset(versal_pki.rq_in, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.rq_out, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.cq, 0, PKI_QUEUE_BUF_SIZE);

	return TEE_SUCCESS;
}

#define PSX_CRF_RST_PKI			0xEC200340

#define PKI_ASSERT_RESET		1
#define PKI_DEASSERT_RESET		0

static TEE_Result versal_pki_engine_reset(void)
{
	vaddr_t reset = 0;

	/* Reset the PKI engine */
	reset = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
					      PSX_CRF_RST_PKI,
					      SMALL_PAGE_SIZE);
	if (!reset)
		return TEE_ERROR_GENERIC;

	io_write32(reset, PKI_ASSERT_RESET);
	udelay(PKI_RESET_DELAY_US);
	io_write32(reset, PKI_DEASSERT_RESET);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC, (void *)reset,
				SMALL_PAGE_SIZE);

	return TEE_SUCCESS;
}

#define FPD_SLCR_BASEADDR		0xEC8C0000
#define FPD_SLCR_SIZE			0x4000

#define FPD_SLCR_WPROT0_OFFSET		0x00000000
#define FPD_SLCR_PKI_MUX_SEL_OFFSET	0x00002000

#define FPD_CLEAR_WRITE_PROTECT		0
#define FPD_ENABLE_WRITE_PROTECT	1

#define PKI_MUX_SEL_MASK		0x00000001
#define PKI_MUX_SELECT			0x00000001

static TEE_Result versal_pki_engine_slcr_config(void)
{
	vaddr_t fpd_slcr = 0;

	fpd_slcr = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						 FPD_SLCR_BASEADDR,
						 FPD_SLCR_SIZE);
	if (!fpd_slcr)
		return TEE_ERROR_GENERIC;

	/* Clear FPD SCLR write protect reg */
	io_write32(fpd_slcr + FPD_SLCR_WPROT0_OFFSET,
		   FPD_CLEAR_WRITE_PROTECT);

	/* PKI mux selection */
	io_mask32(fpd_slcr + FPD_SLCR_PKI_MUX_SEL_OFFSET,
		  PKI_MUX_SELECT, PKI_MUX_SEL_MASK);

	/* Re-enable FPD SCLR write protect */
	io_write32(fpd_slcr + FPD_SLCR_WPROT0_OFFSET,
		   FPD_ENABLE_WRITE_PROTECT);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC,
				(void *)fpd_slcr, FPD_SLCR_SIZE);

	return TEE_SUCCESS;
}

static TEE_Result versal_pki_engine_config(void)
{
	vaddr_t regs = 0;
	uint64_t val = 0;

	regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
					     FPD_PKI_CTRLSTAT_BASEADDR,
					     FPD_PKI_SIZE);
	if (!regs)
		return TEE_ERROR_GENERIC;

	/* Counter-measures configuration */
	val = io_read64(regs + PKI_ENGINE_CTRL_OFFSET);
	if (IS_ENABLED(CFG_VERSAL_PKI_COUNTER_MEASURES))
		val &= ~PKI_ENGINE_CTRL_CM_MASK;
	else
		val |= PKI_ENGINE_CTRL_CM_MASK;
	io_write64(regs + PKI_ENGINE_CTRL_OFFSET, val);

	/* Mark PKI engine transactions as secure */
	val = io_read64(regs + PKI_ENGINE_GEN_CTRL_OFFSET);
	val &= ~PKI_ENGINE_GEN_CTRL_TZ;
	io_write64(regs + PKI_ENGINE_GEN_CTRL_OFFSET, val);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC,
				(void *)regs, FPD_PKI_SIZE);

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_hw_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_pki_engine_slcr_config();
	if (ret != TEE_SUCCESS)
		return ret;

	ret = versal_pki_engine_reset();
	if (ret != TEE_SUCCESS)
		return ret;

	ret = versal_pki_engine_config();
	if (ret != TEE_SUCCESS)
		return ret;

	ret = versal_ecc_trng_init();
	if (ret != TEE_SUCCESS)
		return ret;

	versal_pki.regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
							FPD_PKI_CRYPTO_BASEADDR,
							FPD_PKI_SIZE);
	if (!versal_pki.regs)
		return TEE_ERROR_GENERIC;

	/* Allocate queues */
	versal_pki.rq_in = memalign(CACHELINE_LEN, PKI_QUEUE_BUF_SIZE);
	if (!versal_pki.rq_in)
		goto error;

	versal_pki.rq_out = memalign(CACHELINE_LEN, PKI_QUEUE_BUF_SIZE);
	if (!versal_pki.rq_out)
		goto error;

	versal_pki.cq = memalign(CACHELINE_LEN, PKI_QUEUE_BUF_SIZE);
	if (!versal_pki.cq)
		goto error;

	return TEE_SUCCESS;

error:
	free(versal_pki.rq_in);
	free(versal_pki.rq_out);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC,
				(void *)versal_pki.regs, FPD_PKI_SIZE);

	return TEE_ERROR_GENERIC;
}
