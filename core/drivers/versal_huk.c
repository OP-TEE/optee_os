// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Foundries.io Ltd.
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <assert.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <drivers/versal_puf.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

static struct {
	uint8_t key[HW_UNIQUE_KEY_LENGTH];
	bool ready;
} huk;

enum aes_key_src {
	XSECURE_AES_BBRAM_KEY = 0,
	XSECURE_AES_BBRAM_RED_KEY,
	XSECURE_AES_BH_KEY,
	XSECURE_AES_BH_RED_KEY,
	XSECURE_AES_EFUSE_KEY,
	XSECURE_AES_EFUSE_RED_KEY,
	XSECURE_AES_EFUSE_USER_KEY_0,
	XSECURE_AES_EFUSE_USER_KEY_1,
	XSECURE_AES_EFUSE_USER_RED_KEY_0,
	XSECURE_AES_EFUSE_USER_RED_KEY_1,
	XSECURE_AES_KUP_KEY,
	XSECURE_AES_PUF_KEY,
	XSECURE_AES_USER_KEY_0,
	XSECURE_AES_USER_KEY_1,
	XSECURE_AES_USER_KEY_2,
	XSECURE_AES_USER_KEY_3,
	XSECURE_AES_USER_KEY_4,
	XSECURE_AES_USER_KEY_5,
	XSECURE_AES_USER_KEY_6,
	XSECURE_AES_USER_KEY_7,
	XSECURE_AES_EXPANDED_KEYS,
	XSECURE_AES_ALL_KEYS,
};

enum versal_crypto_api {
	SHA3_UPDATE = 32U,
	AES_INIT = 96U,
	AES_OP_INIT,
	AES_UPDATE_AAD,
	AES_ENCRYPT_UPDATE,
	AES_ENCRYPT_FINAL,
	AES_DECRYPT_UPDATE,
	AES_DECRYPT_FINAL,
	AES_KEY_ZERO,
	AES_WRITE_KEY,
	AES_LOCK_USER_KEY,
	AES_KEK_DECRYPT,
	AES_SET_DPA_CM,
	AES_DECRYPT_KAT,
	AES_DECRYPT_CM_KAT,
	MAX,
};

#define MODULE_SHIFT 8
#define MODULE_ID 5
#define API_ID(__x) ((MODULE_ID << MODULE_SHIFT) | (__x))

struct versal_aes_input_param {
	uint64_t input_addr;
	uint32_t input_len;
	uint32_t is_last;
};

struct versal_aes_init {
	uint64_t iv_addr;
	uint32_t operation;
	uint32_t key_src;
	uint32_t key_len;
};

/* notice: the PLM is little endian so when programming the keys in uint32_t
 * they have to be BE swapped: the test key below would correspond to a byte
 * array as  0xf8, 0x78, 0xb8, 0x38, 0xd8, 0x58, 0x98, 0x18, 0xe8, 0x68, ....
 */
#define DEVEL_KEY { \
0xf878b838, 0xd8589818, 0xe868a828, 0xc8488808, \
0xf070b030, 0xd0509010, 0xe060a020, 0xc0408000, }

#define AAD { \
0x67, 0xe2, 0x1c, 0xf3, 0xcb, 0x29, 0xe0, 0xdc, 0xbc, 0x4d, 0x8b, \
0x1d, 0x0c, 0xc5, 0x33, 0x4b, }

#define NONCE { \
0xd2, 0x45, 0x0e, 0x07, 0xea, 0x5d, 0xe0, 0x42, 0x6c, 0x0f, 0xa1, 0x33, }

static bool versal_persistent_key(enum aes_key_src src, bool *secure)
{
	struct versal_efuse_puf_sec_ctrl_bits puf_ctrl = { };
	struct versal_efuse_sec_ctrl_bits ctrl = { };
	struct versal_puf_data puf_data = { };
	struct versal_puf_cfg cfg  = {
		.global_var_filter = XPUF_GLBL_VAR_FLTR_OPTION,
		.read_option = XPUF_READ_FROM_EFUSE_CACHE,
		.puf_operation = XPUF_REGEN_ON_DEMAND,
		.shutter_value = XPUF_SHUTTER_VALUE,
		.reg_mode = XPUF_SYNDROME_MODE_4K,
	};

	switch (src) {
	case XSECURE_AES_EFUSE_USER_KEY_0:
		if (versal_get_efuse_ops()->read->sec_ctrl(&ctrl))
			panic();

		*secure = ctrl.user_key0_wr_lk ? true : false;
		return true;

	case XSECURE_AES_EFUSE_USER_KEY_1:
		if (versal_get_efuse_ops()->read->sec_ctrl(&ctrl))
			panic();

		*secure = ctrl.user_key1_wr_lk ? true : false;
		return true;

	case XSECURE_AES_PUF_KEY:
		if (versal_get_efuse_ops()->read->puf_sec_ctrl(&puf_ctrl))
			panic();

		if (versal_puf_regenerate(&puf_data, &cfg))
			panic();

		*secure = puf_ctrl.puf_syn_lk ? true : false;
		return true;

	case XSECURE_AES_USER_KEY_0:
		*secure = false;
		return false;

	default:
		EMSG("Trying to use an invalid key for the HUK");
		panic();
	}

	return false;
}

static TEE_Result versal_encrypt(uint8_t *src, size_t src_len,
				 uint8_t *dst, size_t dst_len)
{
	uint32_t key_id = CFG_VERSAL_HUK_KEY;
	struct versal_aes_input_param *input = NULL;
	struct versal_aes_init *init = NULL;
	struct versal_mbox_mem input_cmd = { };
	struct versal_mbox_mem init_buf = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem q = { };
	uint32_t key_data[8] = DEVEL_KEY;
	uint8_t nce_data[12] = NONCE;
	uint8_t aad_data[16] = AAD;
	size_t nce_len = sizeof(nce_data);
	size_t key_len = sizeof(key_data);
	size_t aad_len = sizeof(aad_data);
	TEE_Result ret = TEE_SUCCESS;
	struct ipi_cmd cmd = { };
	bool secure = false;
	size_t i = 0;

	if (key_id >  XSECURE_AES_ALL_KEYS)
		return TEE_ERROR_BAD_PARAMETERS;

	cmd.data[0] = API_ID(AES_INIT);
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_INIT error");
		return TEE_ERROR_GENERIC;
	}

	if (!versal_persistent_key(key_id, &secure)) {
		for (i = 0; i < ARRAY_SIZE(key_data); i++)
			key_data[i] = TEE_U32_BSWAP(key_data[i]);

		versal_mbox_alloc(key_len, key_data, &p);
		cmd.data[0] = API_ID(AES_WRITE_KEY);
		cmd.data[1] = 2;  /* XSECURE_AES_KEY_SIZE_256 */
		cmd.data[2] = key_id;
		cmd.data[3] = virt_to_phys(p.buf);
		cmd.data[4] = virt_to_phys(p.buf) >> 32;
		cmd.ibuf[0].mem = p;
		if (versal_mbox_notify(&cmd, NULL, NULL)) {
			EMSG("AES_WRITE_KEY error");
			ret = TEE_ERROR_GENERIC;
		}
		free(p.buf);
		memset(&cmd, 0, sizeof(cmd));
		if (ret)
			return ret;
	}

	/* Indication that it is safe to generate an RPMB key */
	IMSG("Using %s HUK", secure ? "Production" : "Development");

	versal_mbox_alloc(sizeof(*init), NULL, &init_buf);
	versal_mbox_alloc(nce_len, nce_data, &p);
	init = init_buf.buf;
	init->iv_addr = virt_to_phys(p.buf);
	init->operation = 0; /* encrypt */
	init->key_src = key_id;
	init->key_len = 2;  /* XSECURE_AES_KEY_SIZE_256 */
	cmd.data[0] = API_ID(AES_OP_INIT);
	cmd.data[1] = virt_to_phys(init);
	cmd.data[2] = virt_to_phys(init) >> 32;
	cmd.ibuf[0].mem = init_buf;
	cmd.ibuf[1].mem = p;
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_OP_INIT error");
		ret = TEE_ERROR_GENERIC;
	}
	free(init);
	free(p.buf);
	memset(&cmd, 0, sizeof(cmd));
	if (ret)
		return ret;

	versal_mbox_alloc(aad_len, aad_data, &p);
	cmd.data[0] = API_ID(AES_UPDATE_AAD);
	cmd.data[1] = virt_to_phys(p.buf);
	cmd.data[2] = virt_to_phys(p.buf) >> 32;
	cmd.data[3] = p.len % 16 ? p.alloc_len : p.len;
	cmd.ibuf[0].mem = p;
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_UPDATE_AAD error");
		ret = TEE_ERROR_GENERIC;
	}
	free(p.buf);
	memset(&cmd, 0, sizeof(cmd));
	if (ret)
		return ret;

	versal_mbox_alloc(sizeof(*input), NULL, &input_cmd);
	versal_mbox_alloc(src_len, src, &p);
	versal_mbox_alloc(dst_len, NULL, &q);
	input = input_cmd.buf;
	input->input_addr = virt_to_phys(p.buf);
	input->input_len = p.len;
	input->is_last = true;
	cmd.data[0] = API_ID(AES_ENCRYPT_UPDATE);
	cmd.data[1] = virt_to_phys(input);
	cmd.data[2] = virt_to_phys(input) >> 32;
	cmd.data[3] = virt_to_phys(q.buf);
	cmd.data[4] = virt_to_phys(q.buf) >> 32;
	cmd.ibuf[0].mem = input_cmd;
	cmd.ibuf[1].mem = p;
	cmd.ibuf[2].mem = q;
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_UPDATE_PAYLOAD error");
		ret = TEE_ERROR_GENERIC;
	}

	memcpy(dst, q.buf, dst_len);
	free(input);
	free(p.buf);
	free(q.buf);
	memset(&cmd, 0, sizeof(cmd));
	if (ret)
		return ret;

	versal_mbox_alloc(16, NULL, &p);
	cmd.data[0] = API_ID(AES_ENCRYPT_FINAL);
	cmd.data[1] = virt_to_phys(p.buf);
	cmd.data[2] = virt_to_phys(p.buf) >> 32;
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_ENCRYPT_FINAL error");
		ret = TEE_ERROR_GENERIC;
	}

	free(p.buf);
	memset(&cmd, 0, sizeof(cmd));

	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t dna[EFUSE_DNA_LEN / sizeof(uint32_t)] = { 0 };
	uint8_t enc_data[68] = { 0 };
	uint8_t sha[48] = { 0 };

	if (huk.ready)
		goto out;

	/* Read DNA */
	if (versal_get_efuse_ops()->read->dna(dna, sizeof(dna)))
		return TEE_ERROR_GENERIC;

	/* SHA3-384: 48 bytes */
	if (tee_hash_createdigest(TEE_ALG_SHA3_384, (uint8_t *)dna,
				  sizeof(dna), sha, sizeof(sha)))
		return TEE_ERROR_GENERIC;

	/* Encrypt AES-GCM */
	if (versal_encrypt(sha, sizeof(sha), enc_data, sizeof(enc_data)))
		return TEE_ERROR_GENERIC;

	/* Shrink to HUK length */
	if (tee_hash_createdigest(TEE_ALG_SHA256, enc_data, sizeof(enc_data),
				  huk.key, sizeof(huk.key)))
		return TEE_ERROR_GENERIC;

	huk.ready = true;

	DMSG("HUK:");
	DHEXDUMP(huk.key, sizeof(huk.key));
out:
	memcpy(hwkey->data, huk.key, HW_UNIQUE_KEY_LENGTH);

	return TEE_SUCCESS;
}
