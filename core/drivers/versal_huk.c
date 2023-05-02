// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Foundries.io Ltd.
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <assert.h>
#include <drivers/versal_mbox.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_puf.h>
#include <drivers/versal_sha3_384.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <string_ext.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <utee_defines.h>

static struct {
	uint8_t key[HW_UNIQUE_KEY_LENGTH];
	bool ready;
} huk;

#define MODULE_SHIFT 8
#define MODULE_ID 5
#define API_ID(__x) ((MODULE_ID << MODULE_SHIFT) | (__x))

#define	VERSAL_AES_KEY_SIZE_256  2
#define VERSAL_AES_GCM_ENCRYPT 0

enum versal_aes_key_src {
	VERSAL_AES_BBRAM_KEY = 0,
	VERSAL_AES_BBRAM_RED_KEY,
	VERSAL_AES_BH_KEY,
	VERSAL_AES_BH_RED_KEY,
	VERSAL_AES_EFUSE_KEY,
	VERSAL_AES_EFUSE_RED_KEY,
	VERSAL_AES_EFUSE_USER_KEY_0,
	VERSAL_AES_EFUSE_USER_KEY_1,
	VERSAL_AES_EFUSE_USER_RED_KEY_0,
	VERSAL_AES_EFUSE_USER_RED_KEY_1,
	VERSAL_AES_KUP_KEY,
	VERSAL_AES_PUF_KEY,
	VERSAL_AES_USER_KEY_0,
	VERSAL_AES_USER_KEY_1,
	VERSAL_AES_USER_KEY_2,
	VERSAL_AES_USER_KEY_3,
	VERSAL_AES_USER_KEY_4,
	VERSAL_AES_USER_KEY_5,
	VERSAL_AES_USER_KEY_6,
	VERSAL_AES_USER_KEY_7,
	VERSAL_AES_EXPANDED_KEYS,
	VERSAL_AES_ALL_KEYS,
};

enum versal_crypto_api {
	VERSAL_AES_INIT = 96U,
	VERSAL_AES_OP_INIT,
	VERSAL_AES_UPDATE_AAD,
	VERSAL_AES_ENCRYPT_UPDATE,
	VERSAL_AES_ENCRYPT_FINAL,
	VERSAL_AES_DECRYPT_UPDATE,
	VERSAL_AES_DECRYPT_FINAL,
	VERSAL_AES_KEY_ZERO,
	VERSAL_AES_WRITE_KEY,
	VERSAL_AES_LOCK_USER_KEY,
	VERSAL_AES_KEK_DECRYPT,
	VERSAL_AES_SET_DPA_CM,
	VERSAL_AES_DECRYPT_KAT,
	VERSAL_AES_DECRYPT_CM_KAT,
};

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

/*
 * The PLM is little endian. When programming the keys in uint32_t the driver
 * will BE swap the values.
 *
 * This way the test key below corresponds to the byte array 0xf8, 0x78, 0xb8,
 * 0x38, 0xd8, 0x58, 0x98, 0x18, 0xe8, 0x68, ....
 *
 * NOTICE: This hardcoded value in DEVEL_KEY could have just been zeroes as done
 * in the weak implementation found in otp_stubs.c.
 */
#define DEVEL_KEY { \
		0xf878b838, 0xd8589818, 0xe868a828, 0xc8488808, \
		0xf070b030, 0xd0509010, 0xe060a020, 0xc0408000, \
	}

#define AAD { \
		0x67, 0xe2, 0x1c, 0xf3, 0xcb, 0x29, 0xe0, 0xdc, 0xbc, 0x4d, \
		0x8b, 0x1d, 0x0c, 0xc5, 0x33, 0x4b, \
	}

#define NONCE { \
		0xd2, 0x45, 0x0e, 0x07, 0xea, 0x5d, 0xe0, 0x42, 0x6c, 0x0f, \
		0xa1, 0x33, \
	}

static bool versal_persistent_key(enum versal_aes_key_src src, bool *secure)
{
	struct versal_efuse_puf_sec_ctrl_bits puf_ctrl = { };
	struct versal_efuse_sec_ctrl_bits ctrl = { };
	struct versal_puf_data puf_data = { };
	struct versal_puf_cfg cfg = {
		.global_var_filter = VERSAL_PUF_GLBL_VAR_FLTR_OPTION,
		.read_option = VERSAL_PUF_READ_FROM_EFUSE_CACHE,
		.puf_operation = VERSAL_PUF_REGEN_ON_DEMAND,
		.shutter_value = VERSAL_PUF_SHUTTER_VALUE,
		.reg_mode = VERSAL_PUF_SYNDROME_MODE_4K,
	};

	switch (src) {
	case VERSAL_AES_EFUSE_USER_KEY_0:
		if (versal_efuse_read_sec_ctrl(&ctrl))
			panic();

		*secure = ctrl.user_key0_wr_lk;
		return true;

	case VERSAL_AES_EFUSE_USER_KEY_1:
		if (versal_efuse_read_sec_ctrl(&ctrl))
			panic();

		*secure = ctrl.user_key1_wr_lk;
		return true;

	case VERSAL_AES_PUF_KEY:
		if (versal_efuse_read_puf_sec_ctrl(&puf_ctrl))
			panic();

		if (versal_puf_regenerate(&puf_data, &cfg))
			panic();

		*secure = puf_ctrl.puf_syn_lk;
		return true;

	case VERSAL_AES_USER_KEY_0:
		*secure = false;
		return false;

	default:
		EMSG("Trying to use an invalid key for the HUK");
		panic();
	}

	return false;
}

/* Encrypt using an AES-GCM key selectable with CFG_VERSAL_HUK_KEY */
static TEE_Result aes_gcm_encrypt(uint8_t *src, size_t src_len,
				  uint8_t *dst, size_t dst_len)
{
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
	struct versal_ipi_cmd cmd = { };
	bool secure = false;
	size_t i = 0;
	uint32_t key_id = CFG_VERSAL_HUK_KEY;

	if (key_id > VERSAL_AES_ALL_KEYS)
		return TEE_ERROR_BAD_PARAMETERS;

	cmd.data[0] = API_ID(VERSAL_AES_INIT);
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_INIT error");
		return TEE_ERROR_GENERIC;
	}

	if (!versal_persistent_key(key_id, &secure)) {
		for (i = 0; i < ARRAY_SIZE(key_data); i++)
			key_data[i] = TEE_U32_BSWAP(key_data[i]);

		versal_mbox_alloc(key_len, key_data, &p);
		cmd.data[0] = API_ID(VERSAL_AES_WRITE_KEY);
		cmd.data[1] = VERSAL_AES_KEY_SIZE_256;
		cmd.data[2] = key_id;
		reg_pair_from_64(virt_to_phys(p.buf),
				 &cmd.data[4], &cmd.data[3]);
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

	/* Trace indication that it is safe to generate a RPMB key */
	IMSG("Using %s HUK", secure ? "Production" : "Development");

	versal_mbox_alloc(sizeof(*init), NULL, &init_buf);
	versal_mbox_alloc(nce_len, nce_data, &p);
	init = init_buf.buf;
	init->operation = VERSAL_AES_GCM_ENCRYPT;
	init->key_len = VERSAL_AES_KEY_SIZE_256;
	init->iv_addr = virt_to_phys(p.buf);
	init->key_src = key_id;
	cmd.data[0] = API_ID(VERSAL_AES_OP_INIT);
	reg_pair_from_64(virt_to_phys(init), &cmd.data[2], &cmd.data[1]);
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
	cmd.data[0] = API_ID(VERSAL_AES_UPDATE_AAD);
	reg_pair_from_64(virt_to_phys(p.buf), &cmd.data[2], &cmd.data[1]);
	if (p.len % 16)
		cmd.data[3] = p.alloc_len;
	else
		cmd.data[3] = p.len;
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
	cmd.data[0] = API_ID(VERSAL_AES_ENCRYPT_UPDATE);
	reg_pair_from_64(virt_to_phys(input), &cmd.data[2], &cmd.data[1]);
	reg_pair_from_64(virt_to_phys(q.buf), &cmd.data[4], &cmd.data[3]);
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
	cmd.data[0] = API_ID(VERSAL_AES_ENCRYPT_FINAL);
	reg_pair_from_64(virt_to_phys(p.buf), &cmd.data[2], &cmd.data[1]);
	if (versal_mbox_notify(&cmd, NULL, NULL)) {
		EMSG("AES_ENCRYPT_FINAL error");
		ret = TEE_ERROR_GENERIC;
	}
	free(p.buf);
	memzero_explicit(&cmd, sizeof(cmd));

	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	uint32_t dna[EFUSE_DNA_LEN / sizeof(uint32_t)] = { };
	uint8_t enc_data[64] = { };
	uint8_t sha[48] = { };
	TEE_Result ret = TEE_SUCCESS;

	if (huk.ready)
		goto out;

	if (versal_efuse_read_dna(dna, sizeof(dna)))
		return TEE_ERROR_GENERIC;

	if (versal_sha3_384((uint8_t *)dna, sizeof(dna), sha, sizeof(sha))) {
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	if (aes_gcm_encrypt(sha, sizeof(sha), enc_data, sizeof(enc_data))) {
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

	if (tee_hash_createdigest(TEE_ALG_SHA256, enc_data, sizeof(enc_data),
				  huk.key, sizeof(huk.key))) {
		ret = TEE_ERROR_GENERIC;
		goto cleanup;
	}

cleanup:
	memzero_explicit(enc_data, sizeof(enc_data));
	memzero_explicit(dna, sizeof(dna));
	memzero_explicit(sha, sizeof(sha));

	if (ret)
		return ret;

	huk.ready = true;
out:
	memcpy(hwkey->data, huk.key, HW_UNIQUE_KEY_LENGTH);
	return TEE_SUCCESS;
}
