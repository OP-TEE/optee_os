// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */
#include <ele.h>
#include <key_mgmt.h>
#include <memutils.h>
#include <string.h>

#define ELE_CMD_GENERATE_KEY	0x42

TEE_Result imx_ele_generate_keypair(uint8_t *priv_key_buf,
				    size_t priv_key_size,
				    uint8_t *public_key_buf,
				    size_t public_key_size,
				    uint16_t key_type,
				    size_t key_size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf pub_key = { };
	struct imx_ele_buf priv_key = { };
	/*
	 * For plain-text key generation the key_mgmt_handle, key_group,
	 * key_lifetime, key_usage, permitted_algo and key_lifecycle fields
	 * are reserved and must be zero.  Only the plain-key flag, the key
	 * type, the security size and the DMA buffer addresses are relevant.
	 */
	struct gen_key_cmd {
		uint32_t key_mgmt_handle;
		uint32_t private_key_addr;
		uint16_t public_key_size;
		uint16_t key_group;
		uint16_t key_type;
		uint16_t key_size;
		uint32_t key_lifetime;
		uint32_t key_usage;
		uint32_t permitted_algo;
		uint32_t key_lifecycle;
		uint8_t flags;
		uint8_t reserved;
		uint16_t private_key_size;
		uint32_t public_key_addr;
		uint32_t crc;
	} __packed cmd = { };
	struct imx_mu_msg msg = { };

	if (!priv_key_buf || !public_key_buf ||
	    !priv_key_size || !public_key_size || !key_size_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&pub_key, NULL, public_key_size);
	if (res) {
		EMSG("Public key buffer allocation failed");
		return res;
	}

	res = imx_ele_buf_alloc(&priv_key, NULL, priv_key_size);
	if (res) {
		EMSG("Private key buffer allocation failed");
		goto free_pub;
	}

	cmd.private_key_addr = priv_key.paddr_lsb;
	cmd.private_key_size = (uint16_t)priv_key.size;
	cmd.public_key_size = (uint16_t)pub_key.size;
	cmd.public_key_addr = pub_key.paddr_lsb;
	cmd.key_type = key_type;
	cmd.key_size = (uint16_t)key_size_bits;
	cmd.flags = IMX_ELE_FLAG_PLAINTEXT_KEY;
	cmd.crc = 0;

	msg.header.version = ELE_VERSION_HSM;
	msg.header.size = SIZE_MSG_32(cmd);
	msg.header.tag = ELE_REQUEST_TAG;
	msg.header.command = ELE_CMD_GENERATE_KEY;

	memcpy(msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&msg);

	res = imx_ele_call(&msg);
	if (res) {
		EMSG("Key generation failed: %#" PRIx32, res);
		goto free_priv;
	}

	res = imx_ele_buf_copy(&pub_key, public_key_buf, public_key_size);
	if (res) {
		EMSG("Public key copy failed");
		goto free_priv;
	}

	res = imx_ele_buf_copy(&priv_key, priv_key_buf, priv_key_size);
	if (res)
		EMSG("Private key copy failed");

free_priv:
	imx_ele_buf_free(&priv_key);
free_pub:
	imx_ele_buf_free(&pub_key);

	return res;
}
