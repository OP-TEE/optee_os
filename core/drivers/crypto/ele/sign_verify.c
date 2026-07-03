// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */
#include <ele.h>
#include <key_mgmt.h>
#include <memutils.h>
#include <sign_verify.h>
#include <string.h>

#define ELE_CMD_SIG_GENERATE		0x72
#define ELE_CMD_SIG_VERIFICATION	0x82

TEE_Result imx_ele_signature_generate(const uint8_t *priv_key,
				      size_t priv_key_size,
				      const uint8_t *message,
				      size_t message_size,
				      uint8_t *signature,
				      size_t signature_size,
				      uint32_t signature_scheme,
				      uint8_t message_type,
				      uint32_t key_type,
				      size_t key_size_bits)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf msg_buf = { };
	struct imx_ele_buf sig_buf = { };
	struct imx_ele_buf priv_key_buf = { };
	/*
	 * For plain-text signing the sig_gen_handle and key_identifier
	 * fields are reserved and must be zero.  The private key is passed
	 * directly via a DMA buffer with IMX_ELE_FLAG_PLAINTEXT_KEY set.
	 */
	struct sig_generate_cmd {
		uint32_t sig_gen_handle;
		uint32_t private_key_addr;
		uint32_t message;
		uint32_t signature;
		uint32_t message_size;
		uint16_t signature_size;
		uint8_t flags;
		uint8_t rsvd;
		uint32_t signature_scheme;
		uint16_t salt_len;
		uint16_t key_type;
		uint16_t priv_key_size;
		uint16_t keypair_sec_size;
		uint32_t crc;
	} __packed cmd = { };
	struct imx_mu_msg mu_msg = { };

	if (!priv_key || !message || !signature ||
	    !priv_key_size || !message_size || !signature_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&msg_buf, message, message_size);
	if (res) {
		EMSG("Message buffer allocation failed");
		return res;
	}

	res = imx_ele_buf_alloc(&sig_buf, NULL, signature_size);
	if (res) {
		EMSG("Signature buffer allocation failed");
		goto free_msg;
	}

	res = imx_ele_buf_alloc(&priv_key_buf, priv_key, priv_key_size);
	if (res) {
		EMSG("Private key buffer allocation failed");
		goto free_sig;
	}

	cmd.private_key_addr = priv_key_buf.paddr_lsb;
	cmd.message = msg_buf.paddr_lsb;
	cmd.signature = sig_buf.paddr_lsb;
	cmd.message_size = (uint32_t)msg_buf.size;
	cmd.signature_size = (uint16_t)sig_buf.size;
	cmd.flags = message_type | IMX_ELE_FLAG_PLAINTEXT_KEY;
	cmd.rsvd = 0;
	cmd.signature_scheme = signature_scheme;
	cmd.salt_len = 0;
	cmd.key_type = (uint16_t)key_type;
	cmd.priv_key_size = (uint16_t)priv_key_buf.size;
	cmd.keypair_sec_size = (uint16_t)key_size_bits;
	cmd.crc = 0;

	mu_msg.header.version = ELE_VERSION_HSM;
	mu_msg.header.size = SIZE_MSG_32(cmd);
	mu_msg.header.tag = ELE_REQUEST_TAG;
	mu_msg.header.command = ELE_CMD_SIG_GENERATE;

	memcpy(mu_msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&mu_msg);

	res = imx_ele_call(&mu_msg);
	if (res) {
		EMSG("Signature generation failed: %#" PRIx32, res);
		goto free_priv;
	}

	res = imx_ele_buf_copy(&sig_buf, signature, signature_size);
	if (res)
		EMSG("Signature copy failed");

free_priv:
	imx_ele_buf_free(&priv_key_buf);
free_sig:
	imx_ele_buf_free(&sig_buf);
free_msg:
	imx_ele_buf_free(&msg_buf);

	return res;
}

static TEE_Result imx_ele_sig_verify_status(uint32_t verification_status)
{
	switch (verification_status) {
	case ELE_SIG_VERIFICATION_SUCCESS:
		return TEE_SUCCESS;
	case ELE_SIG_VERIFICATION_FAILURE:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result imx_ele_signature_verify(const uint8_t *public_key,
				    size_t public_key_size,
				    const uint8_t *message,
				    size_t message_size,
				    const uint8_t *signature,
				    size_t signature_size,
				    size_t key_security_size,
				    uint16_t key_type,
				    uint32_t signature_scheme,
				    uint8_t message_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct imx_ele_buf pub_key_buf = { };
	struct imx_ele_buf msg_buf = { };
	struct imx_ele_buf sig_buf = { };
	/*
	 * For plain-text verification the sig_verify_handle field is
	 * reserved and must be zero.
	 */
	struct sig_verify_cmd {
		uint32_t sig_verify_handle;
		uint32_t key;
		uint32_t message;
		uint32_t signature;
		uint32_t message_size;
		uint16_t signature_size;
		uint16_t key_size;
		uint16_t key_security_size;
		uint16_t key_type;
		uint8_t flags;
		uint8_t rsvd[3];
		uint32_t signature_scheme;
		uint16_t salt_len;
		uint8_t rsvd2[2];
		uint32_t crc;
	} __packed cmd = { };
	struct sig_verify_rsp {
		uint32_t rsp_code;
		uint32_t verification_status;
	} rsp = { };
	struct imx_mu_msg mu_msg = { };

	if (!public_key || !message || !signature ||
	    !public_key_size || !message_size || !signature_size ||
	    !key_security_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = imx_ele_buf_alloc(&pub_key_buf, public_key, public_key_size);
	if (res) {
		EMSG("Public key buffer allocation failed");
		return res;
	}

	res = imx_ele_buf_alloc(&msg_buf, message, message_size);
	if (res) {
		EMSG("Message buffer allocation failed");
		goto free_pub;
	}

	res = imx_ele_buf_alloc(&sig_buf, signature, signature_size);
	if (res) {
		EMSG("Signature buffer allocation failed");
		goto free_msg;
	}

	cmd.key = pub_key_buf.paddr_lsb;
	cmd.message = msg_buf.paddr_lsb;
	cmd.signature = sig_buf.paddr_lsb;
	cmd.message_size = (uint32_t)msg_buf.size;
	cmd.signature_size = (uint16_t)sig_buf.size;
	cmd.key_size = (uint16_t)pub_key_buf.size;
	cmd.key_security_size = (uint16_t)key_security_size;
	cmd.key_type = key_type;
	cmd.flags = message_type;
	cmd.signature_scheme = signature_scheme;
	cmd.salt_len = 0;
	cmd.crc = 0;

	mu_msg.header.version = ELE_VERSION_HSM;
	mu_msg.header.size = SIZE_MSG_32(cmd);
	mu_msg.header.tag = ELE_REQUEST_TAG;
	mu_msg.header.command = ELE_CMD_SIG_VERIFICATION;

	memcpy(mu_msg.data.u8, &cmd, sizeof(cmd));
	update_crc(&mu_msg);

	res = imx_ele_call(&mu_msg);
	if (res) {
		EMSG("Signature verification failed: %#" PRIx32, res);
		goto free_sig;
	}

	memcpy(&rsp, mu_msg.data.u8, sizeof(rsp));
	res = imx_ele_sig_verify_status(rsp.verification_status);

free_sig:
	imx_ele_buf_free(&sig_buf);
free_msg:
	imx_ele_buf_free(&msg_buf);
free_pub:
	imx_ele_buf_free(&pub_key_buf);

	return res;
}
