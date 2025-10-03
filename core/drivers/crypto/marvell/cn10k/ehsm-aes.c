// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Marvell.
 */

#include <stdint.h>
#include "ehsm.h"
#include "ehsm-aes.h"
#include "ehsm-hal.h"
#include "ehsm-security.h"

enum sec_return ehsm_aes_zeroize(struct ehsm_handle *handle)
{
	struct ehsm_command cmd = { };
	enum ehsm_status estat = STATUS_SUCCESS;

	ehsm_clear_command(&cmd);

	cmd.opcode = BCM_AES_ZEROIZE;
	estat = ehsm_command(handle, &cmd);
	if (estat != STATUS_SUCCESS)
		return (enum sec_return)estat;

	return SEC_NO_ERROR;
}

enum sec_return ehsm_aes_init(struct ehsm_handle *handle,
			      bool decrypt,
			      enum ehsm_aes_key_size key_size,
			      enum ehsm_aes_mode aes_mode,
			      uint8_t ctr_modular,
			      bool endian_swap)
{
	struct ehsm_command cmd = { };
	enum ehsm_status estat = STATUS_SUCCESS;

	if (aes_mode == EHSM_AES_MODE_CTR) {
		if (ctr_modular >= 128)
			return SEC_INVALID_PARAMETER;
	} else if (aes_mode == EHSM_AES_MODE_GCM) {
		return SEC_INVALID_PARAMETER;
	} else if (ctr_modular != 0) {
		return SEC_INVALID_PARAMETER;
	}
	if (key_size != (key_size & 0x180))
		return SEC_INVALID_PARAMETER;

	ehsm_clear_command(&cmd);

	cmd.args[0] = decrypt;
	cmd.args[1] = key_size;
	cmd.args[2] = aes_mode;
	cmd.args[3] = ctr_modular;
	cmd.args[8] = endian_swap;
	cmd.opcode = BCM_AES_INIT;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

enum sec_return ehsm_aes_gcm_init(struct ehsm_handle *handle,
				  bool decrypt,
				  uint32_t aad_size,
				  uint32_t tag_size,
				  uint32_t iv_size,
				  const uint32_t *iv,
				  bool endian_swap)
{
	struct ehsm_command cmd = { };
	enum ehsm_status estat = STATUS_SUCCESS;

	ehsm_clear_command(&cmd);

	cmd.args[0] = decrypt;
	cmd.args[1] = aad_size;
	if (tag_size < 1 || tag_size > 16)
		return SEC_INVALID_PARAMETER;
	cmd.args[2] = tag_size;
	cmd.args[3] = iv_size;
	cmd.args[4] = iv[0];
	cmd.args[5] = iv[1];
	cmd.args[6] = iv[2];
	cmd.args[7] = endian_swap;
	cmd.opcode = BCM_AES_GCM_INIT;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

enum sec_return ehsm_aes_load_key(struct ehsm_handle *handle,
				  enum ehsm_aes_key_size key_size,
				  const void *key,
				  bool secondary_key,
				  bool endian_swap)
{
	struct ehsm_command cmd = { };
	enum ehsm_status estat = STATUS_SUCCESS;

	ehsm_clear_command(&cmd);

	cmd.args[0] = key_size;
	cmd.args[1] = ehsm_addr_low(key);
	cmd.args[2] = ehsm_addr_hi(key);
	cmd.args[3] = secondary_key;
	cmd.args[5] = endian_swap;
	cmd.opcode = BCM_AES_LOAD_KEY;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

enum sec_return ehsm_aes_load_iv(struct ehsm_handle *handle,
				 const void *iv,
				 bool endian_swap)
{
	struct ehsm_command cmd = { };
	enum ehsm_status estat = STATUS_SUCCESS;

	ehsm_clear_command(&cmd);

	cmd.args[0] = ehsm_addr_low(iv);
	cmd.args[1] = ehsm_addr_hi(iv);
	cmd.args[3] = endian_swap;
	cmd.opcode = BCM_AES_LOAD_IV;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

enum sec_return ehsm_aes_process(struct ehsm_handle *handle,
				 const void *src,
				 void *dest,
				 uint64_t payload_len_byte,
				 uint32_t timeout,
				 bool is_new,
				 bool is_final,
				 bool block_tag_gen __unused,
				 struct ehsm_dtd *src_list,
				 struct ehsm_dtd *dest_list)
{
	struct ehsm_command cmd = { };
	enum ehsm_status estat = STATUS_SUCCESS;

	ehsm_clear_command(&cmd);

	if (src) {
		cmd.args[0] = ehsm_addr_low(src);
		cmd.args[1] = ehsm_addr_hi(src);
	}
	if (dest) {
		cmd.args[2] = ehsm_addr_low(dest);
		cmd.args[3] = ehsm_addr_hi(dest);
	}

	reg_pair_from_64(payload_len_byte, &cmd.args[5], &cmd.args[4]);
	cmd.args[6] = is_new;
	cmd.args[8] = timeout;
	cmd.args[10] = is_final;
	if (src_list) {
		cmd.args[12] = ehsm_addr_low(src_list);
		cmd.args[13] = ehsm_addr_hi(src_list);
	}
	if (dest_list) {
		cmd.args[14] = ehsm_addr_low(dest_list);
		cmd.args[15] = ehsm_addr_hi(dest_list);
	}
	cmd.opcode = BCM_AES_PROCESS;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}
