// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <crypto/crypto.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <trace.h>

#include "ice_sw_keys.h"

/*
 * Register the ICE (Inline Crypto Engine) LUT keys register region so this
 * PTA can program key slots.
 */
register_phys_mem_pgdir(MEM_AREA_IO_SEC,
			(ICE_LUT_KEYS & ~SMALL_PAGE_MASK),
			ICE_LUT_KEYS_SIZE);

/* Write ICE register */
static inline void ice_reg_write(paddr_t addr, uint32_t mask, uint32_t shift,
				 uint32_t val)
{
	vaddr_t va = (vaddr_t)phys_to_virt(addr, MEM_AREA_IO_SEC,
					   sizeof(uint32_t));

	if (mask == 0 && shift == 0)
		io_write32(va, val);
	else
		io_mask32(va, val << shift, mask);
}

/* Returns true if every byte of @key is zero. */
static bool ice_key_is_all_zeros(const uint8_t *key, uint32_t key_len)
{
	uint32_t i;

	for (i = 0; i < key_len; i++)
		if (key[i] != 0)
			return false;
	return true;
}

/*
 * Write @key_len bytes of key material into consecutive ICE CRYPTOCFG_r_n
 * registers starting at @reg_start. Each 4-byte group is packed little-endian
 * so the key bytes appear in natural order in the register file (key byte 0 in
 * the register LSB). Remaining registers up to the slot size are zero-filled.
 */
static void ice_write_key_to_regs(uint32_t index, uint32_t reg_start,
				  const uint8_t *key, uint32_t key_len)
{
	uint32_t i;
	uint32_t num_words = key_len / 4;
	uint32_t max_words = ICE_KEY_REG_SIZE / 4;

	for (i = 0; i < num_words && i < max_words; i++) {
		uint32_t word = ((uint32_t)key[i * 4 + 3] << 24) |
				((uint32_t)key[i * 4 + 2] << 16) |
				((uint32_t)key[i * 4 + 1] << 8)  |
				((uint32_t)key[i * 4 + 0]);

		ice_reg_write(ICE_CRYPTOCFG_r_n_ADDR(index, reg_start + i),
			      0, 0, word);
	}
	for (; i < max_words; i++)
		ice_reg_write(ICE_CRYPTOCFG_r_n_ADDR(index, reg_start + i),
			      0, 0, 0x0);
}

/*
 * Overwrite all data registers of key slot @index with random data.
 * Fails rather than falling back to a fixed pattern if the RNG can't be
 * read, so a slot is never left holding predictable "wiped" key material.
 */
static TEE_Result ice_wipe_key_regs(uint32_t index)
{
	uint8_t rand_data[ICE_AES256_KEY_SIZE * 2];
	uint32_t i;

	if (crypto_rng_read(rand_data, sizeof(rand_data)) != TEE_SUCCESS) {
		EMSG("ICE: RNG read failed, refusing to wipe slot %u", index);
		return TEE_ERROR_BAD_STATE;
	}

	for (i = 0; i < ICE_CRYPTOCFG_DATA_REGS; i++) {
		const uint8_t *b = &rand_data[i * 4];
		uint32_t word = ((uint32_t)b[0] << 24) |
				((uint32_t)b[1] << 16) |
				((uint32_t)b[2] << 8)  |
				((uint32_t)b[3]);

		ice_reg_write(ICE_CRYPTOCFG_r_n_ADDR(index, i),
			      0, 0, word);
	}

	return TEE_SUCCESS;
}

/*
 * Program CRYPTOCFG_r_16: cipher/capability mode (CAPIDX), the data-unit
 * size for XTS tweak calculation (DUSIZE), and finally set CFGE to mark
 * the slot's configuration valid/enabled.
 */
static void ice_configure_slot(uint32_t index, uint32_t cap_index,
			       uint32_t data_unit_size)
{
	ice_reg_write(ICE_CRYPTOCFG_r_16_ADDR(index),
		      ICE_CRYPTOCFG_r_16_CAPIDX_BMSK,
		      ICE_CRYPTOCFG_r_16_CAPIDX_SHFT, cap_index);
	ice_reg_write(ICE_CRYPTOCFG_r_16_ADDR(index),
		      ICE_CRYPTOCFG_r_16_DUSIZE_BMSK,
		      ICE_CRYPTOCFG_r_16_DUSIZE_SHFT, data_unit_size);
	ice_reg_write(ICE_CRYPTOCFG_r_16_ADDR(index),
		      ICE_CRYPTOCFG_r_16_CFGE_BMSK,
		      ICE_CRYPTOCFG_r_16_CFGE_SHFT, 0x1);
}

/*
 * Command: tzbsp_es_invalidate_ice_key port.
 * [in] params[0].value.a  key slot index
 */
TEE_Result sw_cmd_ice_invalidate_key(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	uint32_t index;

	if (param_types != exp_pt) {
		EMSG("ICE invalidate: bad param types 0x%x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	index = params[0].value.a;
	if (index >= ICE_MAX_KEY_IDX) {
		EMSG("ICE invalidate: invalid slot %u (max %u)", index,
		     ICE_MAX_KEY_IDX - 1);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Disable the slot so ICE can't use stale key data while it is wiped */
	ice_reg_write(ICE_CRYPTOCFG_r_16_ADDR(index), 0, 0, 0x0);

	/*
	 * Security wipe: overwrite all 16 registers with random data. Leave
	 * the slot disabled with the wipe left incomplete if the RNG can't
	 * be read, rather than re-arming it below with a partially wiped key.
	 */
	if (ice_wipe_key_regs(index) != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Re-arm the slot with a fixed, non-secret placeholder config
	 * instead of leaving it disabled with stale configuration, so an
	 * invalidated slot ends up in a deterministic, non-secret state.
	 */
	ice_configure_slot(index, ICE_CIPHER_MODE_XTS_256,
			   ICE_DATA_UNIT_SIZE_512);
	dsb();

	return TEE_SUCCESS;
}

/*
 * Command: tzbps_es_set_config_ice_key port. This platform only ever
 * receives raw plaintext key bytes from the kernel; there is no
 * wrapped/hardware-key variant to select between.
 * [in] params[0].value.a  key slot index
 * [in] params[0].value.b  capability index (enum ice_capability_index_type)
 * [in] params[1].value.a  data unit size (enum ice_data_unit_type)
 * [in] params[2].memref   key || salt
 */
TEE_Result sw_cmd_ice_set_config_key(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE);
	uint32_t index, cap_index, data_unit_size;
	const uint8_t *key_buf;
	uint32_t key_buf_len, key_size, salt_size;
	bool is_xts;

	if (param_types != exp_pt) {
		EMSG("ICE set_key: bad param types 0x%x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	index          = params[0].value.a;
	cap_index      = params[0].value.b;
	data_unit_size = params[1].value.a;
	key_buf        = (const uint8_t *)params[2].memref.buffer;
	key_buf_len    = params[2].memref.size;

	if (index >= ICE_MAX_KEY_IDX) {
		EMSG("ICE set_key: invalid slot %u (max %u)", index,
		     ICE_MAX_KEY_IDX - 1);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!key_buf) {
		EMSG("ICE set_key: NULL key buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* ECB modes rejected to match set_config_ice_key_common() */
	if (cap_index > ICE_CIPHER_MODE_ECB_256 ||
	    cap_index == ICE_CIPHER_MODE_ECB_128 ||
	    cap_index == ICE_CIPHER_MODE_ECB_256) {
		EMSG("ICE set_key: unsupported cap_index %u", cap_index);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (data_unit_size) {
	case ICE_DATA_UNIT_SIZE_512:
	case ICE_DATA_UNIT_SIZE_1024:
	case ICE_DATA_UNIT_SIZE_2048:
	case ICE_DATA_UNIT_SIZE_4096:
	case ICE_DATA_UNIT_SIZE_8192:
	case ICE_DATA_UNIT_SIZE_16384:
	case ICE_DATA_UNIT_SIZE_32768:
	case ICE_DATA_UNIT_SIZE_65536:
		break;
	default:
		EMSG("ICE set_key: invalid data_unit_size 0x%x",
		     data_unit_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch ((enum ice_capability_index_type)cap_index) {
	case ICE_CIPHER_MODE_XTS_128:
		key_size = ICE_AES128_KEY_SIZE; salt_size = ICE_AES128_KEY_SIZE;
		is_xts = true;  break;
	case ICE_CIPHER_MODE_CBC_128:
		key_size = ICE_AES128_KEY_SIZE; salt_size = 0;
		is_xts = false; break;
	case ICE_CIPHER_MODE_XTS_256:
		key_size = ICE_AES256_KEY_SIZE; salt_size = ICE_AES256_KEY_SIZE;
		is_xts = true;  break;
	case ICE_CIPHER_MODE_CBC_256:
		key_size = ICE_AES256_KEY_SIZE; salt_size = 0;
		is_xts = false; break;
	default:
		EMSG("ICE set_key: unhandled cap_index %u", cap_index);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (key_buf_len < (key_size + salt_size)) {
		EMSG("ICE set_key: key buf too small: got %u need %u",
		     key_buf_len, key_size + salt_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (ice_key_is_all_zeros(key_buf, key_size)) {
		EMSG("ICE set_key: all-zero key rejected");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (is_xts && ice_key_is_all_zeros(key_buf + key_size, salt_size)) {
		EMSG("ICE set_key: all-zero salt rejected");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Disable the slot so ICE can't use stale key data during reconfig */
	ice_reg_write(ICE_CRYPTOCFG_r_16_ADDR(index), 0, 0, 0x0);

	/* Configure CRYPTOCFG_r_16 (mode/data-unit/enable) before key data */
	ice_configure_slot(index, cap_index, data_unit_size);

	/*
	 * Security wipe: overwrite all 16 registers with random data. Leave
	 * the slot disabled rather than enabled over an incomplete wipe if
	 * the RNG can't be read.
	 */
	if (ice_wipe_key_regs(index) != TEE_SUCCESS) {
		ice_reg_write(ICE_CRYPTOCFG_r_16_ADDR(index), 0, 0, 0x0);
		return TEE_ERROR_BAD_STATE;
	}

	/* Program the key (and salt, for XTS) into the data registers */
	ice_write_key_to_regs(index, ICE_KEY_DATA_REG_START, key_buf, key_size);
	if (is_xts)
		ice_write_key_to_regs(index, ICE_KEY_SALT_REG_START,
				      key_buf + key_size, salt_size);
	dsb();

	return TEE_SUCCESS;
}
