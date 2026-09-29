// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <arm.h>
#include <crypto/crypto.h>
#include <drivers/qcom/qfprom/qfprom.h>
#include <inttypes.h>
#include <qfprom_target.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#include "sec_elf_v2.h"

#define SHK_SIZE_BYTES	40
#define SHK_NUM_ROWS	5

TEE_Result provision_shk(const struct fuse_entry *entries, uint32_t count,
			 bool *fuses_blown)
{
	enum qfprom_error err = QFPROM_NO_ERR;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t shk[SHK_SIZE_BYTES] = {0};
	uint32_t shk_row_idx = 0;
	uint32_t data[2] = {0};
	uint8_t has_fec = 0;
	uint32_t i = 0;

	for (i = 0; i < count; i++) {
		if (entries[i].region != FUSEPROV_REGION_SHK ||
		    entries[i].operation != FUSEPROV_OP_BLOW)
			continue;

		err = qfprom_read_row(entries[i].addr, QFPROM_ADDR_SPACE_CORR,
				      data);
		if (err != QFPROM_NO_ERR)
			return TEE_ERROR_GENERIC;

		if (data[0] != 0 || data[1] != 0) {
			IMSG("SHK fuse already provisioned");
			return TEE_SUCCESS;
		}
	}

	res = crypto_rng_read(shk, sizeof(shk));
	if (res != TEE_SUCCESS)
		return res;

	shk_row_idx = 0;
	for (i = 0; i < count; i++) {
		uint32_t offset = 0;

		if (entries[i].region != FUSEPROV_REGION_SHK ||
		    entries[i].operation != FUSEPROV_OP_BLOW)
			continue;

		if (shk_row_idx >= SHK_NUM_ROWS) {
			EMSG("Too many SHK entries in SEC-ELF (max %d)",
			     SHK_NUM_ROWS);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		err = qfprom_row_has_fec_bits(entries[i].addr,
					      QFPROM_ADDR_SPACE_RAW, &has_fec);
		if (err != QFPROM_NO_ERR) {
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		offset = shk_row_idx * 8;
		memcpy(&data[0], &shk[offset], 4);
		memcpy(&data[1], &shk[offset + 4], 4);

		data[0] &= 0xFFFFFFFF;
		data[1] &= 0x00FFFFFF;

		if (has_fec)
			data[1] = qfprom_fec_63_56_bit(data[0], data[1]);

		err = qfprom_write_row(entries[i].addr, data);
		if (err != QFPROM_NO_ERR) {
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		if (fuses_blown)
			*fuses_blown = true;

		shk_row_idx++;
	}

	res = TEE_SUCCESS;

out:
	memzero_explicit(shk, sizeof(shk));
	memzero_explicit(data, sizeof(data));

	return res;
}

TEE_Result provision_oem_spare(const struct fuse_entry *entries,
			       uint32_t count, bool *fuses_blown)
{
	enum qfprom_error err = QFPROM_NO_ERR;
	TEE_Result res = TEE_SUCCESS;
	uint32_t data[2] = {0};
	uint8_t rnd[8] = {0};
	uint8_t has_fec = 0;
	uint32_t i = 0;

	for (i = 0; i < count; i++) {
		const struct fuse_entry *entry = &entries[i];

		if (entry->region != FUSEPROV_REGION_OEM_SPARE ||
		    (entry->operation != FUSEPROV_OP_BLOW &&
		     entry->operation != FUSEPROV_OP_BLOW_RANDOM))
			continue;

		err = qfprom_read_row(entry->addr, QFPROM_ADDR_SPACE_CORR,
				      data);
		if (err != QFPROM_NO_ERR) {
			EMSG("Failed to read OEM spare fuse at 0x%08"PRIx32
			     ": err=%d", entry->addr, err);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		if (data[0] != 0 || data[1] != 0) {
			IMSG("OEM spare fuse at 0x%08"PRIx32
			     " already provisioned, skipping", entry->addr);
			continue;
		}

		has_fec = 0;

		err = qfprom_row_has_fec_bits(entry->addr,
					      QFPROM_ADDR_SPACE_RAW,
					      &has_fec);
		if (err != QFPROM_NO_ERR) {
			EMSG("Failed to check FEC for addr 0x%08"PRIx32
			     ": error=%d", entry->addr, err);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		if (entry->operation == FUSEPROV_OP_BLOW) {
			data[0] = entry->lsb_val;
			data[1] = entry->msb_val;
		} else {
			res = crypto_rng_read(rnd, sizeof(rnd));
			if (res != TEE_SUCCESS) {
				EMSG("Failed to generate rand data: 0x%"PRIx32,
				     res);
				goto out;
			}

			memcpy(&data[0], &rnd[0], 4);
			memcpy(&data[1], &rnd[4], 4);
		}

		if (has_fec)
			data[1] = qfprom_fec_63_56_bit(data[0], data[1]);

		err = qfprom_write_row(entry->addr, data);
		if (err != QFPROM_NO_ERR) {
			EMSG("Failed to write OEM spare fuse at 0x%08"PRIx32
			     ": err=%d", entry->addr, err);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		if (fuses_blown)
			*fuses_blown = true;
	}

out:
	memzero_explicit(rnd, sizeof(rnd));
	memzero_explicit(data, sizeof(data));

	return res;
}
