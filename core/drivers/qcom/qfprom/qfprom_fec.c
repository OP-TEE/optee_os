// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/qfprom/qfprom.h>
#include <stdint.h>
#include <util.h>

uint32_t qfprom_fec_63_56_bit(uint32_t lsb_data, uint32_t msb_data)
{
	uint8_t lfsr[7] = {0};
	uint64_t data_loc = 0;
	uint32_t fec_val = 0;
	uint32_t temp = 0;
	int i = 0;

	data_loc = (SHIFT_U64(msb_data, 32)) | lsb_data;

	for (i = 0; i < 56; i++) {
		temp = lfsr[0] ^ ((data_loc >> i) & 0x1);

		lfsr[0] = lfsr[1] ^ temp;
		lfsr[1] = lfsr[2];
		lfsr[2] = lfsr[3];
		lfsr[3] = lfsr[4];
		lfsr[4] = lfsr[5] ^ temp;
		lfsr[5] = lfsr[6];
		lfsr[6] = temp;
	}

	for (i = 6; i >= 0; i--) {
		temp = SHIFT_U32(lfsr[i], i);
		fec_val = (fec_val | temp);
	}

	return (SHIFT_U32(fec_val, 24) | msb_data);
}
