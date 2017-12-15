/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef READER_H
#define READER_H

#define MAX_ATR_SIZE	23

struct pcsc_reader {
	bool connected;
	uint8_t index;
	uint32_t state;
	uint32_t mmio_base;
	uint8_t atr[MAX_ATR_SIZE];
	uint8_t atr_len;
	struct tee_se_reader se_reader;
};

void init_reader(struct pcsc_reader *r, uint8_t index, uint32_t mmio_base);

#endif
