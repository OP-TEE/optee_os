/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Foundries.io Ltd
 */

#ifndef __RNG_PTA__H
#define __RNG_PTA__H

#define PTA_RNG_UUID { 0x035a4479, 0xc369, 0x47f4, { \
		       0x94, 0x51, 0xc6, 0xfd, 0xff, 0x28, 0xad, 0x65 } }

/*
 * [in/out]	memref[0]	entropy buffer
 */
#define PTA_CMD_GET_ENTROPY		0

/*
 * [out]	value[0].a	RNG data-rate in bytes per second
 * [out]	value[0].b	quality/entropy per 1024 bit of data
 */
#define PTA_CMD_GET_RNG_INFO		1

#endif /* __RNG_PTA__H */
