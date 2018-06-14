/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#ifndef __SKS_TA_H__
#define __SKS_TA_H__

#include <sys/types.h>
#include <stdint.h>
#include <util.h>

#define TA_SKS_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			{ 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/*
 * SKS_CMD_PING		Acknowledge TA presence
 *
 * param#0: none
 * param#1: none
 * param#2: none
 * param#3: none
 */
#define SKS_CMD_PING			0x00000000

#endif /*__SKS_TA_H__*/
