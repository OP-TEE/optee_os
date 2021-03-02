/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2019, Linaro Limited
 */
#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#include <util.h>

/*
 * Interface to the pseudo TA, which provides remote attestation.
 */
#define ATTESTATION_UUID \
		{ 0xa2b0b139, 0x82dc, 0x4ffc, \
			{ 0xa8, 0xa8, 0x7d, 0x7c, 0x63, 0x66, 0xe9, 0x84 } }

#define ATTESTATION_CMD_SET_DATA	0
#define ATTESTATION_CMD_GET_CERT	1

#endif /* __PTA_ATTESTATION_H */
