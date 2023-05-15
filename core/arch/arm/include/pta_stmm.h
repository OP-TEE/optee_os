/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */
#ifndef __PTA_STMM_H
#define __PTA_STMM_H

/*
 * Interface to the pseudo TA, which provides a communication channel with
 * the Standalone MM SP (StMM) running at S-EL0.
 */

#define PTA_STMM_UUID { 0xed32d533, 0x99e6, 0x4209, {\
			0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98, 0xa7 } }

/*
 * Pass a buffer to Standalone MM SP
 *
 * [in/out]     memref[0]:	EFI Communication buffer
 * [out]	value[1].a:	EFI return code
 */
#define PTA_STMM_CMD_COMMUNICATE	0

#endif /* __PTA_STMM_H */

