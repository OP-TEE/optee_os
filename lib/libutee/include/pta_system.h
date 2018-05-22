/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef __PTA_SYSTEM_H
#define __PTA_SYSTEM_H

/*
 * Interface to the pseudo TA, which is provides misc. auxiliary services,
 * extending existing GlobalPlatform Core API
 */

#define PTA_SYSTEM_UUID { 0x3a2f8978, 0x5dc0, 0x11e8, { \
			 0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc } }

/*
 * Add (re-seed) caller-provided entropy to the RNG pool. Keymaster
 * implementations need to securely mix the provided entropy into their pool,
 * which also must contain internally-generated entropy from a hardware random
 * number generator.
 *
 * [in]     memref[0]: entropy input data
 */
#define PTA_SYSTEM_ADD_RNG_ENTROPY	0

#endif /* __PTA_SYSTEM_H */
