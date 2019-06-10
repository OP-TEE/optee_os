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
 * Having keys with too few bits impose a potential security risk, hence set a
 * lower bound of 128 bits.
 */
#define TA_DERIVED_KEY_MIN_SIZE		16

/* Same value as max in huk_subkey_derive */
#define TA_DERIVED_KEY_MAX_SIZE		32

#define TA_DERIVED_EXTRA_DATA_MAX_SIZE	1024

/*
 * Add (re-seed) caller-provided entropy to the RNG pool. Keymaster
 * implementations need to securely mix the provided entropy into their pool,
 * which also must contain internally-generated entropy from a hardware random
 * number generator.
 *
 * [in]     memref[0]: entropy input data
 */
#define PTA_SYSTEM_ADD_RNG_ENTROPY	0

/*
 * Derives a device and TA unique key. The caller can also provide extra data
 * that will be mixed together with existing device unique properties. If no
 * extra data is provided, then the derived key will only use device unique
 * properties and caller TA UUID.
 *
 * [in]  params[0].memref.buffer     Buffer for extra data
 * [in]  params[0].memref.size       Size of extra data (max 1024 bytes)
 * [out] params[1].memref.buffer     Buffer for the derived key
 * [out] params[1].memref.size       Size of the derived key (16 to 32 bytes)
 */
#define PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY 1

#endif /* __PTA_SYSTEM_H */
