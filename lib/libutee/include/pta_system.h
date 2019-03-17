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

/*
 * libdl - dlopen(const char *filename, int flags)
 *
 * [in]     memref[0]: the UUID of the shared library to open (@filename)
 * [in]     value[1].a: @flags, must be (RTLD_NOW | RTLD_GLOBAL)
 */
#define PTA_SYSTEM_DLOPEN		1

/*
 * libdl - dlsym(void *handle, const char *symbol)
 *
 * [in]     memref[0]: the UUID that corresponds to @handle
 * [in]     memref[1]: @symbol
 * [out]    value[2]: address of the symbol or NULL
 */
#define PTA_SYSTEM_DLSYM		2

#endif /* __PTA_SYSTEM_H */
