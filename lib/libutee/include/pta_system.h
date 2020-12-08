/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2019, Linaro Limited
 * Copyright (c) 2020, Open Mobile Platform LLC
 */
#ifndef __PTA_SYSTEM_H
#define __PTA_SYSTEM_H

#include <util.h>

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

/* Memory can be shared with other TAs */
#define PTA_SYSTEM_MAP_FLAG_SHAREABLE	BIT32(0)
/* Read/write memory */
#define PTA_SYSTEM_MAP_FLAG_WRITEABLE	BIT32(1)
/* Executable memory */
#define PTA_SYSTEM_MAP_FLAG_EXECUTABLE	BIT32(2)

/*
 * Map zero initialized memory
 *
 * [in]	    value[0].a: Number of bytes
 * [in]	    value[0].b: Flags, 0 or PTA_SYSTEM_MAP_FLAG_SHAREABLE
 * [out]    value[1].a: Address upper 32-bits
 * [out]    value[1].b: Address lower 32-bits
 * [in]     value[2].a: Extra pad before memory range
 * [in]     value[2].b: Extra pad after memory range
 */
#define PTA_SYSTEM_MAP_ZI		2

/*
 * Unmap memory
 *
 * [in]	    value[0].a: Number of bytes
 * [in]	    value[0].b: Must be 0
 * [in]	    value[1].a: Address upper 32-bits
 * [in]	    value[1].b: Address lower 32-bits
 */
#define PTA_SYSTEM_UNMAP		3

/*
 * Find and opens an TA binary and return a handle
 *
 * [in]	    memref[0]:	UUID of TA binary
 * [out]    value[1].a:	Handle to TA binary
 * [out]    value[1].b:	0
 */
#define PTA_SYSTEM_OPEN_TA_BINARY	4

/*
 * Close an TA binary handle
 *
 * When a TA is done mapping new parts of an TA binary it closes the handle
 * to free resources, established mappings remains.
 *
 * [in]     value[1].a:	Handle to TA binary
 * [in]     value[1].b:	Must be 0
 *
 * Returns TEE_SUCCESS if the TA binary was verified successfully.
 */
#define PTA_SYSTEM_CLOSE_TA_BINARY	5

/*
 * Map segment of TA binary
 *
 * Different parts of an TA binary file needs different permissions.
 * Read-write mapped parts are private to the TA, while read-only (which
 * includes execute) mapped parts are shared with other TAs. This is
 * transparent to the TA. If the supplied address in value[3] is 0 a
 * suitable address is selected, else it will either be mapped at that
 * address of an error is returned.
 *
 * [in]     value[0].a:	Handle to TA binary
 * [in]     value[0].b:	Flags, PTA_SYSTEM_MAP_FLAG_*
 * [in]     value[1].a:	Offset into TA binary, must be page aligned
 * [in]     value[1].b:	Number of bytes, the last page will be zero
 *			extended if not page aligned
 * [in/out] value[2].a:	Address upper 32-bits
 * [in/out] value[2].b:	Address lower 32-bits
 * [in]     value[3].a: Extra pad before memory range
 * [in]     value[3].b: Extra pad after memory range
 */
#define PTA_SYSTEM_MAP_TA_BINARY	6

/*
 * Copy a memory range from TA binary
 *
 * [in]     value[0].a:	Handle to TA binary
 * [in]     value[0].b:	Offset into TA binary
 * [out]    memref[1]:	Destination
 */
#define PTA_SYSTEM_COPY_FROM_TA_BINARY	7

/*
 * Set memory protection
 *
 * [in]	    value[0].a: Number of bytes
 * [in]     value[0].b:	Flags, PTA_SYSTEM_MAP_FLAG_*
 * [in]	    value[1].a: Address upper 32-bits
 * [in]	    value[1].b: Address lower 32-bits
 */
#define PTA_SYSTEM_SET_PROT		8

/*
 * Remap a segment of a TA mapping
 *
 * Moves an already mapped segment of a TA to a new address. If the
 * supplied new address is 0 a suitable address is selected, else it will
 * either be mapped at that address or an error is returned.
 *
 * [in]	    value[0].a: Number of bytes, must match length rounded up to
 *			closest page of original mapping
 * [in]     value[0].b:	Must be 0
 * [in]	    value[1].a:	Old address upper 32-bits
 * [in]     value[1].b:	Old address lower 32-bits
 * [in/out] value[2].a:	New address upper 32-bits
 * [in/out] value[2].b:	New address lower 32-bits
 * [in]     value[3].a: Extra pad before memory range
 * [in]     value[3].b: Extra pad after memory range
 */
#define PTA_SYSTEM_REMAP		9

/*
 * Load a shared library
 *
 * [in]     memref[0]: the UUID of the shared library (@filename)
 * [in]     value[1].a: @flags, must be (RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE)
 *
 * Used by: (libdl) dlopen(const char *filename, int flags)
 */
#define PTA_SYSTEM_DLOPEN               10

/*
 * Resolve a symbol in a previously loaded shared library or in the whole TA
 *
 * [in]     memref[0]: the UUID of the shared library, or the nil UUID to
 *                     search the whole TA
 * [in]     memref[1]: symbol name (@symbol)
 * [out]    value[2]: address of the symbol or NULL
 *
 * Used by: (libdl) dlsym(void *handle, const char *symbol)
 */
#define PTA_SYSTEM_DLSYM                11

/*
 * Retrieves a copy of the TPM Event log held in secure memory.
 *
 * [out]    memref[0]: Pointer to the buffer where to store the event log.
 */
#define PTA_SYSTEM_GET_TPM_EVENT_LOG	12

/*
 * Invoke a tee-supplicant's plugin
 *
 * [in]     memref[0]        uuid of the plugin (TEE_UUID)
 * [in]     value[1].a       command for the plugin
 * [in]     value[1].b       sub_command for the plugin
 * [in/out] memref[2]        additional data for the plugin
 * [out]    value[3].a       output length of data
 */
#define PTA_SYSTEM_SUPP_PLUGIN_INVOKE	13

#endif /* __PTA_SYSTEM_H */
