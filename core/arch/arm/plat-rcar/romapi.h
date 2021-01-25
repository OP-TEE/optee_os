/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, EPAM Systems
 */

#ifndef __ROMAPI_H
#define __ROMAPI_H

#include <compiler.h>

/*
 * Mask ROM provides number of facilities, including function that returns 32
 * byte random vector.
 */
#define PLAT_RND_VECTOR_SZ	32

/*
 * Call to this function must be protected by a spinlock, because ROM code
 * accesses hardware. This function requires at least 4kb scratch buffer to
 * work. All parameters should be aligned to 8 bytes.
 */
uint32_t plat_rom_getrndvector(uint8_t rndbuff[PLAT_RND_VECTOR_SZ],
			       uint8_t *scratch,
			       uint32_t scratch_sz);

#endif
