/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TEE_MISC_H
#define TEE_MISC_H

#include <types_ext.h>

/*
 * Macro to derive hex string buffer size from binary buffer size & the
 * reverse
 */
#define TEE_B2HS_HSBUF_SIZE(x) ((x) * 2 + 1)
#define TEE_HS2B_BBUF_SIZE(x) ((x + 1) >> 1)

/*
 * binary to hex string buffer
 * Returns the number of data bytes written to the hex string
 */
uint32_t tee_b2hs(uint8_t *b, uint8_t *hs, uint32_t blen, uint32_t hslen);

/*
 * hex string to binary buffer
 * Returns the number of data bytes written to the bin buffer
 */
uint32_t tee_hs2b(uint8_t *hs, uint8_t *b, uint32_t hslen, uint32_t blen);

/*
 * Is buffer 'b' inside/outside/overlapping area 'a'?
 *
 * core_is_buffer_inside() - return true if buffer is inside memory area
 * core_is_buffer_outside() - return true if buffer is outside area
 * core_is_buffer_intersect() - return true if buffer overlaps area
 *
 * Warning: core_is_buffer_inside(x,x,x,x)==false does NOT mean
 * core_is_buffer_outside(x,x,x,x)==true.
 *
 * Arguments use by each of these routines:
 * @b - buffer start address (handled has an unsigned offset)
 * @bl - length (in bytes) of the target buffer
 * @a - memory area start address (handled has an unsigned offset)
 * @al - memory area length (in byte)
 */
#define core_is_buffer_inside(b, bl, a, al) \
	_core_is_buffer_inside((vaddr_t)(b), (size_t)(bl), \
				(vaddr_t)(a), (size_t)(al))

#define core_is_buffer_outside(b, bl, a, al) \
	_core_is_buffer_outside((vaddr_t)(b), (size_t)(bl), \
				(vaddr_t)(a), (size_t)(al))

#define core_is_buffer_intersect(b, bl, a, al) \
	_core_is_buffer_intersect((vaddr_t)(b), (size_t)(bl), \
				(vaddr_t)(a), (size_t)(al))

bool _core_is_buffer_inside(vaddr_t b, size_t bl, vaddr_t a, size_t al);
bool _core_is_buffer_outside(vaddr_t b, size_t bl, vaddr_t a, size_t al);
bool _core_is_buffer_intersect(vaddr_t b, size_t bl, vaddr_t a, size_t al);

#endif /* TEE_MISC_H */
