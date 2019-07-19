// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    caam_desc.c
 *
 * @brief   Descriptor construction functions.
 */
/* Global includes*/
#include <types_ext.h>

/* Local includes */
#include "caam_io.h"
#include "desc_helper.h"
#include "desc_defines.h"

/* Macros for manipulating JR registers */
union ptr_addr {
	uint64_t m_whole;
	struct {
#ifdef CFG_CAAM_BIG_ENDIAN
		uint32_t high;
		uint32_t low;
#else
		uint32_t low;
		uint32_t high;
#endif
	} m_halves;
};

// Return higher 32 bits of physical address
#define PHYS_ADDR_HI(phys_addr) \
	(uint32_t)(((uint64_t)phys_addr) >> 32)

// Return lower 32 bits of physical address
#define PHYS_ADDR_LO(phys_addr) \
	(uint32_t)(((uint64_t)phys_addr) & 0xFFFFFFFF)


uint32_t desc_get_len(uint32_t *desc)
{
	return GET_JD_DESCLEN(caam_read_val((void *)desc));
}

/* Initialize the descriptor */
void desc_init(uint32_t *desc)
{
	*desc = 0;
}

void desc_update_hdr(uint32_t *desc, uint32_t word)
{
	/* Update first word of desc */
	caam_write_val((void *)desc, word);

}

void desc_add_word(uint32_t *desc, uint32_t word)
{
	uint32_t len = GET_JD_DESCLEN(caam_read_val((void *)desc));

	uint32_t *last = desc + len;

	/* Add Word at Last */
	caam_write_val((void *)last, word);

	/* Increase the length */
	caam_write_val((void *)(desc), (caam_read_val((void *)desc) + 1));
}

/* Add Pointer to the descriptor */
void desc_add_ptr(uint32_t *desc, paddr_t ptr)
{
	uint32_t len = GET_JD_DESCLEN(caam_read_val((void *)desc));

	/* Add Word at Last */
	uint32_t *last = desc + len;
	uint32_t inc = 1;

#ifdef CFG_CAAM_64BITS
	union ptr_addr *ptr_addr = (union ptr_addr *)(uintptr_t)last;

	caam_write_val((void *)(&ptr_addr->m_halves.high), PHYS_ADDR_HI(ptr));
	caam_write_val((void *)(&ptr_addr->m_halves.low), PHYS_ADDR_LO(ptr));
	inc++;
#else
	caam_write_val((void *)last, ptr);
#endif

	/* Increase the length */
	caam_write_val((void *)(desc), (caam_read_val((void *)desc) + inc));
}
