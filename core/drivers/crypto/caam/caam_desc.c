// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   Descriptor construction functions.
 */
#include <caam_desc_helper.h>
#include <caam_io.h>
#include <types_ext.h>
#include <trace.h>

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

/* Return higher 32 bits of physical address */
#define PHYS_ADDR_HI(phys_addr) (uint32_t)(((uint64_t)phys_addr) >> 32)

/* Return lower 32 bits of physical address */
#define PHYS_ADDR_LO(phys_addr) (uint32_t)(((uint64_t)phys_addr) & UINT32_MAX)

uint32_t caam_desc_get_len(uint32_t *desc)
{
	return GET_JD_DESCLEN(caam_read_val((void *)desc));
}

/* Initialize the descriptor */
void caam_desc_init(uint32_t *desc)
{
	*desc = 0;
}

void caam_desc_update_hdr(uint32_t *desc, uint32_t word)
{
	/* Update first word of desc */
	caam_write_val((void *)desc, word);
}

void caam_desc_add_word(uint32_t *desc, uint32_t word)
{
	uint32_t len = caam_desc_get_len(desc);
	uint32_t *last = desc + len;

	/* Add Word at Last */
	caam_write_val((void *)last, word);

	/* Increase the length */
	caam_write_val((void *)desc, caam_read_val((void *)desc) + 1);
}

/* Add Pointer to the descriptor */
void caam_desc_add_ptr(uint32_t *desc, paddr_t ptr)
{
	uint32_t len = caam_desc_get_len(desc);

	/* Add Word at Last */
	uint32_t *last = desc + len;
	uint32_t inc = 1;

#ifdef CFG_CAAM_64BIT
	union ptr_addr *ptr_addr = (union ptr_addr *)(uintptr_t)last;

	caam_write_val((void *)(&ptr_addr->m_halves.high), PHYS_ADDR_HI(ptr));
	caam_write_val((void *)(&ptr_addr->m_halves.low), PHYS_ADDR_LO(ptr));
	inc++;
#else
	caam_write_val((void *)last, ptr);
#endif

	/* Increase the length */
	caam_write_val((void *)desc, caam_read_val((void *)desc) + inc);
}
