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

struct ptr_addr {
#ifdef CFG_CAAM_BIG_ENDIAN
	uint32_t high;
	uint32_t low;
#else
	uint32_t low;
	uint32_t high;
#endif
};

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
	uint32_t *last = desc + len;
	uint32_t inc = 1;

	/* Add Word at Last */
#ifdef CFG_CAAM_64BIT
	struct ptr_addr *ptr_addr = (struct ptr_addr *)(uintptr_t)last;

	reg_pair_from_64(ptr, &ptr_addr->high, &ptr_addr->low);
	inc++;
#else
	caam_write_val((void *)last, ptr);
#endif

	/* Increase the length */
	caam_write_val((void *)desc, caam_read_val((void *)desc) + inc);
}
