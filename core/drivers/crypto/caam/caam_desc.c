// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   Descriptor construction functions.
 */
#include <caam_desc_helper.h>
#include <caam_io.h>
#include <trace.h>
#include <types_ext.h>

struct ptr_addr {
#ifdef CFG_CAAM_BIG_ENDIAN
	uint32_t high;
	uint32_t low;
#else
	uint32_t low;
	uint32_t high;
#endif /* CFG_CAAM_BIG_ENDIAN */
};

uint32_t caam_desc_get_len(uint32_t *desc)
{
	return GET_JD_DESCLEN(caam_read_val32((void *)desc));
}

void caam_desc_init(uint32_t *desc)
{
	*desc = 0;
}

void caam_desc_update_hdr(uint32_t *desc, uint32_t word)
{
	/* Update first word of desc */
	caam_write_val32((void *)desc, word);
}

void caam_desc_add_word(uint32_t *desc, uint32_t word)
{
	uint32_t len = caam_desc_get_len(desc);
	uint32_t *last = desc + len;

	/* Add Word at Last */
	caam_write_val32((void *)last, word);

	/* Increase the length */
	caam_write_val32((void *)desc, caam_read_val32((void *)desc) + 1);
}

void caam_desc_add_ptr(uint32_t *desc, paddr_t ptr)
{
	uint32_t len = caam_desc_get_len(desc);
	uint32_t *last = desc + len;
	uint32_t inc = 1;

	/* Add Word at Last */
#ifdef CFG_CAAM_64BIT
	struct ptr_addr *ptr_addr = (struct ptr_addr *)(uintptr_t)last;

	caam_write_val32(&ptr_addr->high, ptr >> 32);
	caam_write_val32(&ptr_addr->low, ptr);
	inc++;
#else
	caam_write_val32((void *)last, ptr);
#endif /* CFG_CAAM_64BIT */

	/* Increase the length */
	caam_write_val32((void *)desc, caam_read_val32((void *)desc) + inc);
}

#ifdef CFG_CAAM_64BIT
void caam_desc_push(uint64_t *in_entry, paddr_t paddr)
{
#ifdef CFG_CAAM_BIG_ENDIAN
	put_be64(in_entry, paddr);
#else
	put_le64(in_entry, paddr);
#endif /* CFG_CAAM_BIG_ENDIAN */
}

paddr_t caam_desc_pop(uint64_t *out_entry)
{
#ifdef CFG_CAAM_BIG_ENDIAN
	return get_be64(out_entry);
#else
	return get_le64(out_entry);
#endif /* CFG_CAAM_BIG_ENDIAN */
}
#else /* CFG_CAAM_64BIT */
void caam_desc_push(uint32_t *in_entry, paddr_t paddr)
{
	caam_write_val32(in_entry, paddr);
}

paddr_t caam_desc_pop(uint32_t *out_entry)
{
	return caam_read_val32(out_entry);
}
#endif /* CFG_CAAM_64BIT */

uint32_t caam_read_jobstatus(uint32_t *addr)
{
	return caam_read_val32(addr);
}
