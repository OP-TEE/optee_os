// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2021 NXP
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

#ifdef CFG_ARM64_core
	caam_write_val32(&ptr_addr->high, ptr >> 32);
#else
	caam_write_val32(&ptr_addr->high, 0);
#endif /* CFG_ARM64_core */
	caam_write_val32(&ptr_addr->low, ptr);
	inc++;
#else
	caam_write_val32((void *)last, ptr);
#endif /* CFG_CAAM_64BIT */

	/* Increase the length */
	caam_write_val32((void *)desc, caam_read_val32((void *)desc) + inc);
}

#ifdef CFG_CAAM_64BIT
void caam_desc_push(struct caam_inring_entry *in_entry, paddr_t paddr)
{
#ifdef CFG_CAAM_BIG_ENDIAN
	put_be64(&in_entry->desc, paddr);
#else
	put_le64(&in_entry->desc, paddr);
#endif /* CFG_CAAM_BIG_ENDIAN */
}

paddr_t caam_desc_pop(struct caam_outring_entry *out_entry)
{
	const uintptr_t v_desc = (uintptr_t)&out_entry->desc;
	const uint32_t *a32 = (const uint32_t *)v_desc;

#ifdef CFG_CAAM_BIG_ENDIAN
	return SHIFT_U64(get_be32(&a32[0]), 32) | get_be32(&a32[1]);
#else
	return SHIFT_U64(a32[1], 32) | a32[0];
#endif /* CFG_CAAM_BIG_ENDIAN */
}
#else /* CFG_CAAM_64BIT */
void caam_desc_push(struct caam_inring_entry *in_entry, paddr_t paddr)
{
	caam_write_val32(&in_entry->desc, paddr);
}

paddr_t caam_desc_pop(struct caam_outring_entry *out_entry)
{
	return caam_read_val32(&out_entry->desc);
}
#endif /* CFG_CAAM_64BIT */

uint32_t caam_read_jobstatus(struct caam_outring_entry *out)
{
	return caam_read_val32(&out->status);
}

void caam_desc_add_dmaobj(uint32_t *desc, struct caamdmaobj *data,
			  unsigned int pre_op)
{
	uint32_t operation = pre_op;
	size_t op_length = 0;
	uint32_t op_ext_length = 0;

	if (data->sgtbuf.sgt_type)
		operation |= CMD_SGT;

	/* Check the operation length to set extension length or not */
	switch (GET_CMD_TYPE(pre_op)) {
	case CMD_FIFO_LOAD_TYPE:
		op_length = FIFO_LOAD_LENGTH(data->sgtbuf.length);
		op_ext_length = FIFO_LOAD_EXT;
		break;

	case CMD_STORE_TYPE:
		/* Note: there is extension length for the STORE command */
		op_length = STORE_LENGTH(data->sgtbuf.length);
		break;

	case CMD_FIFO_STORE_TYPE:
		op_length = FIFO_STORE_LENGTH(data->sgtbuf.length);
		op_ext_length = FIFO_STORE_EXT;
		break;

	case CMD_KEY_TYPE:
		/* Note: there is extension length for the KEY command */
		op_length = KEY_LENGTH(data->sgtbuf.length);
		break;

	case CMD_SEQ_OUT_TYPE:
		op_length = SEQ_LENGTH(data->sgtbuf.length);
		op_ext_length = SEQ_EXT;
		break;

	default:
		break;
	}

	if (op_length == data->sgtbuf.length)
		operation |= op_length;
	else
		operation |= op_ext_length;

	caam_desc_add_word(desc, operation);
	caam_desc_add_ptr(desc, data->sgtbuf.paddr);

	if (op_length != data->sgtbuf.length)
		caam_desc_add_word(desc, data->sgtbuf.length);
}
