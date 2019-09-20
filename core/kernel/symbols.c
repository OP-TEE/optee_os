// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, EPAM Systems
 */

#include <stdio.h>
#include <symbols.h>
#include <util.h>

/* All extern entries are auto-generated during first and second linking pass */

/* Symbol table */
extern const struct syms_table syms_table[] __weak;
/* Number of entries in syms_table */
extern const unsigned int syms_count __weak;
/* Compressed symbol names */
extern const uint8_t syms_names[] __weak;
/* Basically, absolute address of the first symbol */
extern const vaddr_t syms_base __weak;
/* Indexes of symbols in the compressing table */
extern const uint16_t syms_token_index[257] __weak;
/* Compressing table */
extern const char syms_token_table[] __weak;

static const struct syms_table *find_symbol(vaddr_t addr, size_t *offset)
{
	unsigned int a = 0;
	unsigned int b = syms_count;

	if (addr < syms_base)
		return NULL;

	addr -= syms_base;

	/*
	 * Table is sorted and we assume that last entry points to end
	 * of OP-TEE memory.
	 */
	if (addr > syms_table[syms_count - 1].offset)
		return NULL;

	/* Perform binary search */
	while (b - a > 1) {
		unsigned int idx = a + (b - a) / 2;

		if (syms_table[idx].offset <= addr)
			a = idx;
		else
			b = idx;
	}

	if (offset)
		*offset = addr - syms_table[a].offset;

	return syms_table + a;
}

static int syms_uncompress_name(const struct syms_table *sym, char *buf,
				size_t buf_len)
{
	const uint8_t *data = syms_names + sym->name_offset;
	size_t len = MIN(sym->name_len, buf_len);
	int ret = len;

	if (buf_len > len)
		buf[len] = '\0';

	while (len) {
		const char *tok = syms_token_table + syms_token_index[*data];
		size_t tok_len = syms_token_index[*data + 1] -
			syms_token_index[*data];

		for (; tok_len && len; tok_len--, len--)
			*buf++ = *tok++;

		data++;
	}

	return ret;
}

int syms_format_name_w_offset(vaddr_t addr, char *buf, size_t buf_len)
{
	size_t offset = 0;
	int len = 0;
	const struct syms_table *sym = find_symbol(addr, &offset);

	if (!buf_len)
		return 0;

	if (!sym)
		return 0;

	*buf++ = '<';
	buf_len--;

	len = syms_uncompress_name(sym, buf, buf_len);
	buf_len -= len;
	buf += len;

	return snprintf(buf, buf_len, "+0x%zx>", offset) + 1 + len;
}

