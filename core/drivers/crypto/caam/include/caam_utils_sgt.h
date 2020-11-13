/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Scatter-Gather Table management utilities header.
 */
#ifndef __CAAM_UTILS_SGT_H__
#define __CAAM_UTILS_SGT_H__

#include <caam_common.h>
#include <utee_types.h>

/*
 * Cache operation on SGT table
 *
 * @op     Cache operation
 * @insgt  SGT table
 */
void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt);

/*
 * Set a Scatter Gather Table Entry
 *
 * @sgt      SGT entry
 * @paddr    Data's physical address
 * @len      Data's length
 * @offset   Offset to start in data buffer
 * @final_e  Final entry in the table if true
 * @ext_e    Entry is a SGT table extension
 */
void caam_sgt_set_entry(struct caamsgt *sgt, vaddr_t paddr, size_t len,
			unsigned int offset, bool final_e, bool ext_e);

#define CAAM_SGT_ENTRY(sgt, paddr, len)                                        \
	caam_sgt_set_entry(sgt, paddr, len, 0, false, false)
#define CAAM_SGT_ENTRY_FINAL(sgt, paddr, len)                                  \
	caam_sgt_set_entry(sgt, paddr, len, 0, true, false)
#define CAAM_SGT_ENTRY_EXT(sgt, paddr, len)                                    \
	caam_sgt_set_entry(sgt, paddr, len, 0, false, true)

/*
 * Build a SGT object with @block and @data buffer.
 * If @block is not null, create a SGT with block buffer as first SGT entry
 * and then the @data.
 * If the @data buffer is a User buffer mapped on multiple Small Page,
 * convert it in SGT entries corresponding to physical Small Page.
 *
 * @sgtbuf [out] SGT object built
 * @block  If not NULL, data block to be handled first
 * @data   Operation data
 */
enum caam_status caam_sgt_build_block_data(struct caamsgtbuf *sgtbuf,
					   struct caamblock *block,
					   struct caambuf *data);

#endif /* __CAAM_UTILS_SGT_H__ */
