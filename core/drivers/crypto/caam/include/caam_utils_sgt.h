/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019, 2021 NXP
 *
 * Brief   Scatter-Gather Table management utilities header.
 */
#ifndef __CAAM_UTILS_SGT_H__
#define __CAAM_UTILS_SGT_H__

#include <caam_types.h>
#include <utee_types.h>

#define BP_SGT_V2_OFFSET	48
#define BS_SGT_V2_OFFSET	12
#define SGT_V2_OFFSET_MAX_VALUE GENMASK_64(BS_SGT_V2_OFFSET - 1, 0)
#define BM_SGT_V2_OFFSET \
	SHIFT_U64(GENMASK_64(BS_SGT_V2_OFFSET - 1, 0), BP_SGT_V2_OFFSET)
#define BV_SGT_V2_OFFSET(_x) SHIFT_U64(((uint64_t)_x), BP_SGT_V2_OFFSET)
#define SGT_V2_ENTRY_OFFSET(_x) \
	((((uint64_t)_x) & BM_SGT_V2_OFFSET) >> BP_SGT_V2_OFFSET)

#define BP_SGT_V2_AVAIL_LENGTH	      0
#define BS_SGT_V2_AVAIL_LENGTH	      32
#define SGT_V2_AVAIL_LENGTH_MAX_VALUE GENMASK_64(BS_SGT_V2_AVAIL_LENGTH - 1, 0)
#define BM_SGT_V2_AVAIL_LENGTH \
	SHIFT_U64(SGT_V2_AVAIL_LENGTH_MAX_VALUE, BP_SGT_V2_AVAIL_LENGTH)
#define BV_SGT_V2_AVAIL_LENGTH(_x) \
	SHIFT_U64(((uint64_t)_x), BP_SGT_V2_AVAIL_LENGTH)
#define SGT_V2_ENTRY_AVAIL_LENGTH(_x) \
	((((uint64_t)_x) & BM_SGT_V2_AVAIL_LENGTH) >> BP_SGT_V2_AVAIL_LENGTH)

#define BP_SGT_V2_F   63
#define BM_SGT_V2_F   BIT64(BP_SGT_V2_F)
#define BP_SGT_V2_IVP 46
#define BM_SGT_V2_IVP BIT64(BP_SGT_V2_IVP)

/*
 * Scatter/Gather Table type for input and output data
 */
union caamsgt {
	struct {
		/* W0 - Address pointer (MS 8 LSBs) */
		uint32_t ptr_ms;
		/* W1 - Address pointer (LS 32 bits) */
		uint32_t ptr_ls;
		/* W2 - Length 30bits, 1bit Final, 1bit Extension */
		uint32_t len_f_e;
		/* W3- Offset in memory buffer (13 LSBs) */
		uint32_t offset;
	} v1;
	struct {
		uint64_t w1; /* Address of the data */
		uint64_t w2; /* Final bit, offset and length */
	} v2;
};

/*
 * Data buffer encoded in SGT format
 */
struct caamsgtbuf {
	union caamsgt *sgt;  /* SGT Array */
	struct caambuf *buf; /* Buffer Array */
	unsigned int number; /* Number of SGT/Buf */
	size_t length;	     /* Total length of the data encoded */
	paddr_t paddr;	     /* Physical address to use in CAAM descriptor */
	bool sgt_type;	     /* Define the data format */
};

/*
 * Allocate data of type struct caamsgtbuf
 *
 * @data    [out] Data object allocated
 */
enum caam_status caam_sgtbuf_alloc(struct caamsgtbuf *data);

/*
 * Free data of type struct caamsgtbuf
 *
 * @data    Data object to free
 */
void caam_sgtbuf_free(struct caamsgtbuf *data);

/*
 * Cache operation on SGT table
 *
 * @op     Cache operation
 * @insgt  SGT table
 * @length Length of data to maintain
 */
void caam_sgt_cache_op(enum utee_cache_operation op, struct caamsgtbuf *insgt,
		       size_t length);

/*
 * Set a Scatter Gather Table Entry
 *
 * @sgt      SGT entry
 * @paddr    Data's physical address
 * @len      Data's length
 * @offset   Offset to start in data buffer
 * @final_e  Final entry in the table if true
 */
void caam_sgt_set_entry(union caamsgt *sgt, vaddr_t paddr, size_t len,
			unsigned int offset, bool final_e);

#define CAAM_SGT_ENTRY(sgt, paddr, len) \
	caam_sgt_set_entry(sgt, paddr, len, 0, false)
#define CAAM_SGT_ENTRY_FINAL(sgt, paddr, len) \
	caam_sgt_set_entry(sgt, paddr, len, 0, true)

/*
 * Build a SGT object with @data buffer.
 * If the @data buffer is a buffer mapped on non-contiguous physical areas,
 * convert it in SGT entries.
 * Fill the CAAM SGT table with the buffer list in @sgt parameter
 *
 * @sgt [in/out] SGT buffer list and table
 */
void caam_sgt_fill_table(struct caamsgtbuf *sgt);

/*
 * Derive a CAAM SGT table from the @from SGT table starting @offset.
 * Allocate the resulting SGT table derived.
 *
 * @sgt     [out] SGT buffer list and table
 * @from    Input SGT table
 * @offset  Offset to start
 * @length  Length of the new SGT data
 */
enum caam_status caam_sgt_derive(struct caamsgtbuf *sgt,
				 const struct caamsgtbuf *from, size_t offset,
				 size_t length);

/*
 * Print the details of an SGT entry using the trace macro
 *
 * @idx [in]Index of the sgt to print
 * @sgt [in] SGT buffer list and table
 */
void sgt_entry_trace(unsigned int idx, const struct caamsgtbuf *sgt);

/*
 * Add an @offset to the SGT entry
 *
 * @sgt     [in/out] Sgt entry
 * @offset  Offset to add
 */
void sgt_entry_offset(union caamsgt *sgt, unsigned int offset);

#endif /* __CAAM_UTILS_SGT_H__ */
