/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Linaro Limited
 */

#ifndef __KERNEL_TRANSFER_LIST_H
#define __KERNEL_TRANSFER_LIST_H

#define TRANSFER_LIST_SIGNATURE		U(0x4a0fb10b)
#define TRANSFER_LIST_VERSION		U(0x0001)

/*
 * Init value of maximum alignment required by any transfer entry data in the TL
 * specified as a power of two
 */
#define TRANSFER_LIST_INIT_MAX_ALIGN	U(3)

/* Alignment required by transfer entry header start address, in bytes */
#define TRANSFER_LIST_GRANULE		U(8)

/*
 * Version of the register convention used.
 * Set to 1 for both AArch64 and AArch32 according to fw handoff spec v0.9
 */
#define REG_CONVENTION_VER_MASK BIT(24)

#define TL_FLAGS_HAS_CHECKSUM BIT(0)

/* Transfer list operation codes */
#define TL_OPS_NONE	U(0) /* invalid for any operation */
#define TL_OPS_ALL	U(1) /* valid for all operations */
#define TL_OPS_RO	U(2) /* valid for read only */
#define TL_OPS_CUS	U(3) /* either abort or special code to interpret */

#ifndef __ASSEMBLER__

#include <types_ext.h>

/* Get alignment from a value specified as power of two */
#define TL_ALIGNMENT_FROM_ORDER(a) BIT(a)

enum transfer_list_tag_id {
	TL_TAG_EMPTY = 0,
	TL_TAG_FDT = 1,
	TL_TAG_HOB_BLOCK = 2,
	TL_TAG_HOB_LIST = 3,
	TL_TAG_ACPI_TABLE_AGGREGATE = 4,
	TL_TAG_OPTEE_PAGABLE_PART = 0x100,
};

struct transfer_list_header {
	uint32_t signature;
	uint8_t checksum;
	uint8_t version;
	uint8_t hdr_size;
	uint8_t alignment;	/* max alignment of transfer entry data */
	uint32_t size;		/* TL header + all transfer entries */
	uint32_t max_size;
	uint32_t flags;
	uint32_t reserved;	/* spare bytes */
	/*
	 * Commented out element used to visualize dynamic part of the
	 * data structure.
	 *
	 * Note that struct transfer_list_entry also is dynamic in size
	 * so the elements can't be indexed directly but instead must be
	 * traversed in order
	 *
	 * struct transfer_list_entry entries[];
	 */
};

struct transfer_list_entry {
	uint16_t tag_id;
	uint8_t reserved0;	/* place holder for tag ID 3rd byte (MSB) */
	uint8_t hdr_size;
	uint32_t data_size;
	/*
	 * Commented out element used to visualize dynamic part of the
	 * data structure.
	 *
	 * Note that padding is added at the end of @data to make it reach
	 * a 8-byte boundary.
	 *
	 * uint8_t	data[ROUNDUP(data_size, 8)];
	 */
};

struct transfer_list_header *transfer_list_map(paddr_t pa);
void transfer_list_unmap_sync(struct transfer_list_header *tl);
void transfer_list_unmap_nosync(struct transfer_list_header *tl);

void transfer_list_dump(struct transfer_list_header *tl);
struct transfer_list_header *transfer_list_init(paddr_t pa, size_t max_size);

struct transfer_list_header *
transfer_list_relocate(struct transfer_list_header *tl, paddr_t pa,
		       size_t max_size);

#if defined(CFG_TRANSFER_LIST)

int transfer_list_check_header(const struct transfer_list_header *tl);

struct transfer_list_entry *transfer_list_find(struct transfer_list_header *tl,
					       uint16_t tag_id);

void *transfer_list_entry_data(struct transfer_list_entry *tl_e);

#else /* CFG_TRANSFER_LIST */

static inline int
transfer_list_check_header(const struct transfer_list_header *tl __unused)
{
	return TL_OPS_NONE;
}

static inline struct transfer_list_entry *
transfer_list_find(struct transfer_list_header *tl __unused,
		   uint16_t tag_id __unused)
{
	return NULL;
}

static inline void *
transfer_list_entry_data(struct transfer_list_entry *tl_e __unused)
{
	return NULL;
}

#endif /* CFG_TRANSFER_LIST */

void transfer_list_update_checksum(struct transfer_list_header *tl);
bool transfer_list_verify_checksum(const struct transfer_list_header *tl);

bool transfer_list_set_data_size(struct transfer_list_header *tl,
				 struct transfer_list_entry *tl_e,
				 uint32_t new_data_size);

bool transfer_list_rem(struct transfer_list_header *tl,
		       struct transfer_list_entry *tl_e);

struct transfer_list_entry *transfer_list_add(struct transfer_list_header *tl,
					      uint16_t tag_id,
					      uint32_t data_size,
					      const void *data);

struct transfer_list_entry *
transfer_list_add_with_align(struct transfer_list_header *tl, uint16_t tag_id,
			     uint32_t data_size, const void *data,
			     uint8_t alignment);

struct transfer_list_entry *
transfer_list_next(struct transfer_list_header *tl,
		   struct transfer_list_entry *last);

#endif /*__ASSEMBLER__*/
#endif /*__TRANSFER_LIST_H*/
