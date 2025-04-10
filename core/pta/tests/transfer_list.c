// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Linaro Limited
 */

#include <kernel/transfer_list.h>
#include <mm/core_mmu.h>
#include <mm/phys_mem.h>
#include <pta_invoke_tests.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "misc.h"

#define TEST_TL_MAX_SIZE	256
#define TEST_TE2_ALIGN_POWER	4
#define TEST_TE1_ID		0xf000
#define TEST_TE2_ID		0xf0f0
#define TEST_TE3_ID		0xff00

static const char test_str1[] = "first added entry";
static const char test_str2[] = "second added entry";
static const char test_str3[] = "last added entry";

static TEE_Result test_add_te(struct transfer_list_header *tl,
			      uint16_t tag_id, uint32_t data_size,
			      const void *data, uint8_t align,
			      struct transfer_list_entry **tle)
{
	uint8_t *te_dat = NULL;
	uint8_t old_tl_align = 0;
	vaddr_t old_tl_ev = (vaddr_t)tl + tl->size;
	struct transfer_list_entry *tl_e = NULL;

	old_tl_align = tl->alignment;

	if (!align)
		tl_e = transfer_list_add(tl, tag_id, data_size, data);
	else
		tl_e = transfer_list_add_with_align(tl, tag_id, data_size, data,
						    align);

	if (!tl_e)
		return TEE_ERROR_GENERIC;

	if (tl->alignment != MAX(old_tl_align, align))
		return TEE_ERROR_CORRUPT_OBJECT;

	if (tl_e->tag_id != tag_id || tl_e->hdr_size != sizeof(*tl_e) ||
	    tl_e->data_size != data_size)
		return TEE_ERROR_CORRUPT_OBJECT;

	te_dat = transfer_list_entry_data(tl_e);

	if (!te_dat || te_dat != (uint8_t *)tl_e + sizeof(*tl_e))
		return TEE_ERROR_CORRUPT_OBJECT;

	/*
	 * If an align arg is passed in:
	 * 1. Entry data must start from an aligned address, and;
	 * 2. To align the entry data, a minimum gap should be inserted before
	 *    the new entry.
	 */
	if (align) {
		vaddr_t mask = TL_ALIGNMENT_FROM_ORDER(align) - 1;
		size_t gap_min = (~(old_tl_ev + sizeof(*tl_e)) + 1) & mask;

		if (((vaddr_t)tl_e - old_tl_ev != gap_min) ||
		    ((vaddr_t)te_dat & mask))
			return TEE_ERROR_CORRUPT_OBJECT;
	}

	if (memcmp(te_dat, data, tl_e->data_size))
		return TEE_ERROR_CORRUPT_OBJECT;

	if (!transfer_list_verify_checksum(tl))
		return TEE_ERROR_CORRUPT_OBJECT;

	*tle = tl_e;

	return TEE_SUCCESS;
}

static TEE_Result test_rm_te(struct transfer_list_header *tl,
			     uint16_t tag_id)
{
	struct transfer_list_entry *tl_e = NULL;

	tl_e = transfer_list_find(tl, tag_id);
	if (!tl_e)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (!transfer_list_rem(tl, tl_e))
		return TEE_ERROR_GENERIC;

	if (transfer_list_find(tl, tag_id))
		return TEE_ERROR_CORRUPT_OBJECT;

	if (!transfer_list_verify_checksum(tl))
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
}

static TEE_Result test_set_te_data_size(struct transfer_list_header *tl,
					struct transfer_list_entry *tl_e,
					uint32_t new_data_size)
{
	struct transfer_list_entry *old_te_next = NULL;
	struct transfer_list_entry *new_te_next = NULL;
	size_t mov_dis = 0;

	old_te_next = transfer_list_next(tl, tl_e);

	if (!transfer_list_set_data_size(tl, tl_e, new_data_size))
		return TEE_ERROR_GENERIC;

	if (!transfer_list_verify_checksum(tl))
		return TEE_ERROR_CORRUPT_OBJECT;

	new_te_next = transfer_list_next(tl, tl_e);

	/* skip the inserted void entries */
	while (new_te_next && new_te_next->tag_id == TL_TAG_EMPTY)
		new_te_next = transfer_list_next(tl, new_te_next);

	/*
	 * The followed entry moved distance must be aligned with the
	 * max alignment of the TL.
	 */
	if (new_te_next > old_te_next)
		mov_dis = (vaddr_t)new_te_next - (vaddr_t)old_te_next;
	else
		mov_dis = (vaddr_t)old_te_next - (vaddr_t)new_te_next;

	if (!IS_ALIGNED(mov_dis, TL_ALIGNMENT_FROM_ORDER(tl->alignment)))
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
}

static TEE_Result transfer_list_tests(void)
{
	struct transfer_list_header *tl = NULL;
	struct transfer_list_entry *te1 = NULL;
	struct transfer_list_entry *te2 = NULL;
	struct transfer_list_entry *te3 = NULL;
	TEE_Result ret = TEE_SUCCESS;
	tee_mm_entry_t *mm = NULL;

	mm = phys_mem_core_alloc(SMALL_PAGE_SIZE);
	if (!mm)
		return TEE_ERROR_OUT_OF_MEMORY;

	tl = transfer_list_init(tee_mm_get_smem(mm), TEST_TL_MAX_SIZE);
	if (!tl) {
		ret = TEE_ERROR_GENERIC;
		goto free_tl;
	}

	if (transfer_list_check_header(tl) == TL_OPS_NONE) {
		ret = TEE_ERROR_CORRUPT_OBJECT;
		goto unmap_tl;
	}

	if (tl->hdr_size != sizeof(*tl) ||
	    tl->alignment != TRANSFER_LIST_INIT_MAX_ALIGN ||
	    tl->size != sizeof(*tl) ||
	    tl->max_size != TEST_TL_MAX_SIZE ||
	    tl->flags != TL_FLAGS_HAS_CHECKSUM ||
	    !transfer_list_verify_checksum(tl)) {
		ret = TEE_ERROR_CORRUPT_OBJECT;
		goto unmap_tl;
	}

	/* Add a new entry following the tail without data alignment required */
	ret = test_add_te(tl, TEST_TE1_ID, sizeof(test_str1), test_str1, 0,
			  &te1);
	if (ret)
		goto unmap_tl;

	/* Add a new entry with alignment, expecting a padding before it */
	ret = test_add_te(tl, TEST_TE2_ID, sizeof(test_str2), test_str2,
			  TEST_TE2_ALIGN_POWER, &te2);
	if (ret)
		goto unmap_tl;

	/* Add a new entry following the tail without data alignment required */
	ret = test_add_te(tl, TEST_TE3_ID, sizeof(test_str3), test_str3, 0,
			  &te3);
	if (ret)
		goto unmap_tl;

	if (transfer_list_find(tl, TEST_TE1_ID) != te1 ||
	    transfer_list_find(tl, TEST_TE2_ID) != te2 ||
	    transfer_list_find(tl, TEST_TE3_ID) != te3) {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto unmap_tl;
	}

	ret = test_set_te_data_size(tl, te1, sizeof(test_str1) + 10);
	if (ret)
		goto unmap_tl;

	/* The following TEs are shifted, get the new entry */
	te2 = transfer_list_find(tl, TEST_TE2_ID);
	ret = test_set_te_data_size(tl, te2, sizeof(test_str2) - 10);
	if (ret)
		goto unmap_tl;

	/* The following TEs are shifted, get the new entry */
	te3 = transfer_list_find(tl, TEST_TE3_ID);
	ret = test_set_te_data_size(tl, te3, sizeof(test_str3) + 10);
	if (ret)
		goto unmap_tl;

	ret = test_rm_te(tl, TEST_TE2_ID);
	if (ret)
		goto unmap_tl;

	ret = test_rm_te(tl, TEST_TE3_ID);
	if (ret)
		goto unmap_tl;

	ret = test_rm_te(tl, TEST_TE1_ID);

unmap_tl:
	transfer_list_unmap_sync(tl);

free_tl:
	tee_mm_free(mm);
	return ret;
}

/* Exported entrypoint for transfer_list tests */
TEE_Result core_transfer_list_tests(uint32_t nParamTypes __unused,
				    TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	if (transfer_list_tests())
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
