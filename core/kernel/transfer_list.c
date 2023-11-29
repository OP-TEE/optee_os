// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Linaro Limited
 */

/*******************************************************************************
 * Transfer list library compliant with the Firmware Handoff specification at:
 * https://github.com/FirmwareHandoff/firmware_handoff
 ******************************************************************************/

#include <kernel/cache_helpers.h>
#include <kernel/panic.h>
#include <kernel/transfer_list.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <util.h>

/*******************************************************************************
 * Adapt a physical address to match the maximum transfer entry data alignment
 * required by an existing transfer list.
 * Compliant with 2.4.6 of Firmware Handoff specification (v0.9).
 * @pa: Physical address for adapting.
 * @tl: Pointer to the existing transfer list.
 * Return the adapted physical address.
 ******************************************************************************/
static paddr_t get_align_base_addr(paddr_t pa,
				   struct transfer_list_header *tl)
{
	paddr_t align_mask = TL_ALIGNMENT_FROM_ORDER(tl->alignment) - 1;
	paddr_t align_off = (paddr_t)tl & align_mask;
	paddr_t new_addr = (pa & ~align_mask) + align_off;

	if (new_addr < pa)
		new_addr += TL_ALIGNMENT_FROM_ORDER(tl->alignment);

	return new_addr;
}

static void unmap_list(struct transfer_list_header *tl, size_t sz)
{
	if (core_mmu_remove_mapping(MEM_AREA_TRANSFER_LIST, tl, sz))
		panic("Failed to remove transfer list mapping");
}

struct transfer_list_header *transfer_list_map(paddr_t pa)
{
	struct transfer_list_header *tl = NULL;
	size_t sz = SMALL_PAGE_SIZE;
	size_t old_sz = 0;

	while (true) {
		tl = core_mmu_add_mapping(MEM_AREA_TRANSFER_LIST, pa, sz);
		if (!tl) {
			EMSG("Failed to map TL with PA %#"PRIxPA", size %#zx",
			     pa, sz);
			return NULL;
		}
		old_sz = sz;

		if (transfer_list_check_header(tl) == TL_OPS_NONE) {
			unmap_list(tl, sz);
			return NULL;
		}

		if (tl->max_size <= sz)
			return tl;

		sz = ROUNDUP(tl->max_size, SMALL_PAGE_SIZE);
		unmap_list(tl, old_sz);
	}
}

void transfer_list_unmap_sync(struct transfer_list_header *tl)
{
	size_t sz = tl->max_size;

	transfer_list_update_checksum(tl);
	dcache_cleaninv_range(tl, sz);
	unmap_list(tl, sz);
}

void transfer_list_unmap_nosync(struct transfer_list_header *tl)
{
	unmap_list(tl, tl->max_size);
}

void transfer_list_dump(struct transfer_list_header *tl)
{
	struct transfer_list_entry *tl_e = NULL;
	int i __maybe_unused = 0;

	if (!tl)
		return;

	DMSG("Dump transfer list:");
	DMSG("signature  %#"PRIx32, tl->signature);
	DMSG("checksum   %#"PRIx8, tl->checksum);
	DMSG("version    %#"PRIx8, tl->version);
	DMSG("hdr_size   %#"PRIx8, tl->hdr_size);
	DMSG("alignment  %#"PRIx8, tl->alignment);
	DMSG("size       %#"PRIx32, tl->size);
	DMSG("max_size   %#"PRIx32, tl->max_size);
	DMSG("flags      %#"PRIx32, tl->flags);
	while (true) {
		tl_e = transfer_list_next(tl, tl_e);
		if (!tl_e)
			break;

		DMSG("Entry %d:", i++);
		DMSG("tag_id     %#"PRIx16, tl_e->tag_id);
		DMSG("hdr_size   %#"PRIx8, tl_e->hdr_size);
		DMSG("data_size  %#"PRIx32, tl_e->data_size);
		DMSG("data_addr  %#"PRIxVA,
		     (vaddr_t)transfer_list_entry_data(tl_e));
	}
}

/*******************************************************************************
 * Creating a transfer list in a specified reserved memory region.
 * Compliant with 2.4.5 of Firmware Handoff specification (v0.9).
 * @pa: Physical address for residing the new transfer list.
 * @max_size: Maximum size of the new transfer list.
 * Return pointer to the created transfer list or NULL on error.
 ******************************************************************************/
struct transfer_list_header *transfer_list_init(paddr_t pa, size_t max_size)
{
	struct transfer_list_header *tl = NULL;
	int align = TL_ALIGNMENT_FROM_ORDER(TRANSFER_LIST_INIT_MAX_ALIGN);

	if (!pa || !max_size)
		return NULL;

	if (!IS_ALIGNED(pa, align) || !IS_ALIGNED(max_size, align) ||
	    max_size < sizeof(*tl))
		return NULL;

	tl = core_mmu_add_mapping(MEM_AREA_TRANSFER_LIST, pa, max_size);
	if (!tl)
		return NULL;

	memset(tl, 0, max_size);
	tl->signature = TRANSFER_LIST_SIGNATURE;
	tl->version = TRANSFER_LIST_VERSION;
	tl->hdr_size = sizeof(*tl);
	tl->alignment = TRANSFER_LIST_INIT_MAX_ALIGN; /* initial max align */
	tl->size = sizeof(*tl); /* initial size is the size of header */
	tl->max_size = max_size;
	tl->flags = TL_FLAGS_HAS_CHECKSUM;

	transfer_list_update_checksum(tl);

	return tl;
}

/*******************************************************************************
 * Relocating a transfer list to a specified reserved memory region.
 * Compliant with 2.4.6 of Firmware Handoff specification (v0.9).
 * @tl: Pointer to the transfer list for relocating.
 * @pa: Physical address for relocating the transfer list.
 * @max_size: Maximum size of the transfer list after relocating
 * Return pointer to the relocated transfer list or NULL on error.
 ******************************************************************************/
struct transfer_list_header *
transfer_list_relocate(struct transfer_list_header *tl, paddr_t pa,
		       size_t max_size)
{
	paddr_t new_addr = 0;
	struct transfer_list_header *new_tl = NULL;
	size_t new_max_size = 0;

	if (!tl || !pa || !max_size)
		return NULL;

	new_addr = get_align_base_addr(pa, tl);
	new_max_size = max_size - (new_addr - pa);

	/* The new space is not sufficient for the TL */
	if (tl->size > new_max_size)
		return NULL;

	new_tl = core_mmu_add_mapping(MEM_AREA_TRANSFER_LIST, new_addr,
				      new_max_size);
	if (!new_tl)
		return NULL;

	memmove(new_tl, tl, tl->size);
	new_tl->max_size = new_max_size;

	transfer_list_update_checksum(new_tl);
	transfer_list_unmap_nosync(tl);

	return new_tl;
}

/*******************************************************************************
 * Verifying the header of a transfer list.
 * Compliant with 2.4.1 of Firmware Handoff specification (v0.9).
 * @tl: Pointer to the transfer list.
 * Return transfer list operation status code.
 ******************************************************************************/
int transfer_list_check_header(const struct transfer_list_header *tl)
{
	if (!tl)
		return TL_OPS_NONE;

	if (tl->signature != TRANSFER_LIST_SIGNATURE) {
		EMSG("Bad transfer list signature %#"PRIx32, tl->signature);
		return TL_OPS_NONE;
	}

	if (!tl->max_size) {
		EMSG("Bad transfer list max size %#"PRIx32, tl->max_size);
		return TL_OPS_NONE;
	}

	if (tl->size > tl->max_size) {
		EMSG("Bad transfer list size %#"PRIx32, tl->size);
		return TL_OPS_NONE;
	}

	if (tl->hdr_size != sizeof(struct transfer_list_header)) {
		EMSG("Bad transfer list header size %#"PRIx8, tl->hdr_size);
		return TL_OPS_NONE;
	}

	if (!transfer_list_verify_checksum(tl)) {
		EMSG("Bad transfer list checksum %#"PRIx8, tl->checksum);
		return TL_OPS_NONE;
	}

	if (tl->version == 0) {
		EMSG("Transfer list version is invalid");
		return TL_OPS_NONE;
	} else if (tl->version == TRANSFER_LIST_VERSION) {
		DMSG("Transfer list version is valid for all operations");
		return TL_OPS_ALL;
	} else if (tl->version > TRANSFER_LIST_VERSION) {
		DMSG("Transfer list version is valid for read-only");
		return TL_OPS_RO;
	}

	DMSG("Old transfer list version is detected");
	return TL_OPS_CUS;
}

/*******************************************************************************
 * Enumerate the next transfer entry.
 * @tl: Pointer to the transfer list.
 * @cur: Pointer to the current transfer entry where we want to search for the
 *       next one.
 * Return pointer to the next transfer entry or NULL on error or if @cur is the
 * last entry.
 ******************************************************************************/
struct transfer_list_entry *transfer_list_next(struct transfer_list_header *tl,
					       struct transfer_list_entry *cur)
{
	struct transfer_list_entry *tl_e = NULL;
	vaddr_t tl_ev = 0;
	vaddr_t va = 0;
	vaddr_t ev = 0;
	size_t sz = 0;

	if (!tl)
		return NULL;

	tl_ev = (vaddr_t)tl + tl->size;

	if (cur) {
		va = (vaddr_t)cur;
		/* check if the total size overflow */
		if (ADD_OVERFLOW(cur->hdr_size, cur->data_size, &sz))
			return NULL;
		/* roundup to the next entry */
		if (ADD_OVERFLOW(va, sz, &va) ||
		    ROUNDUP_OVERFLOW(va, TRANSFER_LIST_GRANULE, &va))
			return NULL;
	} else {
		va = (vaddr_t)tl + tl->hdr_size;
	}

	tl_e = (struct transfer_list_entry *)va;

	if (va + sizeof(*tl_e) > tl_ev || tl_e->hdr_size < sizeof(*tl_e) ||
	    ADD_OVERFLOW(tl_e->hdr_size, tl_e->data_size, &sz) ||
	    ADD_OVERFLOW(va, sz, &ev) || ev > tl_ev)
		return NULL;

	return tl_e;
}

/*******************************************************************************
 * Calculate the byte sum (modulo 256) of a transfer list.
 * @tl: Pointer to the transfer list.
 * Return byte sum of the transfer list.
 ******************************************************************************/
static uint8_t calc_byte_sum(const struct transfer_list_header *tl)
{
	uint8_t *b = (uint8_t *)tl;
	uint8_t cs = 0;
	size_t n = 0;

	for (n = 0; n < tl->size; n++)
		cs += b[n];

	return cs;
}

/*******************************************************************************
 * Update the checksum of a transfer list.
 * @tl: Pointer to the transfer list.
 * Return updated checksum of the transfer list.
 ******************************************************************************/
void transfer_list_update_checksum(struct transfer_list_header *tl)
{
	uint8_t cs = 0;

	if (!tl || !(tl->flags & TL_FLAGS_HAS_CHECKSUM))
		return;

	cs = calc_byte_sum(tl);
	cs -= tl->checksum;
	cs = 256 - cs;
	tl->checksum = cs;
	assert(transfer_list_verify_checksum(tl));
}

/*******************************************************************************
 * Verify the checksum of a transfer list.
 * @tl: Pointer to the transfer list.
 * Return true if verified or false if not.
 ******************************************************************************/
bool transfer_list_verify_checksum(const struct transfer_list_header *tl)
{
	if (!tl)
		return false;

	if (!(tl->flags & TL_FLAGS_HAS_CHECKSUM))
		return true;

	return !calc_byte_sum(tl);
}

/*******************************************************************************
 * Update the data size of a transfer entry.
 * @tl: Pointer to the transfer list.
 * @tl_e: Pointer to the transfer entry.
 * @new_data_size: New data size of the transfer entry.
 * Return true on success or false on error.
 ******************************************************************************/
bool transfer_list_set_data_size(struct transfer_list_header *tl,
				 struct transfer_list_entry *tl_e,
				 uint32_t new_data_size)
{
	vaddr_t tl_old_ev = 0;
	vaddr_t new_ev = 0;
	vaddr_t old_ev = 0;
	vaddr_t r_new_ev = 0;
	struct transfer_list_entry *dummy_te = NULL;
	size_t gap = 0;
	size_t mov_dis = 0;
	size_t sz = 0;

	if (!tl || !tl_e)
		return false;

	tl_old_ev = (vaddr_t)tl + tl->size;

	/*
	 * Calculate the old and new end of transfer entry
	 * both must be roundup to align with TRANSFER_LIST_GRANULE
	 */
	if (ADD_OVERFLOW(tl_e->hdr_size, tl_e->data_size, &sz) ||
	    ADD_OVERFLOW((vaddr_t)tl_e, sz, &old_ev) ||
	    ROUNDUP_OVERFLOW(old_ev, TRANSFER_LIST_GRANULE, &old_ev))
		return false;

	if (ADD_OVERFLOW(tl_e->hdr_size, new_data_size, &sz) ||
	    ADD_OVERFLOW((vaddr_t)tl_e, sz, &new_ev) ||
	    ROUNDUP_OVERFLOW(new_ev, TRANSFER_LIST_GRANULE, &new_ev))
		return false;

	if (new_ev > old_ev) {
		/*
		 * Move distance should be rounded up to match the entry data
		 * alignment.
		 * Ensure that the increased size doesn't exceed the max size
		 * of TL
		 */
		mov_dis = new_ev - old_ev;
		if (ROUNDUP_OVERFLOW(mov_dis,
				     TL_ALIGNMENT_FROM_ORDER(tl->alignment),
				     &mov_dis) ||
		    tl->size + mov_dis > tl->max_size) {
			return false;
		}
		r_new_ev = old_ev + mov_dis;
		tl->size += mov_dis;
	} else {
		/*
		 * Move distance should be rounded down to match the entry data
		 * alignment.
		 */
		mov_dis = ROUNDDOWN(old_ev - new_ev,
				    TL_ALIGNMENT_FROM_ORDER(tl->alignment));
		r_new_ev = old_ev - mov_dis;
		tl->size -= mov_dis;
	}
	/* Move all following entries to fit in the expanded or shrunk space */
	memmove((void *)r_new_ev, (void *)old_ev, tl_old_ev - old_ev);

	/*
	 * Fill the gap due to round up/down with a void entry if the size of
	 * the gap is more than an entry header.
	 */
	gap = r_new_ev - new_ev;
	if (gap >= sizeof(*dummy_te)) {
		/* Create a dummy transfer entry to fill up the gap */
		dummy_te = (struct transfer_list_entry *)new_ev;
		dummy_te->tag_id = TL_TAG_EMPTY;
		dummy_te->reserved0 = 0;
		dummy_te->hdr_size = sizeof(*dummy_te);
		dummy_te->data_size = gap - sizeof(*dummy_te);
	}

	tl_e->data_size = new_data_size;

	transfer_list_update_checksum(tl);
	return true;
}

/*******************************************************************************
 * Remove a specified transfer entry from a transfer list.
 * @tl: Pointer to the transfer list.
 * @tl_e: Pointer to the transfer entry.
 * Return true on success or false on error.
 ******************************************************************************/
bool transfer_list_rem(struct transfer_list_header *tl,
		       struct transfer_list_entry *tl_e)
{
	if (!tl || !tl_e || (vaddr_t)tl_e > (vaddr_t)tl + tl->size)
		return false;

	tl_e->tag_id = TL_TAG_EMPTY;
	tl_e->reserved0 = 0;
	transfer_list_update_checksum(tl);
	return true;
}

/*******************************************************************************
 * Add a new transfer entry into a transfer list.
 * Compliant with 2.4.3 of Firmware Handoff specification (v0.9).
 * @tl: Pointer to the transfer list.
 * @tag_id: Tag ID for the new transfer entry.
 * @data_size: Data size of the new transfer entry.
 * @data: Pointer to the data for the new transfer entry.
 *        NULL to skip data copying.
 * Return pointer to the added transfer entry or NULL on error.
 ******************************************************************************/
struct transfer_list_entry *transfer_list_add(struct transfer_list_header *tl,
					      uint16_t tag_id,
					      uint32_t data_size,
					      const void *data)
{
	vaddr_t max_tl_ev = 0;
	vaddr_t tl_ev = 0;
	vaddr_t ev = 0;
	struct transfer_list_entry *tl_e = NULL;
	size_t sz = 0;

	if (!tl)
		return NULL;

	max_tl_ev = (vaddr_t)tl + tl->max_size;
	tl_ev = (vaddr_t)tl + tl->size;
	ev = tl_ev;

	/*
	 * Skip the step 1 (optional step).
	 * New transfer entry will be added into the tail
	 */
	if (ADD_OVERFLOW(sizeof(*tl_e), data_size, &sz) ||
	    ADD_OVERFLOW(ev, sz, &ev) ||
	    ROUNDUP_OVERFLOW(ev, TRANSFER_LIST_GRANULE, &ev) ||
	    ev > max_tl_ev) {
		return NULL;
	}

	tl_e = (struct transfer_list_entry *)tl_ev;
	*tl_e = (struct transfer_list_entry){
		.tag_id = tag_id,
		.hdr_size = sizeof(*tl_e),
		.data_size = data_size,
	};

	tl->size += ev - tl_ev;

	if (data)
		memmove(tl_e + tl_e->hdr_size, data, data_size);

	transfer_list_update_checksum(tl);

	return tl_e;
}

/*******************************************************************************
 * Add a new transfer entry into a transfer list with specified new data
 * alignment requirement.
 * Compliant with 2.4.4 of Firmware Handoff specification (v0.9).
 * @tl: Pointer to the transfer list.
 * @tag_id: Tag ID for the new transfer entry.
 * @data_size: Data size of the new transfer entry.
 * @data: Pointer to the data for the new transfer entry.
 * @alignment: New data alignment specified as a power of two.
 * Return pointer to the added transfer entry or NULL on error.
 ******************************************************************************/
struct transfer_list_entry *
transfer_list_add_with_align(struct transfer_list_header *tl, uint16_t tag_id,
			     uint32_t data_size, const void *data,
			     uint8_t alignment)
{
	struct transfer_list_entry *tl_e = NULL;
	vaddr_t tl_ev = 0;
	vaddr_t ev = 0;
	vaddr_t new_tl_ev = 0;
	size_t dummy_te_data_sz = 0;

	if (!tl)
		return NULL;

	tl_ev = (vaddr_t)tl + tl->size;
	ev = tl_ev + sizeof(struct transfer_list_entry);

	if (!IS_ALIGNED(ev, TL_ALIGNMENT_FROM_ORDER(alignment))) {
		/*
		 * Transfer entry data address is not aligned to the new
		 * alignment. Fill the gap with an empty transfer entry as a
		 * placeholder before adding the desired transfer entry
		 */
		new_tl_ev = ROUNDUP(ev, TL_ALIGNMENT_FROM_ORDER(alignment)) -
			    sizeof(struct transfer_list_entry);
		assert(new_tl_ev - tl_ev > sizeof(struct transfer_list_entry));
		dummy_te_data_sz = new_tl_ev - tl_ev -
				   sizeof(struct transfer_list_entry);
		if (!transfer_list_add(tl, TL_TAG_EMPTY, dummy_te_data_sz,
				       NULL)) {
			return NULL;
		}
	}

	tl_e = transfer_list_add(tl, tag_id, data_size, data);

	if (alignment > tl->alignment) {
		tl->alignment = alignment;
		transfer_list_update_checksum(tl);
	}

	return tl_e;
}

/*******************************************************************************
 * Search for an existing transfer entry with the specified tag id from a
 * transfer list.
 * @tl: Pointer to the transfer list.
 * @tag_id: Tag ID to match a transfer entry.
 * Return pointer to the found transfer entry or NULL if not found.
 ******************************************************************************/
struct transfer_list_entry *transfer_list_find(struct transfer_list_header *tl,
					       uint16_t tag_id)
{
	struct transfer_list_entry *tl_e = NULL;

	do {
		tl_e = transfer_list_next(tl, tl_e);
	} while (tl_e && tl_e->tag_id != tag_id);

	return tl_e;
}

/*******************************************************************************
 * Retrieve the data pointer of a specified transfer entry.
 * @tl_e: Pointer to the transfer entry.
 * Return pointer to the transfer entry data or NULL on error.
 ******************************************************************************/
void *transfer_list_entry_data(struct transfer_list_entry *tl_e)
{
	if (!tl_e)
		return NULL;

	return (uint8_t *)tl_e + tl_e->hdr_size;
}
