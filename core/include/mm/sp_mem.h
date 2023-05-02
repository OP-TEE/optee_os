/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2022, Arm Limited.
 */

#ifndef __MM_SP_MEM_H
#define __MM_SP_MEM_H

#include <ffa.h>
#include <mm/fobj.h>
#include <sys/queue.h>

struct sp_mem;

/*
 * struct sp_mem_receiver - Memory object instance for a FF-A receiver endpoint
 *
 * @perm: Receiver permission on the shared memory
 * @ref_count: Count retrieve requests from endpoint
 * @smem: Shared memory reference
 * @link: Link in related list
 */
struct sp_mem_receiver {
	struct ffa_mem_access_perm perm;
	uint8_t ref_count;
	struct sp_mem *smem;

	SLIST_ENTRY(sp_mem_receiver) link;
};

/*
 * sp_mem_map_region represents the memory address when using FF-A shares.
 * Instead of storing the physical addresses and the size of the region, we use
 * the mobj's which were already used by the SPs. The offset is used to point
 * to the specific location inside the mobj memory range.
 */
struct sp_mem_map_region {
	struct mobj *mobj;
	/*
	 * Offset (in pages) inside the mobj which is used to retrieve the
	 * location.
	 */
	uint32_t page_offset;
	uint32_t page_count;

	SLIST_ENTRY(sp_mem_map_region) link;
};

SLIST_HEAD(sp_mem_receiver_head, sp_mem_receiver);
SLIST_HEAD(sp_mem_regions_head, sp_mem_map_region);

/*
 * sp_mem is used as the main place to store the FF-A shares information.
 * For each FFA_SHARE message a new sp_mem object is created.
 * The receivers field is used to store all receiver specific information.
 * The regions field is used to store all data needed for retrieving the
 * shared addresses.
 */
struct sp_mem {
	struct sp_mem_regions_head regions;
	struct sp_mem_receiver_head receivers;
	/* Data which was passed inside struct ffa_mem_transaction */
	uint16_t sender_id;
	uint8_t mem_reg_attr;
	uint32_t flags;
	uint64_t global_handle;
	uint64_t tag;

	SLIST_ENTRY(sp_mem) link;
};

struct sp_mem *sp_mem_new(void);
struct sp_mem_receiver *sp_mem_get_receiver(uint32_t s_id, struct sp_mem *smem);
struct sp_mem *sp_mem_get(uint64_t handle);

bool sp_mem_is_shared(struct sp_mem_map_region *new_reg);
void *sp_mem_get_va(const struct user_mode_ctx *uctx, size_t offset,
		    struct mobj *mobj);
void sp_mem_remove(struct sp_mem *s_mem);
void sp_mem_add(struct sp_mem *smem);
struct mobj *sp_mem_new_mobj(uint64_t pages, uint32_t mem_type, bool is_secure);
int sp_mem_add_pages(struct mobj *mobj, unsigned int *idx,
		     paddr_t pa, unsigned int num_pages);
#endif /*__MM_SP_MEM_H*/
