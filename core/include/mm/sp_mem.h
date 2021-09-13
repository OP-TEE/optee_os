/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Arm Limited.
 */

#ifndef __MM_SP_MEM_H
#define __MM_SP_MEM_H

#include <ffa.h>
#include <mm/fobj.h>
#include <sys/queue.h>

struct sp_mem_receiver;
struct sp_mem;

/*
 * The sp_mem_receiver keeps track of the data which is specific to the
 * receiving endpoint.When sharing memory via FF-A, each FF-A endpoint can
 * have different permissions. Each of the endpoints can retrieve the share
 * multiple times. The ref_count is used to track the amount of time the
 * endpoint has retrieved the share.
 */
struct sp_mem_receiver {
	struct ffa_mem_access_perm perm;
	/* Keep track of the number of times the share has been retrieved. */
	uint8_t ref_count;
	struct sp_mem *smem;

	SLIST_ENTRY(sp_mem_receiver) link;
};

/*
 * sp_mem_map_region represents the memory address when using FF-A shares.
 * instead of storing the physical addresses and the size of the region, we use
 * the mobj's which where already used by the SPs. The offset is used to point
 * to the specific location inside the mobj memory range.
 */
struct sp_mem_map_region {
	struct mobj *mobj;
	/* Offset inside the mobj which is used to retrieve the location.*/
	uint32_t page_offset;
	uint32_t page_count;

	SLIST_ENTRY(sp_mem_map_region) link;
};

SLIST_HEAD(sp_mem_receiver_head_t, sp_mem_receiver);
SLIST_HEAD(sp_mem_regions_head_t, sp_mem_map_region);
/*
 * sp_mem is used as the main place to store the FF-A shares information.
 * For each FFA_SHARE message a new sp_mem object is created.
 * The receivers field is used to store all receiver specific information.
 * The regions field is used to store all data needed for retrieving the
 * shared addresses.
 */
struct sp_mem {
	struct sp_mem_regions_head_t regions;
	struct sp_mem_receiver_head_t receivers;

	SLIST_ENTRY(sp_mem) link;
	struct ffa_mem_transaction transaction;
};

struct sp_mem *sp_mem_new(void);
bool sp_mem_remove(struct sp_mem *s_mem);
#endif /*__MM_SP_MEM_H*/
