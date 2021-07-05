/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * Copyright (c) 2021, Arm Limited.
 */

#ifndef __MM_MOBJ_FFA_H
#define __MM_MOBJ_FFA_H

#include <compiler.h>
#include <ffa.h>
#include <mm/core_memprot.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <string_ext.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <types_ext.h>

#include <optee_msg.h>

SLIST_HEAD(sp_shared_mem_head_t, sp_mem_access_descr);

struct mobj_ffa {
	struct mobj mobj;
	uint64_t cookie;
	tee_mm_entry_t *mm;
	struct refcount mapcount;
	uint16_t page_offset;
#ifdef CFG_CORE_SEL1_SPMC
	bool registered_by_cookie;
	bool unregistered_by_cookie;
	enum buf_is_attr attr;
	struct ffa_mem_transaction transaction;
	struct sp_shared_mem_head_t sp_head;
#endif

	SLIST_ENTRY(mobj_ffa) link;
	paddr_t pages[];
};

struct mobj *mobj_ffa_get_by_cookie(uint64_t cookie,
				    unsigned int internal_offs);

TEE_Result mobj_ffa_unregister_by_cookie(uint64_t cookie);

/* Functions for SPMC */
#ifdef CFG_CORE_SEL1_SPMC
struct mobj_ffa *mobj_ffa_sel1_spmc_new(unsigned int num_pages,
					enum buf_is_attr attr
					);
void mobj_ffa_sel1_spmc_delete(struct mobj_ffa *mobj);
TEE_Result mobj_ffa_sel1_spmc_reclaim(uint64_t cookie);
#endif
#ifdef CFG_CORE_SEL2_SPMC
struct mobj_ffa *mobj_ffa_sel2_spmc_new(uint64_t cookie,
					unsigned int num_pages);
void mobj_ffa_sel2_spmc_delete(struct mobj_ffa *mobj);
#endif

uint64_t mobj_ffa_get_cookie(struct mobj_ffa *mobj);
TEE_Result mobj_ffa_add_pages_at(struct mobj_ffa *mobj, unsigned int *idx,
				 paddr_t pa, unsigned int num_pages);
uint64_t mobj_ffa_push_to_inactive(struct mobj_ffa *mobj);
void *mobj_ffa_get_va(struct mobj *mobj, size_t offset);
size_t mobj_ffa_get_page_count(struct mobj_ffa *mf);
struct mobj_ffa *to_mobj_ffa(struct mobj *mobj);

TEE_Result ffa_get_pa(struct mobj *mobj, size_t offset,
		      size_t granule, paddr_t *pa);
bool mobj_ffa_pa_is_shared(paddr_t pa, size_t page_count);

#endif /*__MM_MOBJ_FFA_H*/

