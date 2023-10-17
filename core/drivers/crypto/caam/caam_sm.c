// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2023 NXP
 */
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_hal_sm.h>
#include <caam_jr.h>
#include <caam_status.h>
#include <caam_sm.h>
#include <tee_api_defines.h>

/*
 * Secure memory module private data
 */
static struct sm_privdata {
	vaddr_t baseaddr;  /* Secure memory base address */
	vaddr_t ctrl_addr; /* CAAM base address */
	vaddr_t jr_addr;   /* Job Ring base address */
	paddr_t jr_offset; /* Job Ring offset */
} sm_privdata;

enum caam_status caam_sm_alloc(const struct caam_sm_page_desc *page_desc,
			       struct caam_sm_page_addr *page_addr)
{
	enum caam_status ret = CAAM_FAILURE;

	if (!page_desc || !page_addr)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = caam_hal_sm_check_page_partition(sm_privdata.jr_addr, page_desc);
	if (ret != CAAM_NO_ERROR) {
		SM_TRACE("Pages %u to %u or partition %u are out of bounds",
			 page_desc->page,
			 page_desc->page + page_desc->page_count - 1,
			 page_desc->partition);
		return ret;
	}

	/* Check if partition is already allocated */
	if (!caam_hal_sm_prtn_is_free(sm_privdata.jr_addr,
				      page_desc->partition)) {
		SM_TRACE("Partition %u not available", page_desc->partition);
		return CAAM_BUSY;
	}

	/* Open secure memory partition to all groups */
	caam_hal_sm_open_access_perm(sm_privdata.jr_addr, page_desc->partition);
	caam_hal_sm_set_access_all_group(sm_privdata.jr_addr,
					 page_desc->partition);

	ret = caam_hal_sm_allocate_page(sm_privdata.jr_addr, page_desc);
	if (ret != CAAM_NO_ERROR) {
		SM_TRACE("Error allocation Pages %u to %u into partition %u",
			 page_desc->page,
			 page_desc->page + page_desc->page_count - 1,
			 page_desc->partition);

		/* Free all potientiel pages allocated before failure */
		return caam_hal_sm_deallocate_pages(sm_privdata.jr_addr,
						    page_desc);
	}

	page_addr->paddr = caam_hal_ctrl_get_smvaddr(sm_privdata.ctrl_addr,
						     sm_privdata.jr_offset) +
			   caam_hal_sm_get_pages_size(sm_privdata.jr_addr,
						      page_desc->page);
	page_addr->vaddr = sm_privdata.baseaddr +
			   caam_hal_sm_get_pages_size(sm_privdata.jr_addr,
						      page_desc->page);

	SM_TRACE("Partition %u Pages %u to %u allocated @0x%" PRIxVA
		 " (phys 0x@%" PRIxPA,
		 page_desc->partition, page_desc->page,
		 page_desc->page + page_desc->page_count - 1, page_addr->vaddr,
		 page_addr->paddr);

	return CAAM_NO_ERROR;
}

enum caam_status caam_sm_free(const struct caam_sm_page_desc *page_desc)
{
	enum caam_status ret = CAAM_FAILURE;

	SM_TRACE("Free Secure Memory pages %u to %u from partition %u",
		 page_desc->page, page_desc->page + page_desc->page_count,
		 page_desc->partition);

	/*
	 * De-allocate partition. It automatically releases partition's pages
	 * to the pool of available pages. if the partition if marked as CSP,
	 * pages will be zeroized. If the partition is marked as PSP,
	 * partition and pages will not be de-allocated and a PSP will be
	 * returned.
	 */
	if (!caam_hal_sm_prtn_is_owned(sm_privdata.jr_addr,
				       page_desc->partition)) {
		SM_TRACE("Partition %u not owned by used JR",
			 page_desc->partition);
		return TEE_ERROR_ACCESS_DENIED;
	}

	ret = caam_hal_sm_deallocate_pages(sm_privdata.jr_addr, page_desc);
	if (ret) {
		SM_TRACE("De-alloc pages %u to %u error 0x%" PRIx32,
			 page_desc->page,
			 page_desc->page + page_desc->page_count, ret);

		return ret;
	}

	ret = caam_hal_sm_deallocate_partition(sm_privdata.jr_addr,
					       page_desc->partition);
	if (ret) {
		SM_TRACE("De-alloc partition %u error 0x%" PRIx32,
			 page_desc->partition, ret);
		return ret;
	}

	return CAAM_NO_ERROR;
}

enum caam_status
caam_sm_set_access_perm(const struct caam_sm_page_desc *page_desc,
			unsigned int grp1_perm, unsigned int grp2_perm)
{
	uint32_t grp1 = UINT32_MAX;
	uint32_t grp2 = UINT32_MAX;

	if (!page_desc)
		return CAAM_BAD_PARAM;

	/* Check if the partition is already owned */
	if (!caam_hal_sm_prtn_is_owned(sm_privdata.jr_addr,
				       page_desc->partition)) {
		SM_TRACE("Partition %d not owned by current JR",
			 page_desc->partition);
		return CAAM_FAILURE;
	}

	/*
	 * Set ourself to access Secure Memory group 1 and/or group 2
	 * function if @grp1_perm and/or @grp2_perm not equal 0.
	 *
	 * The Access Group is related to the Job Ring owner setting without
	 * the Secure Bit setting already managed by the Job Ring.
	 */
	if (grp1_perm)
		grp1 = JROWN_ARM_NS;

	if (grp2_perm)
		grp2 = JROWN_ARM_NS;

	caam_hal_sm_set_access_group(sm_privdata.jr_addr, page_desc->partition,
				     grp1, grp2);
	caam_hal_sm_set_access_perm(sm_privdata.jr_addr, page_desc->partition,
				    grp1_perm, grp2_perm);

	return CAAM_NO_ERROR;
}

enum caam_status caam_sm_init(struct caam_jrcfg *jrcfg)
{
	if (!jrcfg)
		return CAAM_FAILURE;

	sm_privdata.ctrl_addr = jrcfg->base;
	sm_privdata.jr_addr = jrcfg->base + jrcfg->offset;
	sm_privdata.jr_offset = jrcfg->offset;
	sm_privdata.baseaddr = caam_hal_sm_get_base();

	if (!sm_privdata.baseaddr)
		return CAAM_FAILURE;

	SM_TRACE("Secure Memory Base address = 0x%" PRIxVA,
		 sm_privdata.baseaddr);
	SM_TRACE("CAAM controller address = 0x%" PRIxVA, sm_privdata.ctrl_addr);
	SM_TRACE("CAAM Job Ring address = 0x%" PRIxVA, sm_privdata.jr_addr);

	return CAAM_NO_ERROR;
}
