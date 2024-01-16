// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019, 2023 NXP
 */
#include <caam_sm.h>
#include <caam_common.h>
#include <caam_hal_sm.h>
#include <caam_io.h>
#include <caam_status.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <mm/core_memprot.h>
#include <registers/sm_regs.h>
#include <registers/version_regs.h>
#include <stdint.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

/*
 * Issue a Secure Memory Command to the @page and @partition.
 * Returns the command status when completed
 *
 * @jr_base    JR virtual base address
 * @page       Memory Page
 * @partition  Partition
 * @cmd        Command to sent
 */
static uint32_t issue_cmd(vaddr_t jr_base, unsigned int page,
			  unsigned int partition, uint8_t cmd)
{
	uint32_t status = 0;
	uint64_t timeout_ref = timeout_init_us(10000);

	assert(jr_base);

	/* Send cmd */
	io_caam_write32(jr_base + SM_SMCR, SM_SMCR_PAGE(page) |
					   SM_SMCR_PRTN(partition) |
					   SM_SMCR_CMD(cmd));

	/* Wait for the command to complete */
	do {
		if (timeout_elapsed(timeout_ref))
			break;
		status = io_caam_read32(jr_base + SM_SMCSR);
	} while (SM_SMCSR_CERR(status) == SM_SMCSR_CERR_NOT_COMPLETED);

	return io_caam_read32(jr_base + SM_SMCSR);
}

enum caam_status
caam_hal_sm_check_page_partition(vaddr_t jr_base,
				 const struct caam_sm_page_desc *page_desc)
{
	uint32_t val = 0;

	if (!jr_base || !page_desc)
		return CAAM_BAD_PARAM;

	val = io_caam_read32(jr_base + SMVID_MS);

	if (page_desc->page + page_desc->page_count >
		    GET_SMVID_MS_MAX_NPAG(val) ||
	    page_desc->partition > GET_SMVID_MS_NPRT(val))
		return CAAM_BAD_PARAM;

	return CAAM_NO_ERROR;
}

size_t caam_hal_sm_get_pages_size(vaddr_t jr_base, unsigned int page)
{
	size_t page_size = 0;

	page_size = GET_SMVID_LS_PSIZ(io_caam_read32(jr_base + SMVID_LS));

	return SHIFT_U32(1, page_size) * (size_t)page * 1024;
}

bool caam_hal_sm_prtn_is_free(vaddr_t jr_base, unsigned int partition)
{
	return SM_SMPO_OWNER(io_caam_read32(jr_base + SM_SMPO), partition) ==
	       SMPO_PO_AVAIL;
}

bool caam_hal_sm_prtn_is_owned(vaddr_t jr_base, unsigned int partition)
{
	return SM_SMPO_OWNER(io_caam_read32(jr_base + SM_SMPO), partition) ==
	       SMPO_PO_OWNED;
}

void caam_hal_sm_set_access_all_group(vaddr_t jr_base, unsigned int partition)
{
	io_caam_write32(jr_base + SM_SMAG1(partition), UINT32_MAX);
	io_caam_write32(jr_base + SM_SMAG2(partition), UINT32_MAX);
}

void caam_hal_sm_set_access_group(vaddr_t jr_base, unsigned int partition,
				  uint32_t grp1, uint32_t grp2)
{
	if (!jr_base)
		return;

	if (grp1 != UINT32_MAX)
		io_caam_write32(jr_base + SM_SMAG1(partition),
				SHIFT_U32(1, grp1));

	if (grp2 != UINT32_MAX)
		io_caam_write32(jr_base + SM_SMAG2(partition),
				SHIFT_U32(1, grp2));
}

void caam_hal_sm_open_access_perm(vaddr_t jr_base, unsigned int partition)
{
	io_caam_write32(jr_base + SM_SMAPR(partition),
			SM_SMAPR_GRP1(UINT8_MAX) | SM_SMAPR_GRP2(UINT8_MAX));
}

void caam_hal_sm_set_access_perm(vaddr_t jr_base, unsigned int partition,
				 unsigned int grp1_perm, unsigned int grp2_perm)
{
	io_caam_write32(jr_base + SM_SMAPR(partition),
			SM_SMAPR_GRP1(grp1_perm) | SM_SMAPR_GRP2(grp2_perm) |
			SM_SMAPR_CSP | SM_SMAPR_SMAP_LCK | SM_SMAPR_SMAG_LCK);
}

enum caam_status
caam_hal_sm_allocate_page(vaddr_t jr_base,
			  const struct caam_sm_page_desc *page_desc)
{
	unsigned int page = 0;
	uint32_t status = 0;

	if (!jr_base || !page_desc)
		return CAAM_BAD_PARAM;

	/* Check if pages are available */
	for (page = page_desc->page;
	     page < page_desc->page + page_desc->page_count; page++) {
		status = issue_cmd(jr_base, page, page_desc->partition,
				   SM_SMCR_PAGE_INQ);
		if (SM_SMCSR_PO(status) != SM_SMCSR_PO_AVAILABLE)
			return CAAM_BUSY;
	}

	/* Allocate pages to partition */
	for (page = page_desc->page;
	     page < page_desc->page + page_desc->page_count; page++) {
		status = issue_cmd(jr_base, page, page_desc->partition,
				   SM_SMCR_PAGE_ALLOC);
		if (SM_SMCSR_AERR(status) != SM_SMCSR_AERR_NO_ERROR)
			return CAAM_FAILURE;
	}

	/* Check if pages are available */
	for (page = page_desc->page;
	     page < page_desc->page + page_desc->page_count; page++) {
		status = issue_cmd(jr_base, page, page_desc->partition,
				   SM_SMCR_PAGE_INQ);
		if (SM_SMCSR_PO(status) != SM_SMCSR_PO_OWNED ||
		    SM_SMCSR_PRTN(status) != page_desc->partition)
			return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

enum caam_status caam_hal_sm_deallocate_partition(vaddr_t jr_base,
						  unsigned int partition)
{
	unsigned int status = 0;

	if (!jr_base)
		return CAAM_BAD_PARAM;

	/* De-Allocate partition and so all partition's page */
	status = issue_cmd(jr_base, 0, partition, SM_SMCR_PARTITION_DEALLOC);
	if (SM_SMCSR_AERR(status) != SM_SMCSR_AERR_NO_ERROR)
		return CAAM_FAILURE;

	return CAAM_NO_ERROR;
}

enum caam_status
caam_hal_sm_deallocate_pages(vaddr_t jr_base,
			     const struct caam_sm_page_desc *page_desc)
{
	unsigned int page = 0;
	uint32_t status = 0;

	if (!jr_base || !page_desc)
		return CAAM_BAD_PARAM;

	for (page = page_desc->page;
	     page < page_desc->page + page_desc->page_count; page++) {
		/* Deallocate page, set partition as not used */
		status = issue_cmd(jr_base, page, 0, SM_SMCR_PAGE_DEALLOC);
		if (SM_SMCSR_AERR(status) != SM_SMCSR_AERR_NO_ERROR)
			return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

register_phys_mem(MEM_AREA_IO_SEC, SECMEM_BASE, SECMEM_SIZE);
vaddr_t caam_hal_sm_get_base(void)
{
	vaddr_t sm_base = 0;
	void *fdt = NULL;

	fdt = get_dt();
	if (fdt)
		caam_hal_sm_get_base_dt(fdt, &sm_base);

	if (!sm_base)
		sm_base = core_mmu_get_va(SECMEM_BASE, MEM_AREA_IO_SEC,
					  SECMEM_SIZE);

	return sm_base;
}
