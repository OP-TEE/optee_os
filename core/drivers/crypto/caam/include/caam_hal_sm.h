/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, 2023 NXP
 */
#ifndef __CAAM_HAL_SM_H__
#define __CAAM_HAL_SM_H__

#include <caam_sm.h>
#include <stdint.h>

/*
 * Checks if @page and @partition number are valid
 *
 * @jr_base       JR base address
 * @sm_page_desc  Secure Memory page
 */
enum caam_status
caam_hal_sm_check_page_partition(vaddr_t jr_base,
				 const struct caam_sm_page_desc *sm_page_desc);

/*
 * Return the Pages Size in KBytes
 *
 * @jr_base    JR base address
 * @page       Page number
 */
size_t caam_hal_sm_get_pages_size(vaddr_t jr_base, unsigned int page);

/*
 * Return if the partition is free (available)
 *
 * @jr_base    JR base address
 * @partition  Partition number
 */
bool caam_hal_sm_prtn_is_free(vaddr_t jr_base, unsigned int partition);

/*
 * Return if the partition is owned (by the HW register reader)
 *
 * @jr_base    JR base address
 * @partition  Partition number
 */
bool caam_hal_sm_prtn_is_owned(vaddr_t jr_base, unsigned int partition);

/*
 * Set the Secure Memory access to all groups
 *
 * @jr_base    JR base address
 * @partition  Partition number
 * @grp1       Group 1 value
 * @grp2       Group 2 value
 */
void caam_hal_sm_set_access_all_group(vaddr_t jr_base, unsigned int partition);

/*
 * Set the Secure Memory access to group 1 and/or group 2
 *
 * @jr_base    JR base address
 * @partition  Partition number
 * @grp1       Group 1 value
 * @grp2       Group 2 value
 */
void caam_hal_sm_set_access_group(vaddr_t jr_base, unsigned int partition,
				  uint32_t grp1, uint32_t grp2);

/*
 * Open all Secure Memory Permissions
 *
 * @jr_base    JR base address
 * @partition  Partition number
 */
void caam_hal_sm_open_access_perm(vaddr_t jr_base, unsigned int partition);

/*
 * Set the Secure Memory access permission for group 1 and group 2.
 * Enable Critical Security and lock configuration
 *
 * @jr_base    JR base address
 * @partition  Partition number
 * @grp1_perm  Group 1 Permissions
 * @grp2_perm  Group 2 Permissions
 */
void caam_hal_sm_set_access_perm(vaddr_t jr_base, unsigned int partition,
				 unsigned int grp1_perm,
				 unsigned int grp2_perm);

/*
 * Allocate a @page to the @partition.
 *
 * @jr_base  JR base address
 * @sm_page_desc  Secure Memory page
 */
enum caam_status
caam_hal_sm_allocate_page(vaddr_t jr_base,
			  const struct caam_sm_page_desc *sm_page_desc);

/*
 * De-allocate a @partition and all partition's page.
 *
 * @jr_base    JR base address
 * @partition  Partition number
 */
enum caam_status caam_hal_sm_deallocate_partition(vaddr_t jr_base,
						  unsigned int partition);

/*
 * De-allocate all pages specified in the @sm struct
 *
 * @jr_base  JR base address
 * @sm_page_desc  Secure Memory page
 */
enum caam_status
caam_hal_sm_deallocate_pages(vaddr_t jr_base,
			     const struct caam_sm_page_desc *sm_page_desc);

/* Return the virtual base address of the Secure Memory registers */
vaddr_t caam_hal_sm_get_base(void);

#ifdef CFG_DT
void caam_hal_sm_get_base_dt(void *fdt, vaddr_t *sm_base);
#else
static inline void caam_hal_sm_get_base_dt(void *fdt __unused, vaddr_t *sm_base)
{
	*sm_base = 0;
}
#endif /* CFG_DT */
#endif /* __CAAM_HAL_SM_H__ */
