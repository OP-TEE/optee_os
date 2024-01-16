/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019, 2023 NXP
 */
#ifndef __CAAM_SM_H__
#define __CAAM_SM_H__

#include "caam_jr.h"
#include "drivers/caam_extension.h"

/*
 * Secure Memory data
 */
struct caam_sm_page_addr {
	paddr_t paddr; /* Secure memory base address */
	vaddr_t vaddr; /* Secure memory virtual base address */
};

/*
 * Secure Memory Page(s)/Partition definition
 */
struct caam_sm_page_desc {
	unsigned int partition; /* Partition number */
	unsigned int page; /* Page number */
	unsigned int page_count; /* Number of pages used */
};

#ifdef CFG_NXP_CAAM_SM_DRV
/*
 * CAAM Secure memory module initialization
 *
 * @jrcfg  JR configuration structure
 */
enum caam_status caam_sm_init(struct caam_jrcfg *jrcfg);

/*
 * Allocate page(s) to one partition in the CAAM secure memory.
 * Reset the group access and permission access to remove restrictions.
 *
 * @sm_page_descriptor  Secure Memory page
 * @sm_page_addr [out]  Secure Memory page addresses
 */
enum caam_status
caam_sm_alloc(const struct caam_sm_page_desc *sm_page_descriptor,
	      struct caam_sm_page_addr *sm_page_addr);

/*
 * Set the Secure Memory group 1 and group 2 access rights to allocated
 * partition and lock configuration.
 *
 * @page_desc  Secure Memory page
 * @grp1_perm  Group 1 Permission value
 * @grp2_perm  Group 2 Permission value
 */
enum caam_status
caam_sm_set_access_perm(const struct caam_sm_page_desc *page_desc,
			unsigned int grp1_perm, unsigned int grp2_perm);

/*
 * Free a Secure Memory pages
 *
 * @sm_page_descriptor    Secure Memory page
 */
enum caam_status
caam_sm_free(const struct caam_sm_page_desc *sm_page_descriptor);

#else
static inline enum caam_status caam_sm_init(struct caam_jrcfg *jrcfg __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_SM_DRV */
#endif /* __CAAM_SM_H__ */
