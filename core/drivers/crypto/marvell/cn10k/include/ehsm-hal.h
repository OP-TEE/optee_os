/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Marvell.
 */

#ifndef __EHSM_HAL_H__
#define __EHSM_HAL_H__

#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <trace.h>
#include <io.h>

#include "ehsm.h"

#ifndef FALSE
#define FALSE	false
#endif
#ifndef TRUE
#define TRUE	true
#endif

#define ehsm_printf(fmt, ...)	DMSG(fmt, ##__VA_ARGS__)

#define DEBUG_EHSM	0

#if (DEBUG_EHSM)
#define ehsm_debug(fmt, ...)	ehsm_printf(fmt, ##__VA_ARGS__)
#else
#define ehsm_debug(fmt, ...)
#endif

/*
 * eHSM mailbox for AES crypto operations
 */
#define EHSM_CRYPTO_MAILBOX	EHSM_MAILBOX0

/*
 * Base address for eHSM standard registers.
 */
#define EHSM_BASE_ADDR		(0x80B000000000ULL)

/*
 * Prepare the device for access to the eHSM.
 */
register_phys_mem_pgdir(MEM_AREA_IO_SEC, EHSM_BASE_ADDR, CORE_MMU_PGDIR_SIZE);

static inline void ehsm_prepare_csr_access(struct ehsm_handle *handle)
{
	handle->ehsm_base = (uint32_t *)phys_to_virt_io(EHSM_BASE_ADDR,
							CORE_MMU_PGDIR_SIZE);
}

static inline uint32_t ehsm_ptr_to_reg(void *ptr)
{
	return (uint32_t)((unsigned long)ptr & 0xffffffff);
}

static inline uint32_t ehsm_read_csr(const struct ehsm_handle *handle,
				     size_t reg)
{
	return io_read32((vaddr_t)(handle->ehsm_base + reg / 4));
}

static inline void ehsm_write_csr(struct ehsm_handle *handle,
				  size_t reg, uint32_t value)
{
	io_write32((vaddr_t)(handle->ehsm_base + reg / 4), value);
}

static inline uint32_t ehsm_addr_low(const void *ptr)
{
	return (uint32_t)(unsigned long)ptr & 0xFFFFFFFFUL;
}

static inline uint32_t ehsm_addr_hi(const void *ptr)
{
	return ((((unsigned long)ptr) >> 16) >> 16) & 0xFFFFFFFF;
}
#endif  /* __EHSM_HAL_H__ */
