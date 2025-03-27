/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Marvell.
 */

#ifndef __EHSM_HAL_H__
#define __EHSM_HAL_H__

#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <io.h>
#include <stdint.h>
#include <trace.h>

#include "ehsm.h"

#define ehsm_printf(fmt, ...)	DMSG(fmt, ##__VA_ARGS__)

#define DEBUG_EHSM	0

#if (DEBUG_EHSM)
#define ehsm_debug(fmt, ...)	ehsm_printf(fmt, ##__VA_ARGS__)
#else
#define ehsm_debug(fmt, ...)
#endif

#ifdef CFG_MARVELL_EHSM_CN10K
/*
 * Base address for eHSM standard registers.
 */
#define EHSM_BASE_ADDR		(0x80B000000000ULL)

/*
 * eHSM mailbox for AES crypto operations
 */
#define EHSM_CRYPTO_MAILBOX	EHSM_MAILBOX0
#endif

#ifdef CFG_MARVELL_EHSM_CN20K
/*
 * Base address for eHSM standard registers.
 */
#define EHSM_BASE_ADDR          (0xC01700000000ULL)

/*
 * eHSM mailbox for AES crypto operations
 */
#define EHSM_CRYPTO_MAILBOX	EHSM_MAILBOX1
#endif

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
	return (((unsigned long)ptr) >> 32) & 0xFFFFFFFF;
}
#endif  /* __EHSM_HAL_H__ */
