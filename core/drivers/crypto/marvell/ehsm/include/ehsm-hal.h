/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 Marvell.
 */

#ifndef __EHSM_HAL_H__
#define __EHSM_HAL_H__

#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <io.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>

#include <ehsm.h>

#define ehsm_printf(fmt, ...)	DMSG(fmt, ##__VA_ARGS__)

#define DEBUG_EHSM	0

#if (DEBUG_EHSM)
#define ehsm_debug(fmt, ...)	ehsm_printf(fmt, ##__VA_ARGS__)
#else
#define ehsm_debug(...)		((void)0)
#endif

/* Base address for eHSM standard registers */
#define EHSM_BASE_ADDR		PLAT_MARVELL_EHSM_BASE_ADDR

/* eHSM mailbox for AES crypto operations */
#ifdef CFG_MARVELL_EHSM_CN10K
#define EHSM_CRYPTO_MAILBOX	EHSM_MAILBOX0
#else
#define EHSM_CRYPTO_MAILBOX	EHSM_MAILBOX1
#endif

static inline void ehsm_prepare_csr_access(struct ehsm_handle *handle)
{
	handle->ehsm_base = (vaddr_t)phys_to_virt_io(EHSM_BASE_ADDR,
						     SIZE_4K);
}

static inline uint32_t ehsm_ptr_to_reg(void *ptr)
{
	return low32_from_64((vaddr_t)ptr);
}

static inline uint32_t ehsm_read_csr(const struct ehsm_handle *handle,
				     size_t reg)
{
	return io_read32_off(handle->ehsm_base, reg);
}

static inline void ehsm_write_csr(struct ehsm_handle *handle,
				  size_t reg, uint32_t value)
{
	io_write32_off(handle->ehsm_base, reg, value);
}

static inline uint32_t ehsm_addr_low(const void *ptr)
{
	return low32_from_64((vaddr_t)ptr);
}

static inline uint32_t ehsm_addr_hi(const void *ptr)
{
	return high32_from_64((vaddr_t)ptr);
}
#endif  /* __EHSM_HAL_H__ */
