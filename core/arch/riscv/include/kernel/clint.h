/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KERNEL_CLINT_H
#define __KERNEL_CLINT_H

#include <io.h>
#include <kernel/misc.h>
#include <platform_config.h>
#include <types_ext.h>

#ifdef CFG_RISCV_M_MODE

/* Machine software-interrupt pending register for a specific hart */
#define CLINT_MSIP(hart) (CLINT_BASE + (4 * (hart)))
/* Register for setting mtimecmp for a specific hart */
#define CLINT_MTIMECMP(hart)(CLINT_BASE + 0x4000 + (8 * (hart)))
/* Number of cycles counted from the RTCCLK input */
#define CLINT_MTIME (CLINT_BASE + 0xbff8)

static inline void clint_ipi_send(unsigned long hart)
{
	assert(hart < CFG_TEE_CORE_NB_CORE);
	io_write32(CLINT_MSIP(hart), 1);
}

static inline void clint_ipi_clear(unsigned long hart)
{
	assert(hart < CFG_TEE_CORE_NB_CORE);
	io_write32(CLINT_MSIP(hart), 0);
}

static inline void clint_set_mtimecmp(uint64_t timecmp)
{
	/* Each hart has a separate source of timer interrupts */
	io_write64(CLINT_MTIMECMP(get_core_pos()), timecmp);
}

static inline uint64_t clint_get_mtimecmp(void)
{
	return io_read64(CLINT_MTIMECMP(get_core_pos()));
}

static inline uint64_t clint_get_mtime(void)
{
	return io_read64(CLINT_MTIME);
}

static inline void clint_set_mtime(uint64_t mtime)
{
	io_write64(CLINT_MTIME, mtime);
}

#endif /* CFG_RISCV_M_MODE */
#endif /* __KERNEL_CLINT_H */
