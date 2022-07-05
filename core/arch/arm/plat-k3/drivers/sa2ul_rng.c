// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 SA2UL RNG Driver
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>

#include "sa2ul.h"

#define	RNG_OUTPUT_0            0x00
#define	RNG_OUTPUT_1            0x04
#define	RNG_OUTPUT_2            0x08
#define	RNG_OUTPUT_3            0x0C
#define	RNG_STATUS              0x10
#define RNG_READY               BIT(0)
#define SHUTDOWN_OFLO           BIT(1)
#define	RNG_INTACK              0x10
#define	RNG_CONTROL             0x14
#define ENABLE_TRNG             BIT(10)
#define	RNG_CONFIG              0x18
#define	RNG_ALARMCNT            0x1C
#define	RNG_FROENABLE           0x20
#define	RNG_FRODETUNE           0x24
#define	RNG_ALARMMASK           0x28
#define	RNG_ALARMSTOP           0x2C
#define	RNG_OPTIONS             0x78
#define	RNG_EIP_REV             0x7C

#define RNG_CONTROL_STARTUP_CYCLES_SHIFT        16
#define RNG_CONTROL_STARTUP_CYCLES_MASK         GENMASK_32(31, 16)

#define RNG_CONFIG_MAX_REFIL_CYCLES_SHIFT       16
#define RNG_CONFIG_MAX_REFIL_CYCLES_MASK        GENMASK_32(31, 16)
#define RNG_CONFIG_MIN_REFIL_CYCLES_SHIFT       0
#define RNG_CONFIG_MIN_REFIL_CYCLES_MASK        GENMASK_32(7, 0)

#define RNG_ALARMCNT_ALARM_TH_SHIFT             0
#define RNG_ALARMCNT_ALARM_TH_MASK              GENMASK_32(7, 0)
#define RNG_ALARMCNT_SHUTDOWN_TH_SHIFT          16
#define RNG_ALARMCNT_SHUTDOWN_TH_MASK           GENMASK_32(20, 16)

#define RNG_CONTROL_STARTUP_CYCLES              0xff
#define RNG_CONFIG_MIN_REFIL_CYCLES             0x5
#define RNG_CONFIG_MAX_REFIL_CYCLES             0x22
#define RNG_ALARM_THRESHOLD                     0xff
#define RNG_SHUTDOWN_THRESHOLD                  0x4

#define RNG_FRO_MASK    GENMASK_32(23, 0)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, RNG_BASE, RNG_REG_SIZE);

static unsigned int rng_lock = SPINLOCK_UNLOCK;
static vaddr_t rng;

static void sa2ul_rng_read128(uint32_t *word0, uint32_t *word1,
			      uint32_t *word2, uint32_t *word3)
{
	/* Is the result ready (available)? */
	while (!(io_read32(rng + RNG_STATUS) & RNG_READY)) {
		/* Is the shutdown threshold reached? */
		if (io_read32(rng + RNG_STATUS) & SHUTDOWN_OFLO) {
			uint32_t alarm = io_read32(rng + RNG_ALARMSTOP);
			uint32_t tune = io_read32(rng + RNG_FRODETUNE);

			/* Clear the alarm events */
			io_write32(rng + RNG_ALARMMASK, 0x0);
			io_write32(rng + RNG_ALARMSTOP, 0x0);
			/* De-tune offending FROs */
			io_write32(rng + RNG_FRODETUNE, tune ^ alarm);
			/* Re-enable the shut down FROs */
			io_write32(rng + RNG_FROENABLE, RNG_FRO_MASK);
			/* Clear the shutdown overflow event */
			io_write32(rng + RNG_INTACK, SHUTDOWN_OFLO);

			DMSG("Fixed FRO shutdown");
		}
	}
	/* Read random value */
	*word0 = io_read32(rng + RNG_OUTPUT_0);
	*word1 = io_read32(rng + RNG_OUTPUT_1);
	*word2 = io_read32(rng + RNG_OUTPUT_2);
	*word3 = io_read32(rng + RNG_OUTPUT_3);
	/* Acknowledge read complete */
	io_write32(rng + RNG_INTACK, RNG_READY);
}

uint8_t hw_get_random_byte(void)
{
	static int pos;
	static union {
		uint32_t val[4];
		uint8_t byte[16];
	} random;
	uint32_t exceptions = 0;
	uint8_t ret = 0;

	assert(rng);

	exceptions = cpu_spin_lock_xsave(&rng_lock);

	if (!pos)
		sa2ul_rng_read128(&random.val[0], &random.val[1],
				  &random.val[2], &random.val[3]);

	ret = random.byte[pos];

	pos = (pos + 1) % 16;

	cpu_spin_unlock_xrestore(&rng_lock, exceptions);

	return ret;
}

TEE_Result sa2ul_rng_init(void)
{
	uint32_t val = 0;

	rng = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC, RNG_REG_SIZE);

	/* Ensure initial latency */
	val |= RNG_CONFIG_MIN_REFIL_CYCLES << RNG_CONFIG_MIN_REFIL_CYCLES_SHIFT;
	val |= RNG_CONFIG_MAX_REFIL_CYCLES << RNG_CONFIG_MAX_REFIL_CYCLES_SHIFT;
	io_write32(rng + RNG_CONFIG, val);

	/* Configure the desired FROs */
	io_write32(rng + RNG_FRODETUNE, 0x0);

	/* Enable all FROs */
	io_write32(rng + RNG_FROENABLE, 0xffffff);

	io_write32(rng + RNG_CONTROL, ENABLE_TRNG);

	IMSG("SA2UL TRNG initialized");

	return TEE_SUCCESS;
}
