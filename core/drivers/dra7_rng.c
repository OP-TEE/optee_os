// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
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

#define	RNG_OUTPUT_L            0x0000
#define	RNG_OUTPUT_H            0x0004
#define	RNG_STATUS              0x0008
#  define RNG_READY             BIT(0)
#  define SHUTDOWN_OFLO         BIT(1)
#define	RNG_INTMASK             0x000C
#define	RNG_INTACK              0x0010
#define	RNG_CONTROL             0x0014
#  define ENABLE_TRNG           BIT(10)
#define	RNG_CONFIG              0x0018
#define	RNG_ALARMCNT            0x001C
#define	RNG_FROENABLE           0x0020
#define	RNG_FRODETUNE           0x0024
#define	RNG_ALARMMASK           0x0028
#define	RNG_ALARMSTOP           0x002C
#define	RNG_LFSR_L              0x0030
#define	RNG_LFSR_M              0x0034
#define	RNG_LFSR_H              0x0038
#define	RNG_COUNT               0x003C
#define	RNG_OPTIONS             0x0078
#define	RNG_EIP_REV             0x007C
#define	RNG_MMR_STATUS_EN       0x1FD8
#define	RNG_REV                 0x1FE0
#define	RNG_SYS_CONFIG_REG      0x1FE4
#  define RNG_AUTOIDLE          BIT(0)
#define	RNG_MMR_STATUS_SET      0x1FEC
#define	RNG_SOFT_RESET_REG      0x1FF0
#  define RNG_SOFT_RESET        BIT(0)
#define	RNG_IRQ_EOI_REG         0x1FF4
#define	RNG_IRQSTATUS           0x1FF8

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
#define RNG_CONFIG_MIN_REFIL_CYCLES             0x21
#define RNG_CONFIG_MAX_REFIL_CYCLES             0x22
#define RNG_ALARM_THRESHOLD                     0xff
#define RNG_SHUTDOWN_THRESHOLD                  0x4

#define RNG_FRO_MASK    GENMASK_32(23, 0)

#define RNG_REG_SIZE    0x2000

register_phys_mem_pgdir(MEM_AREA_IO_SEC, RNG_BASE, RNG_REG_SIZE);

static unsigned int rng_lock = SPINLOCK_UNLOCK;

uint8_t hw_get_random_byte(void)
{
	static int pos;
	static union {
		uint32_t val[2];
		uint8_t byte[8];
	} random;
	vaddr_t rng = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC,
					    RNG_REG_SIZE);
	uint8_t ret;

	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	cpu_spin_lock(&rng_lock);

	if (!pos) {
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

				DMSG("Fixed FRO shutdown\n");
			}
		}
		/* Read random value */
		random.val[0] = io_read32(rng + RNG_OUTPUT_L);
		random.val[1] = io_read32(rng + RNG_OUTPUT_H);
		/* Acknowledge read complete */
		io_write32(rng + RNG_INTACK, RNG_READY);
	}

	ret = random.byte[pos];

	pos = (pos + 1) % 8;

	cpu_spin_unlock(&rng_lock);
	thread_set_exceptions(exceptions);

	return ret;
}

static TEE_Result dra7_rng_init(void)
{
	vaddr_t rng = (vaddr_t)phys_to_virt(RNG_BASE, MEM_AREA_IO_SEC,
					    RNG_REG_SIZE);
	uint32_t val;

	/* Execute a software reset */
	io_write32(rng + RNG_SOFT_RESET_REG, RNG_SOFT_RESET);

	/* Wait for the software reset completion by polling */
	while (io_read32(rng + RNG_SOFT_RESET_REG) & RNG_SOFT_RESET)
		;

	/* Switch to low-power operating mode */
	io_write32(rng + RNG_SYS_CONFIG_REG, RNG_AUTOIDLE);

	/*
	 * Select the number of clock input cycles to the
	 * FROs between two samples
	 */
	val = 0;

	/* Ensure initial latency */
	val |= RNG_CONFIG_MIN_REFIL_CYCLES <<
			RNG_CONFIG_MIN_REFIL_CYCLES_SHIFT;
	val |= RNG_CONFIG_MAX_REFIL_CYCLES <<
			RNG_CONFIG_MAX_REFIL_CYCLES_SHIFT;
	io_write32(rng + RNG_CONFIG, val);

	/* Configure the desired FROs */
	io_write32(rng + RNG_FRODETUNE, 0x0);

	/* Enable all FROs */
	io_write32(rng + RNG_FROENABLE, 0xffffff);

	/*
	 * Select the maximum number of samples after
	 * which if a repeating pattern is still detected, an
	 * alarm event is generated
	 */
	val = RNG_ALARM_THRESHOLD << RNG_ALARMCNT_ALARM_TH_SHIFT;

	/*
	 * Set the shutdown threshold to the number of FROs
	 * allowed to be shut downed
	 */
	val |= RNG_SHUTDOWN_THRESHOLD << RNG_ALARMCNT_SHUTDOWN_TH_SHIFT;
	io_write32(rng + RNG_ALARMCNT, val);

	/* Enable the RNG module */
	val = RNG_CONTROL_STARTUP_CYCLES << RNG_CONTROL_STARTUP_CYCLES_SHIFT;
	val |= ENABLE_TRNG;
	io_write32(rng + RNG_CONTROL, val);

	IMSG("DRA7x TRNG initialized");

	return TEE_SUCCESS;
}
driver_init(dra7_rng_init);
