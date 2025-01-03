// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 * Copyright (c) 2024, Rockchip, Inc. All rights reserved.
 */

#include <common.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>

#define FIREWALL_DDR_RGN(i)             ((i) * 0x4)
#define FIREWALL_DDR_CON                0xf0
#define FIREWALL_DSU_RGN(i)             ((i) * 0x4)
#define FIREWALL_DSU_CON(i)             (0xf0 + ((i) * 0x4))

#define RG_MAP_SECURE(top, base)        \
	(((((top) - 1) & 0x7fff) << 16) | ((base) & 0x7fff))

#define DDR_CHN_CNT                     4

#define TRNG_S_CTRL       0x0000
#define TRNG_S_STAT       0x0004
#define TRNG_S_MODE       0x0008
#define TRNG_S_IE         0x0010
#define TRNG_S_ISTAT      0x0014
#define TRNG_S_RAND       0x0020
#define TRNG_S_AUTO_RQSTS 0x0060

#define CMD_NOP         0
#define CMD_RAND        1
#define CMD_SEED        2

#define LEN_128BIT      0

#define TRNG_S_WORDS	4

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DSU_BASE, FIREWALL_DSU_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TRNG_S_BASE, TRNG_S_SIZE);

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	vaddr_t fw_ddr_base = (vaddr_t)phys_to_virt_io(FIREWALL_DDR_BASE,
						       FIREWALL_DDR_SIZE);
	vaddr_t fw_dsu_base = (vaddr_t)phys_to_virt_io(FIREWALL_DSU_BASE,
						       FIREWALL_DSU_SIZE);
	paddr_t ed = st + sz;
	uint32_t st_mb = st / SIZE_M(1);
	uint32_t ed_mb = ed / SIZE_M(1);
	uint32_t i = 0;

	if (!fw_ddr_base || !fw_dsu_base)
		panic();

	assert(rgn <= 16);
	assert(st < ed);

	/* Check aligned 1MB */
	assert(st % SIZE_M(1) == 0);
	assert(ed % SIZE_M(1) == 0);

	DMSG("protecting region %d: 0x%"PRIxPA"-0x%"PRIxPA"", rgn, st, ed);

	/* Map secure region in DDR */
	io_write32(fw_ddr_base + FIREWALL_DDR_RGN(rgn),
		   RG_MAP_SECURE(ed_mb, st_mb));

	/* Map secure region in each DSU channel and enable */
	for (i = 0; i < DDR_CHN_CNT; i++) {
		io_write32(fw_dsu_base + FIREWALL_DSU_RGN(i),
			   RG_MAP_SECURE(ed_mb, st_mb));
		io_setbits32(fw_dsu_base + FIREWALL_DSU_CON(i), BIT(rgn));
	}

	/* Enable secure region for DDR */
	io_setbits32(fw_ddr_base + FIREWALL_DDR_CON, BIT(rgn));

	return 0;
}

TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	vaddr_t trng_s_base = (vaddr_t)phys_to_virt_io(TRNG_S_BASE,
						       TRNG_S_SIZE);
	uint32_t *rand_buf = (uint32_t *)buf;
	size_t remaining = blen;
	uint32_t val;

	if (!trng_s_base)
		panic("TRNG_S base not mapped");

	/* Ensure TRNG is seeded and ready */
	val = io_read32(trng_s_base + TRNG_S_STAT);
	if (!(val & (1 << 9))) {
		/* TRNG not seeded, issue SEED command */
		io_write32(trng_s_base + TRNG_S_CTRL, CMD_SEED);

		/* Wait for SEED_DONE flag in ISTAT register */
		do {
			val = io_read32(trng_s_base + TRNG_S_ISTAT);
		} while (!(val & (1 << 1)));

		/* SEED_DONE flag set, clear SEED_DONE */
		io_write32(trng_s_base + TRNG_S_ISTAT, (1 << 1));
	}

	/* Set RNG length to 128 bits and disable interrupts */
	io_write32(trng_s_base + TRNG_S_MODE, LEN_128BIT);
	io_write32(trng_s_base + TRNG_S_IE, 0);

	while (remaining > 0) {
		/* Set RAND command to generate random numbers */
		io_write32(trng_s_base + TRNG_S_CTRL, CMD_RAND);

		/* Wait for the RAND_RDY flag in the ISTAT register */
		do {
			val = io_read32(trng_s_base + TRNG_S_ISTAT);
		} while (!(val & 1));

		/* Read random data from RAND register */
		for (size_t i = 0; i < TRNG_S_WORDS && remaining > 0; i++) {
			uint32_t rnd = io_read32(trng_s_base + TRNG_S_RAND + i
						 * sizeof(uint32_t));

			rand_buf[(blen - remaining) / sizeof(uint32_t)] = rnd;
			remaining -= sizeof(uint32_t);
		}

		/* Clear RAND_RDY flag */
		io_write32(trng_s_base + TRNG_S_ISTAT, 0xFFFFFFFF);
	}

	/* Reset RNG mode to NOP */
	io_write32(trng_s_base + TRNG_S_CTRL, CMD_NOP);

	return TEE_SUCCESS;
}
