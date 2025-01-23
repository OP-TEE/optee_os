// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2019, Theobroma Systems Design und Consulting GmbH
 * Copyright (c) 2024, Rockchip, Inc. All rights reserved.
 */

#include <common.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>
#include <string.h>
#include <string_ext.h>
#include <utee_defines.h>

#define FIREWALL_DDR_RGN(i)		((i) * 0x4)
#define FIREWALL_DDR_CON		0xf0
#define FIREWALL_DSU_RGN(i)		((i) * 0x4)
#define FIREWALL_DSU_CON(i)		(0xf0 + ((i) * 0x4))

#define RG_MAP_SECURE(top, base)	\
	(((((top) - 1) & 0x7fff) << 16) | ((base) & 0x7fff))

#define DDR_CHN_CNT			4

#define TRNG_S_CTRL		0x0000
#define TRNG_S_STAT		0x0004
#define TRNG_S_MODE		0x0008
#define TRNG_S_IE		0x0010
#define TRNG_S_ISTAT		0x0014
#define TRNG_S_RAND		0x0020
#define TRNG_S_AUTO_RQSTS	0x0060

#define CMD_NOP			0
#define CMD_RAND		1
#define CMD_SEED		2

#define LEN_128BIT		0
#define LEN_256BIT		3

#define TRNG_S_SEEDED_BIT	BIT32(9)
#define TRNG_S_SEED_DONE_BIT	BIT32(1)
#define TRNG_S_RAND_RDY_BIT	BIT32(0)

#define TRNG_POLL_PERIOD_US	0
#define TRNG_POLL_TIMEOUT_US	1000

#define OTP_S_AUTO_CTRL	0x0004
#define OTP_S_AUTO_EN	0x0008
#define OTP_S_PROG_DATA	0x0010
#define OTP_S_DOUT	0x0020
#define OTP_S_INT_ST	0x0084

#define ADDR_SHIFT	16
#define BURST_SHIFT	8
#define CMD_READ	0
#define CMD_WRITE	2
#define EN_ENABLE	1
#define EN_DISABLE	0

#define MAX_INDEX	0x300
#define BURST_SIZE	8
#define OTP_WORD	1

#define OTP_S_ERROR_BIT		BIT32(4)
#define OTP_S_WR_DONE_BIT	BIT32(3)
#define OTP_S_VERIFY_BIT	BIT32(2)
#define OTP_S_RD_DONE_BIT	BIT32(1)

#define OTP_POLL_PERIOD_US	0
#define OTP_POLL_TIMEOUT_US	1000

#define HW_UNIQUE_KEY_INDEX	0x104

register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DDR_BASE, FIREWALL_DDR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, FIREWALL_DSU_BASE, FIREWALL_DSU_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TRNG_S_BASE, TRNG_S_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, OTP_S_BASE, OTP_S_SIZE);

static struct mutex trng_mutex = MUTEX_INITIALIZER;
static struct mutex huk_mutex = MUTEX_INITIALIZER;

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
	size_t remaining = blen;
	size_t copy_len = 0;
	uint32_t val = 0;
	uint32_t rnd = 0;

	mutex_lock(&trng_mutex);

	if (!trng_s_base)
		panic("TRNG_S base not mapped");

	/* Ensure TRNG is seeded and ready */
	val = io_read32(trng_s_base + TRNG_S_STAT);
	if (!(val & TRNG_S_SEEDED_BIT)) {
		/* TRNG not seeded, issue SEED command */
		io_write32(trng_s_base + TRNG_S_CTRL, CMD_SEED);

		/* Wait for SEED_DONE flag with timeout */
		if (IO_READ32_POLL_TIMEOUT(trng_s_base + TRNG_S_ISTAT, val,
					   val & TRNG_S_SEED_DONE_BIT,
					   TRNG_POLL_PERIOD_US,
					   TRNG_POLL_TIMEOUT_US)) {
			mutex_unlock(&trng_mutex);
			return TEE_ERROR_BUSY;
		}

		/* SEED_DONE flag set, clear SEED_DONE */
		io_write32(trng_s_base + TRNG_S_ISTAT, TRNG_S_SEED_DONE_BIT);
	}

	/* Set RNG length to 256 bits */
	io_write32(trng_s_base + TRNG_S_MODE, LEN_256BIT);

	while (remaining > 0) {
		/* Set RAND command to generate random numbers */
		io_write32(trng_s_base + TRNG_S_CTRL, CMD_RAND);

		/* Wait for RAND_RDY flag with timeout */
		if (IO_READ32_POLL_TIMEOUT(trng_s_base + TRNG_S_ISTAT, val,
					   val & TRNG_S_RAND_RDY_BIT,
					   TRNG_POLL_PERIOD_US,
					   TRNG_POLL_TIMEOUT_US)) {
			mutex_unlock(&trng_mutex);
			return TEE_ERROR_BUSY;
		}

		/* Read random data from RAND register */
		rnd = io_read32(trng_s_base + TRNG_S_RAND);

		/* Copy as many bytes as required */
		copy_len = MIN(remaining, sizeof(uint32_t));
		memcpy((uint8_t *)buf + (blen - remaining), &rnd, copy_len);
		remaining -= copy_len;

		/* Clear RAND_RDY flag */
		io_write32(trng_s_base + TRNG_S_ISTAT, TRNG_S_RAND_RDY_BIT);
	}

	/* Reset RNG mode to NOP */
	io_write32(trng_s_base + TRNG_S_CTRL, CMD_NOP);

	mutex_unlock(&trng_mutex);

	return TEE_SUCCESS;
}

static TEE_Result tee_otp_read_secure(uint32_t *value, uint32_t index,
				      uint32_t count)
{
	vaddr_t base = (vaddr_t)phys_to_virt(OTP_S_BASE, MEM_AREA_IO_SEC,
					     OTP_S_SIZE);
	uint32_t int_status = 0;
	uint32_t i = 0;
	uint32_t val = 0;
	uint32_t auto_ctrl_val = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!base)
		panic("OTP_S base not mapped");

	/* Check for invalid parameters or exceeding hardware burst limit */
	if (!value || !count || count > BURST_SIZE ||
	    (index + count > MAX_INDEX))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Setup read: index, count, command = READ */
	auto_ctrl_val = SHIFT_U32(index, ADDR_SHIFT) |
			SHIFT_U32(count, BURST_SHIFT) |
			CMD_READ;

	/* Clear any pending interrupts by reading & writing back INT_ST */
	io_write32(base + OTP_S_INT_ST, io_read32(base + OTP_S_INT_ST));

	/* Set read command */
	io_write32(base + OTP_S_AUTO_CTRL, auto_ctrl_val);

	/* Enable read */
	io_write32(base + OTP_S_AUTO_EN, EN_ENABLE);

	/* Wait for RD_DONE or ERROR bits */
	res = IO_READ32_POLL_TIMEOUT(base + OTP_S_INT_ST,
				     int_status,
				     (int_status & OTP_S_RD_DONE_BIT) ||
				     (int_status & OTP_S_ERROR_BIT),
				     OTP_POLL_PERIOD_US,
				     OTP_POLL_TIMEOUT_US);

	/* Clear the interrupt again */
	io_write32(base + OTP_S_INT_ST, io_read32(base + OTP_S_INT_ST));

	if (int_status & OTP_S_ERROR_BIT) {
		EMSG("OTP_S Error");
		return TEE_ERROR_GENERIC;
	}
	if (res) {
		EMSG("OTP_S Timeout");
		return TEE_ERROR_BUSY;
	}

	/* Read out the data */
	for (i = 0; i < count; i++) {
		val = io_read32(base + OTP_S_DOUT +
				(i * sizeof(uint32_t)));
		value[i] = val;
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_otp_write_secure(const uint32_t *value, uint32_t index,
				       uint32_t count)
{
	vaddr_t base = (vaddr_t)phys_to_virt(OTP_S_BASE, MEM_AREA_IO_SEC,
					     OTP_S_SIZE);
	uint32_t int_status = 0;
	uint32_t i = 0;

	if (!base)
		panic("OTP_S base not mapped");

	/* Check for invalid parameters or exceeding hardware limits */
	if (!value || !count || count > BURST_SIZE ||
	    (index + count > MAX_INDEX))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Program OTP words */
	for (i = 0; i < count; i++) {
		uint32_t old_val = 0;
		uint32_t new_val = 0;
		uint32_t curr_idx = index + i;
		TEE_Result res = TEE_SUCCESS;

		/* Setup write: curr_idx, command = WRITE */
		uint32_t auto_ctrl_val = SHIFT_U32(curr_idx, ADDR_SHIFT) |
						   CMD_WRITE;

		/* Read existing OTP word to see which bits can be set */
		res = tee_otp_read_secure(&old_val, curr_idx, OTP_WORD);
		if (res != TEE_SUCCESS)
			return res;

		/* Check if bits in value conflict with old_val */
		if (~*value & old_val) {
			EMSG("OTP_S Program fail");
			return TEE_ERROR_GENERIC;
		}

		/* Only program bits that are currently 0 (0->1) */
		new_val = *value & ~old_val;
		value++;
		if (!new_val)
			continue;

		/* Clear any pending interrupts */
		io_write32(base + OTP_S_INT_ST, io_read32(base + OTP_S_INT_ST));

		/* Set write command */
		io_write32(base + OTP_S_AUTO_CTRL, auto_ctrl_val);

		/* Write the new bits into PROG_DATA register */
		io_write32(base + OTP_S_PROG_DATA, new_val);

		/* Enable the write */
		io_write32(base + OTP_S_AUTO_EN, EN_ENABLE);

		/* Poll for WR_DONE or verify/error bits */
		res = IO_READ32_POLL_TIMEOUT(base + OTP_S_INT_ST,
					     int_status,
					     (int_status & OTP_S_WR_DONE_BIT) ||
					     (int_status & OTP_S_VERIFY_BIT) ||
					     (int_status & OTP_S_ERROR_BIT),
					     OTP_POLL_PERIOD_US,
					     OTP_POLL_TIMEOUT_US);

		/* Clear INT status bits */
		io_write32(base + OTP_S_INT_ST, int_status);

		/* Check for VERIFY_FAIL, ERROR or timeout */
		if (int_status & OTP_S_VERIFY_BIT) {
			EMSG("OTP_S Verification fail");
			return TEE_ERROR_GENERIC;
		}
		if (int_status & OTP_S_ERROR_BIT) {
			EMSG("OTP_S Error");
			return TEE_ERROR_GENERIC;
		}
		if (res) {
			EMSG("OTP_S Timeout");
			return TEE_ERROR_BUSY;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t buffer[HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t)] = { };
	bool key_is_empty = true;
	size_t i = 0;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&huk_mutex);

	/* Read 4 words (16 bytes) from OTP at HW_UNIQUE_KEY_INDEX */
	res = tee_otp_read_secure(buffer,
				  HW_UNIQUE_KEY_INDEX,
				  HW_UNIQUE_KEY_LENGTH / sizeof(uint32_t));
	if (res)
		goto out;

	/* Check if the buffer is all zero => HUK not present */
	for (i = 0; i < ARRAY_SIZE(buffer); i++) {
		if (buffer[i] != 0)
			key_is_empty = false;
	}

	if (key_is_empty) {
		/* Generate random 128-bit key from TRNG */
		res = hw_get_random_bytes(buffer, sizeof(buffer));
		if (res)
			goto out;

		/* Write the new HUK into OTP at HW_UNIQUE_KEY_INDEX */
		res = tee_otp_write_secure(buffer,
					   HW_UNIQUE_KEY_INDEX,
					   HW_UNIQUE_KEY_LENGTH /
					   sizeof(uint32_t));
		if (res)
			goto out;
	}

	/* Copy HUK into hwkey->data */
	memcpy(hwkey->data, buffer, HW_UNIQUE_KEY_LENGTH);

out:
	/* Clear buffer memory */
	memzero_explicit(buffer, sizeof(buffer));

	mutex_unlock(&huk_mutex);

	return res;
}
