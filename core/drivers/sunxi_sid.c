// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Linumiz
 */

#include <drivers/sunxi_sid.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <string_ext.h>
#include <util.h>

#define SID_PRCTL		0x40
#define SID_RDKEY		0x60
#define SID_PRCTL_OP_LOCK	0xAC
#define SID_PRCTL_READ		BIT(1)
#define SID_MAX_READ_LEN	8

#define SID_POLL_PERIOD_US	100
#define SID_POLL_TIMEOUT_US	250000

static vaddr_t sunxi_sid_base;
static struct mutex lock = MUTEX_INITIALIZER;

TEE_Result sunxi_sid_read_otp(uint8_t *buf, size_t len, uint32_t offset)
{
	uint32_t val[SID_MAX_READ_LEN] = {0};
	TEE_Result ret = TEE_SUCCESS;
	uint32_t reg_val = 0;

	if (!sunxi_sid_base)
		return TEE_ERROR_BAD_STATE;

	if (!buf || !len || (len % sizeof(uint32_t)))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((len / sizeof(uint32_t)) > SID_MAX_READ_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&lock);
	for (uint8_t i = 0; i < (len / sizeof(uint32_t)); i++) {
		reg_val = (((offset & 0x1FF) << 16) | (SID_PRCTL_OP_LOCK << 8) |
			   SID_PRCTL_READ);

		io_write32(sunxi_sid_base + SID_PRCTL, reg_val);
		if (IO_READ32_POLL_TIMEOUT(sunxi_sid_base + SID_PRCTL, reg_val,
					   !(reg_val & SID_PRCTL_READ),
					   SID_POLL_PERIOD_US,
					   SID_POLL_TIMEOUT_US)) {
			ret = TEE_ERROR_TIMEOUT;
			goto err_out;
		}

		val[i] = io_read32(sunxi_sid_base + SID_RDKEY);
		io_write32(sunxi_sid_base + SID_PRCTL, 0);
		offset += sizeof(uint32_t);
	}

	memcpy(buf, val, len);

err_out:
	memzero_explicit(val, sizeof(val));
	mutex_unlock(&lock);

	return ret;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	if (!buffer || !len)
		return -1;

	if (sunxi_sid_read_otp(buffer, len, SUNXI_SID_CHIP_ID_REG))
		return -1;

	return 0;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	return sunxi_sid_read_otp(&hwkey->data[0], HW_UNIQUE_KEY_LENGTH,
				  SUNXI_SID_HUK_REG);
}

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SUNXI_SID_BASE, SUNXI_SID_SIZE);

static TEE_Result sunxi_sid_init(void)
{
	sunxi_sid_base = (vaddr_t)core_mmu_get_va(SUNXI_SID_BASE,
						  MEM_AREA_IO_SEC,
						  SUNXI_SID_SIZE);
	if (!sunxi_sid_base)
		return TEE_ERROR_GENERIC;

	DMSG("sunxi sid init done");
	return TEE_SUCCESS;
}
service_init(sunxi_sid_init);
