// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <io.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <util.h>

#include "qfprom_hal.h"
#include "qfprom_priv.h"
#include "qfprom_target.h"

static void qfprom_write_reg(uint32_t offset, uint32_t value)
{
	struct qfprom_context *ctx = qfprom_get_context();
	vaddr_t reg = ctx->raw_base_va + offset;

	io_write32(reg, value);
}

static uint32_t qfprom_read_reg(uint32_t offset)
{
	struct qfprom_context *ctx = qfprom_get_context();
	vaddr_t reg = ctx->raw_base_va + offset;

	return io_read32(reg);
}

static enum qfprom_error hal_qfprom_read_address_generic(uint32_t addr,
							 uint32_t *value)
{
	vaddr_t vaddr;

	if (!value)
		return QFPROM_DATA_PTR_NULL_ERR;

	if (!IS_ALIGNED_WITH_TYPE(addr, uint32_t))
		return QFPROM_ADDRESS_INVALID_ERR;

	vaddr = (vaddr_t)phys_to_virt(addr, MEM_AREA_IO_SEC, sizeof(uint32_t));
	if (!vaddr)
		return QFPROM_ADDRESS_INVALID_ERR;

	*value = io_read32(vaddr);

	return QFPROM_NO_ERR;
}

static enum qfprom_error hal_qfprom_read_row_generic(uint32_t addr,
						     uint32_t *value)
{
	enum qfprom_error ret;

	if (!value)
		return QFPROM_DATA_PTR_NULL_ERR;

	ret = hal_qfprom_read_address_generic(addr, &value[0]);
	if (ret != QFPROM_NO_ERR)
		return ret;

	return hal_qfprom_read_address_generic(addr + 4, &value[1]);
}

void hal_qfprom_set_blow_timer(uint32_t value)
{
	qfprom_write_reg(QFPROM_BLOW_TIMER_OFFSET, value);
}

void hal_qfprom_set_accel(uint32_t value)
{
	qfprom_write_reg(QFPROM_ACCEL_OFFSET, value);
}

enum qfprom_error hal_qfprom_read_raw_address(uint32_t addr, uint32_t *value)
{
	return hal_qfprom_read_address_generic(addr, value);
}

enum qfprom_error hal_qfprom_read_raw_address_row(uint32_t addr,
						  uint32_t *value)
{
	return hal_qfprom_read_row_generic(addr, value);
}

enum qfprom_error hal_qfprom_read_corrected_address(uint32_t addr,
						    uint32_t *value)
{
	return hal_qfprom_read_address_generic(addr, value);
}

enum qfprom_error hal_qfprom_read_corrected_address_row(uint32_t addr,
							uint32_t *value)
{
	return hal_qfprom_read_row_generic(addr, value);
}

enum qfprom_error hal_qfprom_write_raw_address(uint32_t addr, uint32_t value)
{
	vaddr_t vaddr;

	if (!IS_ENABLED(CFG_QFPROM_PROGRAMMING))
		return QFPROM_OPERATION_NOT_ALLOWED_ERR;

	if (!IS_ALIGNED_WITH_TYPE(addr, uint32_t))
		return QFPROM_ADDRESS_INVALID_ERR;

	vaddr = (vaddr_t)phys_to_virt(addr, MEM_AREA_IO_SEC, sizeof(uint32_t));
	if (!vaddr)
		return QFPROM_ADDRESS_INVALID_ERR;

	io_write32(vaddr, value);
	return QFPROM_NO_ERR;
}

enum qfprom_error hal_qfprom_read_blow_status(uint32_t *value)
{
	if (!value)
		return QFPROM_DATA_PTR_NULL_ERR;

	*value = qfprom_read_reg(QFPROM_BLOW_STATUS_OFFSET) &
		 QFPROM_BLOW_STATUS_RMSK;

	return QFPROM_NO_ERR;
}

void hal_qfprom_clear_fec_error_status(void)
{
	qfprom_write_reg(QFPROM_FEC_ESR_OFFSET, QFPROM_FEC_ESR_ERR_SEEN_BMSK);
}

bool hal_qfprom_is_fec_error_seen(void)
{
	uint32_t val = qfprom_read_reg(QFPROM_FEC_ESR_OFFSET);

	return (val & QFPROM_FEC_ESR_ERR_SEEN_BMSK) != 0;
}

void hal_qfprom_read_error_address(uint16_t *value)
{
	uint32_t val;

	if (!value)
		return;

	val = qfprom_read_reg(QFPROM_FEC_EAR_OFFSET);
	*value = (uint16_t)(val & QFPROM_FEC_EAR_ERR_ADDR_BMSK);
}
