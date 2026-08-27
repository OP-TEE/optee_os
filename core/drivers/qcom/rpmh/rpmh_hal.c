// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <io.h>
#include <util.h>

#include "rpmh_hal.h"

static vaddr_t rsc_base;

static inline vaddr_t get_tcs_base(uint32_t tcs_id)
{
	return rsc_base + TCS_BASE_OFFSET + (tcs_id * TCS_STRIDE);
}

static inline uint32_t hal_read32(vaddr_t addr)
{
	return io_read32(addr);
}

static inline void hal_write32(vaddr_t addr, uint32_t val)
{
	io_write32(addr, val);
}

enum hal_status hal_rpmh_init(vaddr_t base)
{
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	rsc_base = base;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_is_tcs_idle(uint32_t tcs_id, bool *idle)
{
	vaddr_t tcs_base = get_tcs_base(tcs_id);
	uint32_t status = 0;

	if (!idle)
		return HAL_STATUS_INVALID_PARAM;

	status = hal_read32(tcs_base + TCS_STATUS_OFFSET);
	*idle = (status & TCS_STATUS_CONTROLLER_IDLE) != 0;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_enable_amc_status(uint32_t tcs_id)
{
	uint32_t enable = hal_read32(rsc_base + RSC_DRV_IRQ_ENABLE);

	enable |= BIT(tcs_id);
	hal_write32(rsc_base + RSC_DRV_IRQ_ENABLE, enable);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_clear_amc_status(uint32_t tcs_id)
{
	hal_write32(rsc_base + RSC_DRV_IRQ_CLEAR, BIT(tcs_id));

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_get_amc_status(uint32_t tcs_id, bool *finished)
{
	uint32_t status = 0;

	if (!finished)
		return HAL_STATUS_INVALID_PARAM;

	status = hal_read32(rsc_base + RSC_DRV_IRQ_STATUS);
	*finished = (status & BIT(tcs_id)) != 0;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_send_tcs(uint32_t tcs_id, uint32_t enable_mask,
				  uint32_t wait_mask)
{
	vaddr_t tcs_base = get_tcs_base(tcs_id);
	uint32_t control = 0;

	hal_write32(tcs_base + TCS_CMD_WAIT_FOR_CMPL_OFFSET, wait_mask);
	hal_write32(tcs_base + TCS_CMD_ENABLE_OFFSET, enable_mask);
	control = hal_read32(tcs_base + TCS_CONTROL_OFFSET);
	control |= TCS_CONTROL_AMC_MODE_EN;
	control &= ~TCS_CONTROL_AMC_MODE_TRIGGER;
	hal_write32(tcs_base + TCS_CONTROL_OFFSET, control);
	control |= TCS_CONTROL_AMC_MODE_TRIGGER;
	hal_write32(tcs_base + TCS_CONTROL_OFFSET, control);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_write_cmd(uint32_t tcs_id, uint32_t cmd_idx,
				   uint32_t addr, uint32_t data,
				   bool completion)
{
	vaddr_t cmd_base = get_tcs_base(tcs_id) + TCS_CMD_BASE_OFFSET +
			   (cmd_idx * TCS_CMD_STRIDE);
	uint32_t slave_id = 0;
	uint32_t addr_reg = 0;
	uint32_t offset = 0;
	uint32_t msgid = 0;

	msgid = 0;
	msgid |= SHIFT_U32(0, MSGID_READ_OR_WRITE_SHIFT);
	msgid |= SHIFT_U32((completion ? 1 : 0), MSGID_RES_REQ_SHIFT);
	msgid |= SHIFT_U32(1, MSGID_MSG_LENGTH_SHIFT);

	slave_id = (addr >> 16) & 0x7;
	offset = addr & 0xFFFF;
	addr_reg = SHIFT_U32(slave_id, ADDR_SLV_ID_SHIFT) |
		   SHIFT_U32(offset, ADDR_OFFSET_SHIFT);

	hal_write32(cmd_base + TCS_CMDn_MSGID_OFFSET, msgid);
	hal_write32(cmd_base + TCS_CMDn_ADDR_OFFSET, addr_reg);
	hal_write32(cmd_base + TCS_CMDn_DATA_OFFSET, data);

	return HAL_STATUS_SUCCESS;
}
