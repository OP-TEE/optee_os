// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <io.h>
#include <util.h>

#include "rpmh_hal.h"

static struct {
	vaddr_t rsc_base;
	vaddr_t drv_base[RSC_DRV_MAX];
} rsc_base_addrs;

static inline vaddr_t get_drv_base(enum rsc_drv_id drv_id)
{
	return (drv_id >= RSC_DRV_MAX) ? 0 : rsc_base_addrs.drv_base[drv_id];
}

static inline vaddr_t get_tcs_base(vaddr_t base, uint32_t tcs_id)
{
	return base + TCS_BASE_OFFSET + (tcs_id * TCS_STRIDE);
}

static inline uint32_t hal_read32(vaddr_t addr)
{
	return io_read32(addr);
}

static inline void hal_write32(vaddr_t addr, uint32_t val)
{
	io_write32(addr, val);
}

enum hal_status hal_rpmh_init(vaddr_t rsc_base)
{
	if (!rsc_base)
		return HAL_STATUS_INVALID_PARAM;

	rsc_base_addrs.rsc_base = rsc_base;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_register_drv(enum rsc_drv_id drv_id)
{
	if (drv_id >= RSC_DRV_MAX)
		return HAL_STATUS_INVALID_PARAM;

	rsc_base_addrs.drv_base[drv_id] = rsc_base_addrs.rsc_base +
					  (drv_id * DRV_STRIDE);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_read_config(enum rsc_drv_id drv_id,
				     uint32_t *tcs, uint32_t *cmds)
{
	uint32_t config;
	vaddr_t base;

	if (!tcs || !cmds)
		return HAL_STATUS_INVALID_PARAM;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	config = hal_read32(base + RSC_DRV_TCS_CONFIG);
	*tcs = (config >> 0) & 0xFF;
	*cmds = (config >> 8) & 0xFF;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_convert_to_amc(enum rsc_drv_id drv_id,
					uint32_t tcs_id)
{
	vaddr_t base, tcs_base;
	uint32_t control;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	tcs_base = get_tcs_base(base, tcs_id);
	control = hal_read32(tcs_base + TCS_CONTROL_OFFSET);
	control |= TCS_CONTROL_AMC_MODE_EN;
	hal_write32(tcs_base + TCS_CONTROL_OFFSET, control);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_convert_to_tcs(enum rsc_drv_id drv_id,
					uint32_t tcs_id)
{
	vaddr_t base, tcs_base;
	uint32_t control;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	tcs_base = get_tcs_base(base, tcs_id);
	control = hal_read32(tcs_base + TCS_CONTROL_OFFSET);
	control &= ~TCS_CONTROL_AMC_MODE_EN;
	hal_write32(tcs_base + TCS_CONTROL_OFFSET, control);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_enable_amc_status(enum rsc_drv_id drv_id,
					   uint32_t tcs_id)
{
	uint32_t enable;
	vaddr_t base;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	enable = hal_read32(base + RSC_DRV_IRQ_ENABLE);
	enable |= BIT(tcs_id);
	hal_write32(base + RSC_DRV_IRQ_ENABLE, enable);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_clear_amc_status(enum rsc_drv_id drv_id,
					  uint32_t tcs_id)
{
	vaddr_t base;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	hal_write32(base + RSC_DRV_IRQ_CLEAR, BIT(tcs_id));

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_is_tcs_idle(enum rsc_drv_id drv_id,
				     uint32_t tcs_id, bool *idle)
{
	vaddr_t base, tcs_base;
	uint32_t status;

	if (!idle)
		return HAL_STATUS_INVALID_PARAM;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	tcs_base = get_tcs_base(base, tcs_id);
	status = hal_read32(tcs_base + TCS_STATUS_OFFSET);
	*idle = (status & TCS_STATUS_CONTROLLER_IDLE) != 0;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_get_amc_status(enum rsc_drv_id drv_id,
					uint32_t tcs_id,
					bool *finished)
{
	uint32_t status;
	vaddr_t base;

	if (!finished)
		return HAL_STATUS_INVALID_PARAM;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	status = hal_read32(base + RSC_DRV_IRQ_STATUS);
	*finished = (status & BIT(tcs_id)) != 0;

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_send_tcs(enum rsc_drv_id drv_id,
				  uint32_t tcs_id,
				  uint32_t enable_mask)
{
	vaddr_t base, tcs_base;
	uint32_t control;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	tcs_base = get_tcs_base(base, tcs_id);
	hal_write32(tcs_base + TCS_CMD_ENABLE_OFFSET, enable_mask);
	control = hal_read32(tcs_base + TCS_CONTROL_OFFSET);
	control |= TCS_CONTROL_AMC_MODE_EN;
	control &= ~TCS_CONTROL_AMC_MODE_TRIGGER;
	hal_write32(tcs_base + TCS_CONTROL_OFFSET, control);
	control |= TCS_CONTROL_AMC_MODE_TRIGGER;
	hal_write32(tcs_base + TCS_CONTROL_OFFSET, control);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_write_cmd(enum rsc_drv_id drv_id,
				   uint32_t tcs_id, uint32_t cmd_idx,
				   uint32_t addr, uint32_t data,
				   bool completion)
{
	vaddr_t base, tcs_base, cmd_base;
	uint32_t slave_id, offset;
	uint32_t msgid, addr_reg;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	tcs_base = get_tcs_base(base, tcs_id);
	cmd_base = tcs_base + TCS_CMD_BASE_OFFSET + (cmd_idx * TCS_CMD_STRIDE);

	msgid = 0;
	msgid |= (0 << MSGID_READ_OR_WRITE_SHIFT);
	msgid |= (completion ? 1 : 0) << MSGID_RES_REQ_SHIFT;
	msgid |= (1 << MSGID_MSG_LENGTH_SHIFT);

	slave_id = (addr >> 16) & 0x7;
	offset = addr & 0xFFFF;
	addr_reg = (slave_id << ADDR_SLV_ID_SHIFT) |
		   (offset << ADDR_OFFSET_SHIFT);

	hal_write32(cmd_base + TCS_CMDn_MSGID_OFFSET, msgid);
	hal_write32(cmd_base + TCS_CMDn_ADDR_OFFSET, addr_reg);
	hal_write32(cmd_base + TCS_CMDn_DATA_OFFSET, data);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_update_epcb_timeout(enum rsc_drv_id drv_id,
					     uint32_t threshold)
{
	uint32_t val;
	vaddr_t base;

	if (drv_id != RSC_DRV_SECURE)
		return HAL_STATUS_INVALID_PARAM;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	val = hal_read32(base + RSC_DRV_ERROR_IRQ_ENABLE);
	val &= ~EPCB_TIMEOUT_THRESHOLD_MASK;
	val |= (threshold & EPCB_TIMEOUT_THRESHOLD_MASK) <<
	       EPCB_TIMEOUT_THRESHOLD_SHIFT;
	hal_write32(base + RSC_DRV_ERROR_IRQ_ENABLE, val);

	return HAL_STATUS_SUCCESS;
}

enum hal_status hal_rpmh_toggle_epcb_timeout(enum rsc_drv_id drv_id,
					     bool enable)
{
	uint32_t val;
	vaddr_t base;

	if (drv_id != RSC_DRV_SECURE)
		return HAL_STATUS_INVALID_PARAM;

	base = get_drv_base(drv_id);
	if (!base)
		return HAL_STATUS_INVALID_PARAM;

	val = hal_read32(base + RSC_DRV_ERROR_IRQ_ENABLE);
	if (enable)
		val |= EPCB_TIMEOUT_IRQ_EN_MASK;
	else
		val &= ~EPCB_TIMEOUT_IRQ_EN_MASK;
	hal_write32(base + RSC_DRV_ERROR_IRQ_ENABLE, val);

	return HAL_STATUS_SUCCESS;
}
