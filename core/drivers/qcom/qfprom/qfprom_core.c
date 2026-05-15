// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "qfprom_hal.h"
#include "qfprom_priv.h"
#include "qfprom_target.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_MUTEX_BASE, CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SECURITY_CONTROL_BASE,
			CORE_MMU_PGDIR_SIZE);

static struct qfprom_context ctx;

struct qfprom_context *qfprom_get_context(void)
{
	return &ctx;
}

static bool is_address_valid(uint32_t addr,
			     enum qfprom_addr_space type)
{
	struct qfprom_context *qfprom_ctx = qfprom_get_context();
	paddr_t base, end;
	uint32_t lookup_addr;

	if (!qfprom_ctx || !qfprom_ctx->config ||
	    !IS_ALIGNED_WITH_TYPE(addr, uint64_t))
		return false;

	lookup_addr = addr;
	if (type == QFPROM_ADDR_SPACE_CORR)
		lookup_addr = QFPROM_RAW_TO_CORR(addr);

	if (type == QFPROM_ADDR_SPACE_RAW)
		base = qfprom_ctx->config->qfprom_raw_base;
	else
		base = qfprom_ctx->config->qfprom_corr_base;

	end = base + qfprom_ctx->config->qfprom_size;
	if (lookup_addr < base || lookup_addr >= end)
		return false;

	return true;
}

static enum qfprom_error get_region_name(uint32_t addr,
					 enum qfprom_addr_space addr_type,
					 enum qfprom_region_name *region_name)
{
	struct qfprom_context *drv = qfprom_get_context();
	uint32_t region_start, region_end;
	uint32_t lookup_addr;
	size_t i;

	if (!region_name)
		return QFPROM_DATA_PTR_NULL_ERR;

	if (!drv->config || !drv->config->region_data)
		return QFPROM_ERR_UNKNOWN;

	if (!is_address_valid(addr, addr_type))
		return QFPROM_ADDRESS_INVALID_ERR;

	lookup_addr = (addr_type == QFPROM_ADDR_SPACE_CORR) ?
		      QFPROM_RAW_TO_CORR(addr) : addr;

	for (i = 0; i < drv->config->num_regions; i++) {
		const struct qfprom_region_info *region =
			&drv->config->region_data[i];
		uint32_t offset;

		if (addr_type == QFPROM_ADDR_SPACE_RAW)
			region_start = region->raw_base_addr;
		else if (addr_type == QFPROM_ADDR_SPACE_CORR)
			region_start = region->corr_base_addr;
		else
			return QFPROM_ERR_UNKNOWN;

		region_end = region_start + (region->size * 8);

		if (lookup_addr < region_start)
			continue;

		if (lookup_addr >= region_end)
			continue;

		offset = lookup_addr - region_start;
		if (offset & 7)
			return QFPROM_ADDRESS_INVALID_ERR;

		if ((offset >> 3) >= region->size)
			return QFPROM_ADDRESS_INVALID_ERR;

		*region_name = region->region_name;
		return QFPROM_NO_ERR;
	}

	return QFPROM_REGION_NOT_SUPPORTED_ERR;
}

static int read_row(uint32_t addr,
		    enum qfprom_addr_space type,
		    uint32_t *data)
{
	if (!data)
		return QFPROM_DATA_PTR_NULL_ERR;

	if (type == QFPROM_ADDR_SPACE_RAW)
		return hal_qfprom_read_raw_address_row(addr, data);

	addr = QFPROM_RAW_TO_CORR(addr);
	return hal_qfprom_read_corrected_address_row(addr, data);
}

static enum qfprom_error is_fec_enabled(enum qfprom_region_name region_name,
					bool *fec_status)
{
	struct qfprom_context *drv = qfprom_get_context();
	const struct qfprom_region_info *info = NULL;
	enum qfprom_error err;
	paddr_t reg_addr;
	uint32_t val, bit;
	size_t i;

	if (!fec_status)
		return QFPROM_DATA_PTR_NULL_ERR;

	if (!drv->config || !drv->config->region_data)
		return QFPROM_ERR_UNKNOWN;

	for (i = 0; i < drv->config->num_regions; i++) {
		if (drv->config->region_data[i].region_name == region_name) {
			info = &drv->config->region_data[i];
			break;
		}
	}

	if (!info)
		return QFPROM_REGION_NOT_SUPPORTED_ERR;

	if (info->fec_type == QFPROM_FEC_NONE) {
		*fec_status = false;
		return QFPROM_NO_ERR;
	}

	if (info->fec_type != QFPROM_FEC_63_56 ||
	    info->region_index >= QFPROM_FEC_REGION_MSB_MAX)
		return QFPROM_ERR_UNKNOWN;

	reg_addr = QFPROM_RAW_TO_CORR(FEC_ENABLES_ADDR);
	if (info->region_index >= QFPROM_FEC_REGION_LSB_MAX) {
		reg_addr += 4;
		bit = info->region_index - QFPROM_FEC_REGION_LSB_MAX;
	} else {
		bit = info->region_index;
	}

	err = hal_qfprom_read_corrected_address(reg_addr, &val);
	if (err != QFPROM_NO_ERR) {
		EMSG("Failed to read FEC enable register at 0x%lx, error: %d",
		     reg_addr, err);
		return err;
	}

	*fec_status = !!(val & BIT32(bit));

	return QFPROM_NO_ERR;
}

static bool check_region_access(enum qfprom_region_name region_name,
				uint32_t perm_flags)
{
	struct qfprom_context *drv = qfprom_get_context();
	const struct qfprom_region_info *info = NULL;
	paddr_t perm_addr;
	uint32_t perm;
	uint32_t offset;
	size_t i;

	if (!drv->config || !drv->config->region_data)
		return false;

	for (i = 0; i < drv->config->num_regions; i++) {
		if (drv->config->region_data[i].region_name == region_name) {
			info = &drv->config->region_data[i];
			break;
		}
	}

	if (!info)
		return false;

	/* Check read permission */
	if (perm_flags & REGION_PERM_READ) {
		offset = (info->perm_reg_type == QFPROM_ROW_LSB) ?
			 drv->config->read_perm_lsb_offset :
			 drv->config->read_perm_msb_offset;
		if (!offset) {
			if (!info->read_allowed)
				return false;
		} else {
			perm_addr = drv->config->qfprom_corr_base + offset;
			if (hal_qfprom_read_corrected_address(perm_addr, &perm))
				return false;

			if (perm & info->read_perm_mask)
				return false;
		}
	}

	/* Check write permission */
	if (!(perm_flags & REGION_PERM_WRITE))
		return true;

	offset = (info->perm_reg_type == QFPROM_ROW_LSB) ?
		 drv->config->write_perm_lsb_offset :
		 drv->config->write_perm_msb_offset;
	if (!offset)
		return false;

	perm_addr = drv->config->qfprom_corr_base + offset;
	if (hal_qfprom_read_corrected_address(perm_addr, &perm))
		return false;

	if (perm & info->write_perm_mask)
		return false;

	return true;
}

static enum qfprom_error wait_blow_status_ready(void)
{
	uint64_t timer = timeout_init_us(QFPROM_BLOW_TIMEOUT_US);
	uint32_t status;
	enum qfprom_error err;

	while (true) {
		err = hal_qfprom_read_blow_status(&status);
		if (err != QFPROM_NO_ERR)
			return err;

		if (status != QFPROM_BLOW_STATUS_BUSY_VAL)
			break;

		if (timeout_elapsed(timer)) {
			EMSG("QFPROM blow operation timed out");
			return QFPROM_ERROR_TIMEOUT;
		}

		udelay(10);
	}

	if (status != QFPROM_BLOW_STATUS_READY_VAL)
		return QFPROM_WRITE_ERR;

	return QFPROM_NO_ERR;
}

static enum qfprom_error raw_write(uint32_t addr,
				   const uint32_t *data)
{
	enum qfprom_error err;
	enum qfprom_region_name region_name;
	bool fec_enabled = false;
	uint32_t verify[2];

	if (!data)
		return QFPROM_DATA_PTR_NULL_ERR;

	err = get_region_name(addr, QFPROM_ADDR_SPACE_RAW, &region_name);
	if (err != QFPROM_NO_ERR)
		return err;

	if (!check_region_access(region_name,
				 REGION_PERM_READ | REGION_PERM_WRITE))
		return QFPROM_REGION_NOT_WRITABLE_ERR;

	if (is_fec_enabled(region_name, &fec_enabled) || fec_enabled)
		return QFPROM_REGION_NOT_WRITABLE_ERR;

	err = wait_blow_status_ready();
	if (err != QFPROM_NO_ERR)
		return err;

	err = hal_qfprom_write_raw_address(addr, data[0]);
	if (err != QFPROM_NO_ERR)
		return err;

	err = wait_blow_status_ready();
	if (err != QFPROM_NO_ERR)
		return err;

	err = hal_qfprom_write_raw_address(addr + 4, data[1]);
	if (err != QFPROM_NO_ERR)
		return err;

	err = wait_blow_status_ready();
	if (err != QFPROM_NO_ERR)
		return err;

	if (!check_region_access(region_name, REGION_PERM_READ))
		return QFPROM_NO_ERR;

	err = read_row(addr, QFPROM_ADDR_SPACE_RAW, verify);
	if (err != QFPROM_NO_ERR)
		return QFPROM_NO_ERR;

	if ((verify[0] & data[0]) != data[0] ||
	    (verify[1] & data[1]) != data[1])
		return QFPROM_WRITE_ERR;

	return QFPROM_NO_ERR;
}

TEE_Result qfprom_read_row(uint32_t addr,
			   enum qfprom_addr_space type,
			   uint32_t *data)
{
	enum qfprom_region_name region_name;
	enum qfprom_error err;

	if (!data)
		return TEE_ERROR_BAD_PARAMETERS;

	err = get_region_name(addr, type, &region_name);
	if (err == QFPROM_ADDRESS_INVALID_ERR)
		return TEE_ERROR_BAD_PARAMETERS;
	else if (err != QFPROM_NO_ERR)
		return TEE_ERROR_GENERIC;

	if (!check_region_access(region_name, REGION_PERM_READ))
		return TEE_ERROR_ACCESS_DENIED;

	err = read_row(addr, type, data);
	if (err != QFPROM_NO_ERR) {
		EMSG("QFPROM read failed for address 0x%08x, error: %d",
		     addr, err);
		return TEE_ERROR_GENERIC;
	}

	if (type == QFPROM_ADDR_SPACE_CORR) {
		bool fec_enabled = false;

		err = is_fec_enabled(region_name, &fec_enabled);
		if (err != QFPROM_NO_ERR) {
			EMSG("FEC status check failed, err: %d", err);
			return TEE_ERROR_GENERIC;
		}

		if (fec_enabled && hal_qfprom_is_fec_error_seen()) {
			uint16_t err_addr = 0;

			hal_qfprom_read_error_address(&err_addr);
			EMSG("FEC error: 0x%04x req 0x%08x", err_addr, addr);
			hal_qfprom_clear_fec_error_status();
			return TEE_ERROR_CORRUPT_OBJECT;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result qfprom_hw_init(void)
{
	struct qfprom_context *drv = qfprom_get_context();
	TEE_Result res;

	res = qfprom_acquire_hw_mutex();
	if (res != TEE_SUCCESS)
		return res;

	res = qfprom_enable_voltage();
	if (res != TEE_SUCCESS)
		goto err_unlock;

	res = qfprom_write_set_clock_settings();
	if (res != TEE_SUCCESS)
		goto err_disable_voltage;

	drv->write_op_allowed = true;
	return TEE_SUCCESS;

err_disable_voltage:
	qfprom_disable_voltage();
err_unlock:
	qfprom_release_hw_mutex();
	return res;
}

void qfprom_hw_deinit(void)
{
	struct qfprom_context *drv = qfprom_get_context();

	drv->write_op_allowed = false;
	qfprom_write_reset_clock_settings();
	qfprom_disable_voltage();
	qfprom_release_hw_mutex();
}

TEE_Result qfprom_write_row(uint32_t addr, uint32_t *data)
{
	enum qfprom_error err;
	uint32_t write_data[2];

	if (!data)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ENABLED(CFG_QFPROM_PROGRAMMING))
		return TEE_ERROR_NOT_SUPPORTED;

	write_data[0] = data[0];
	write_data[1] = data[1];

	err = raw_write(addr, write_data);
	if (err != QFPROM_NO_ERR) {
		EMSG("QFPROM write failed for address 0x%08x, error: %d",
		     addr, err);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result qfprom_row_has_fec_bits(uint32_t addr,
				   enum qfprom_addr_space type,
				   uint8_t *has_fec)
{
	struct qfprom_context *drv = qfprom_get_context();
	enum qfprom_region_name region_name;
	enum qfprom_error err;
	size_t i;

	if (!has_fec)
		return TEE_ERROR_BAD_PARAMETERS;

	err = get_region_name(addr, type, &region_name);
	if (err == QFPROM_ADDRESS_INVALID_ERR)
		return TEE_ERROR_BAD_PARAMETERS;
	else if (err != QFPROM_NO_ERR)
		return TEE_ERROR_GENERIC;

	if (!drv->config || !drv->config->region_data)
		return TEE_ERROR_GENERIC;

	for (i = 0; i < drv->config->num_regions; i++) {
		const struct qfprom_region_info *region =
			&drv->config->region_data[i];

		if (region->region_name == region_name) {
			*has_fec = false;
			if (check_region_access(region_name, REGION_PERM_READ))
				*has_fec = region->fec_type != QFPROM_FEC_NONE;

			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

uint32_t qfprom_fec_63_56_bit(uint32_t lsb_data, uint32_t msb_data)
{
	uint8_t lfsr[7] = {0};
	int i = 0;
	uint32_t temp = 0;
	uint32_t fec_val = 0;
	uint64_t data_loc = 0;

	data_loc = ((uint64_t)msb_data << 32) | lsb_data;

	for (i = 0; i < 56; i++) {
		temp = lfsr[0] ^ ((data_loc >> i) & 0x1);

		lfsr[0] = lfsr[1] ^ temp;
		lfsr[1] = lfsr[2];
		lfsr[2] = lfsr[3];
		lfsr[3] = lfsr[4];
		lfsr[4] = lfsr[5] ^ temp;
		lfsr[5] = lfsr[6];
		lfsr[6] = temp;
	}

	for (i = 6; i >= 0; i--) {
		temp = (lfsr[i] << i);
		fec_val = (fec_val | temp);
	}

	return ((fec_val << 24) | msb_data);
}

static TEE_Result qfprom_init(void)
{
	struct qfprom_context *drv = qfprom_get_context();
	const struct qfprom_platform_config *config;

	config = qfprom_get_platform_config();
	if (!config) {
		EMSG("Failed to get platform configuration");
		goto err_panic;
	}

	drv->config = config;

	drv->raw_base_va = (vaddr_t)phys_to_virt(SECURITY_CONTROL_BASE,
						 MEM_AREA_IO_SEC,
						 SECURITY_CONTROL_SIZE);
	if (!drv->raw_base_va) {
		EMSG("Failed to get VA for security control at PA 0x%lx",
		     (unsigned long)SECURITY_CONTROL_BASE);
		goto err_panic;
	}

	drv->mutex_reg_va = (vaddr_t)phys_to_virt(QFPROM_MUTEX_REG_ADDR,
						  MEM_AREA_IO_SEC,
						  sizeof(uint32_t));
	if (!drv->mutex_reg_va) {
		EMSG("Failed to get VA for mutex register at PA 0x%lx",
		     (unsigned long)QFPROM_MUTEX_REG_ADDR);
		goto err_panic;
	}

	drv->corr_base_va = QFPROM_RAW_TO_CORR(drv->raw_base_va);

	return TEE_SUCCESS;

err_panic:
	panic("QFPROM driver initialization failed");
}

early_init_late(qfprom_init);
