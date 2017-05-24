/*
 * Copyright (c) 2016, Xilinx Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <io.h>
#include <kernel/static_ta.h>
#include <kernel/tz_ssvce.h>
#include <mm/core_memprot.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>
#include <zynqmp_bsload.h>

#define TA_NAME "BSLOAD"

#define CSU_PA_BASE			0xFFCA0000
#define CSUDMA_PA_BASE			0xFFC80000

#define CSU_SSS_CONFIG			(csu_base + 0x08)
#define CSU_SSS_CFG_PCAP_SSS_MASK	0xF
#define CSU_SSS_CFG_PCAP_SSS_SHFT	0x0
#define CSU_SSS_CFG_PCAP_DMA_DATA	0x5
#define CSU_PCAP_RESET			(csu_base + 0x300C)
#define CSU_PCAP_RDWR			(csu_base + 0x3004)
#define CSU_PCAP_CTRL			(csu_base + 0x3008)
#define CSU_PCAP_PROG			(csu_base + 0x3000)
#define CSU_PCAP_STATUS			(csu_base + 0x3010)
#define CSU_PCAP_RESET_RESET		BIT(0)
#define CSU_PCAP_CTRL_PCAP_PR		BIT(0)
#define CSU_PCAP_PROG_PCFG_PROG_B	BIT(0)
#define CSU_PCAP_STATUS_PCAP_WR_IDLE	BIT(0)
#define CSU_PCAP_STATUS_PL_INIT		BIT(2)
#define CSU_PCAP_STATUS_PL_DONE		BIT(3)
#define CSU_PCAP_STATUS_PL_RESET_B	BIT(6)

#define CSUDMA_SRC_ADDR				(csudma_base + 0x000)
#define CSUDMA_SRC_CRC				(csudma_base + 0x010)
#define CSUDMA_SRC_SIZE				(csudma_base + 0x004)
#define CSUDMA_SRC_I_STS			(csudma_base + 0x014)
#define CSUDMA_SRC_ADDR_MSB			(csudma_base + 0x028)
#define CSUDMA_SRC_I_STS_DONE			BIT(1)
#define CSUDMA_SRC_SIZE_MASK			0x1ffffffc
#define CSUDMA_SRC_ADDR_MSB_ADDR_MSB_MASK	0x1FFFF

#define DUMMY_WORD			0xffffffff
#define BS_SIZE_MAX			0x1fffffff
#define POLL_TIMEOUT			0x8000000

register_phys_mem(MEM_AREA_IO_SEC, CSU_PA_BASE, CORE_MMU_DEVICE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, CSUDMA_PA_BASE, CORE_MMU_DEVICE_SIZE);

static vaddr_t csu_base;
static vaddr_t csudma_base;

/* Xilinx binary format header */
static const uint32_t bin_format[] = {
	DUMMY_WORD, /* Dummy words */
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	DUMMY_WORD,
	0x000000bb, /* Sync word */
	0x11220044, /* Sync word */
	DUMMY_WORD,
	DUMMY_WORD,
	0xaa995566, /* Sync word */
};

static TEE_Result poll_reg_tout_32(vaddr_t addr, uint32_t mask, uint32_t val,
				   ssize_t tout)
{
	uint32_t reg;

	do {
		reg = read32(addr);
	} while (((reg & mask) != val) && tout--);

	if (tout <= 0)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result check_header(const vaddr_t buf)
{
	const uint32_t *test = (const uint32_t *)buf;

	for (size_t i = 0; i < ARRAY_SIZE(bin_format); i++) {
		if (test[i] != bin_format[i])
			return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

static TEE_Result pcap_init(void)
{
	TEE_Result ret;

	/* reset PCAP */
	write32(CSU_PCAP_RESET_RESET, CSU_PCAP_RESET);
	write32(0, CSU_PCAP_RESET);

	write32(CSU_PCAP_CTRL_PCAP_PR, CSU_PCAP_CTRL);
	write32(0, CSU_PCAP_RDWR);

	/* reset PL */
	write32(0, CSU_PCAP_PROG);
	ret = poll_reg_tout_32(CSU_PCAP_STATUS, CSU_PCAP_STATUS_PL_RESET_B, 0,
			       POLL_TIMEOUT);
	if (ret != TEE_SUCCESS) {
		DMSG("timeout waiting for PL reset");
		return ret;
	}

	write32(CSU_PCAP_PROG_PCFG_PROG_B, CSU_PCAP_PROG);
	ret = poll_reg_tout_32(CSU_PCAP_STATUS, CSU_PCAP_STATUS_PL_INIT,
			       CSU_PCAP_STATUS_PL_INIT, POLL_TIMEOUT);
	if (ret != TEE_SUCCESS) {
		DMSG("timeout waiting for PL init done");
		return ret;
	}

	return TEE_SUCCESS;
}

static TEE_Result pcap_write(uint64_t srcaddr, uint32_t size)
{
	TEE_Result ret;

	write32(0, CSUDMA_SRC_CRC);
	write32(CSU_SSS_CFG_PCAP_DMA_DATA << CSU_SSS_CFG_PCAP_SSS_SHFT,
		CSU_SSS_CONFIG);

	write32((uint32_t)srcaddr, CSUDMA_SRC_ADDR);
	write32((srcaddr >> 32) & CSUDMA_SRC_ADDR_MSB_ADDR_MSB_MASK,
		CSUDMA_SRC_ADDR_MSB);
	write32(size & CSUDMA_SRC_SIZE_MASK, CSUDMA_SRC_SIZE);

	ret = poll_reg_tout_32(CSUDMA_SRC_I_STS, CSUDMA_SRC_I_STS_DONE,
			       CSUDMA_SRC_I_STS_DONE, POLL_TIMEOUT);
	if (ret != TEE_SUCCESS) {
		DMSG("timeout writing bitstream");
		return ret;
	}

	write32(CSUDMA_SRC_I_STS_DONE, CSUDMA_SRC_I_STS);

	ret = poll_reg_tout_32(CSU_PCAP_STATUS, CSU_PCAP_STATUS_PCAP_WR_IDLE,
			       CSU_PCAP_STATUS_PCAP_WR_IDLE, POLL_TIMEOUT);
	if (ret != TEE_SUCCESS) {
		DMSG("timeout waiting for CSUDMA idle");
		return ret;
	}

	DMSG("SRC_CRC: %#" PRIx32, read32(CSUDMA_SRC_CRC));

	return TEE_SUCCESS;
}

static TEE_Result wait_done(void)
{
	TEE_Result ret;

	ret = poll_reg_tout_32(CSU_PCAP_STATUS, CSU_PCAP_STATUS_PL_DONE,
			       CSU_PCAP_STATUS_PL_DONE, POLL_TIMEOUT);
	if (ret != TEE_SUCCESS) {
		DMSG("timeout waiting for PL done");
		return ret;
	}

	io_mask32(CSU_PCAP_RESET, CSU_PCAP_RESET_RESET, CSU_PCAP_RESET_RESET);
	ret = poll_reg_tout_32(CSU_PCAP_RESET, CSU_PCAP_RESET_RESET,
			       CSU_PCAP_RESET_RESET, POLL_TIMEOUT);
	if (ret != TEE_SUCCESS) {
		DMSG("timeout waiting for PCAP reset assert");
		return ret;
	}

	return TEE_SUCCESS;
}

static TEE_Result do_load_bs(vaddr_t bs, size_t sz, __unused uint64_t flags)
{
	paddr_t addr;
	TEE_Result ret;

	/* sanity check bitstream */
	if (!ALIGNMENT_IS_OK(bs, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	if (sz > BS_SIZE_MAX)
		return TEE_ERROR_EXCESS_DATA;

	ret = check_header(bs);
	if (ret)
		return ret;

	addr = virt_to_phys((void *)bs);
	if (!addr) {
		DMSG("no mapping found for va '%#" PRIxVA "'", bs);
		return TEE_ERROR_GENERIC;
	}
	DMSG("bitstream va:%#" PRIxVA ", pa:%#" PRIxPA ", sz:%#zx",
	     bs, addr, sz);

	cache_maintenance_l1(DCACHE_AREA_CLEAN_INV, (void *)bs, sz);

	/* program PL */
	ret = pcap_init();
	if (ret)
		return ret;

	ret = pcap_write(addr, sz);
	if (ret)
		return ret;

	return wait_done();
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	if (!csu_base) {
		csu_base = (vaddr_t)phys_to_virt(CSU_PA_BASE, MEM_AREA_IO_SEC);
		if (!csu_base)
			return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (!csudma_base) {
		csudma_base = (vaddr_t)phys_to_virt(CSUDMA_PA_BASE,
						    MEM_AREA_IO_SEC);
		if (!csudma_base)
			return TEE_ERROR_ITEM_NOT_FOUND;
	}

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    __unused TEE_Param  params[4],
				    __unused void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(__unused void *sess_ctx)
{
}

/**
 * load_bistream - Load a bitstream into the PL
 * @params[0]: Memref describing buffer holding the bitstream
 * @params[1]: Value holding flags.
 */
static TEE_Result load_bitstream(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("bitstream va:%#" PRIxVA ", size:%#" PRIx32,
			params[0].memref.buffer, params[0].memref.size);
	if (!params[0].memref.buffer || !params[0].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	return do_load_bs((vaddr_t)params[0].memref.buffer,
			  params[0].memref.size, params[1].value.a);
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the parameters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(__unused void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case ZYNQMP_BSLOAD_CMD_LOAD_BITSTREAM:
		return load_bitstream(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static_ta_register(.uuid = ZYNQMP_BSLOAD_UUID, .name = TA_NAME,
		   .create_entry_point = TA_CreateEntryPoint,
		   .destroy_entry_point = TA_DestroyEntryPoint,
		   .open_session_entry_point = TA_OpenSessionEntryPoint,
		   .close_session_entry_point = TA_CloseSessionEntryPoint,
		   .invoke_command_entry_point = TA_InvokeCommandEntryPoint);
