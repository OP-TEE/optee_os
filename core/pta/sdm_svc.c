// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024-2026, Altera Corporation.
 *
 * Pseudo-TA: SDM services via ATF FCS SiP SMCs.
 */

#include <initcall.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/thread_arch.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <pta_sdm_svc.h>
#include <string.h>
#include <string_ext.h>
#include <tee/tee_svc.h>
#include <trace.h>

/* SDM DMA remap/stream-control offsets in System Manager */
#define SYSMGR_SDM_AWADDR_REMAP_OFF 0x280
#define SYSMGR_SDM_ARADDR_REMAP_OFF 0x284
#define SYSMGR_SDM_STREAM_CTRL_OFF 0x184

#define SDM_STREAM_NS 0x03U
#define SDM_STREAM_SECURE 0x33U
#define SDM_REMAP_DRAM_BASE 0x80000000U

#define PTA_NAME "sdm_svc.pta"

#define ALTERA_SIP_SMC_ASYNC_GET_IDCODE 0x420000D3
#define ALTERA_SIP_SMC_ASYNC_FCS_OPEN_CS_SESSION 0x4200013A
#define ALTERA_SIP_SMC_ASYNC_FCS_CLOSE_CS_SESSION 0x4200013B
#define ALTERA_SIP_SMC_ASYNC_FCS_RANDOM_NUMBER_EXT 0x4200012D
#define ALTERA_SIP_SMC_ASYNC_FCS_CRYPTION_EXT 0x4200012F
#define ALTERA_SIP_SMC_ASYNC_FCS_SEND_CERTIFICATE 0x42000131
#define ALTERA_SIP_SMC_ASYNC_FCS_GET_PROVISION_DATA 0x42000132
#define ALTERA_SIP_SMC_ASYNC_FCS_CHIP_ID 0x42000135
#define ALTERA_SIP_SMC_ASYNC_FCS_PROGRAM_OWNER_PUBKEY 0x4200016D
#define ALTERA_SIP_SMC_ASYNC_SDM_EFUSE_RELOAD_CACHE 0x4200016C
#define ALTERA_SIP_SMC_ASYNC_FCS_EFUSE_USER_SECURITY_OPTION 0x42000170
#define ALTERA_SIP_SMC_ASYNC_SECURE_EFUSE_WRITE_DISABLE 0x42000177
#define ALTERA_SIP_SMC_ASYNC_SECURE_EFUSE_PUBKEY_PROGRAM_PHASE2 0x42000178
#define ALTERA_SIP_SMC_ASYNC_SECURE_DISABLE_ENTRY_TO_OWNED 0x42000179
#define ALTERA_SIP_SMC_NS_ALLOWED_LIST_ADD 0x4200017E
#define ALTERA_SIP_SMC_NS_ALLOWED_LIST_REMOVE 0x4200017F
#define ALTERA_SIP_SMC_NS_ALLOWED_LIST_CLEAR 0x42000180
#define ALTERA_SIP_SMC_NS_ALLOWED_LIST_DEACTIVATE 0x42000181
#define ALTERA_SIP_SMC_ASYNC_RESP_POLL 0x420000C8
#define ALTERA_SIP_SMC_ASYNC_GEN_MBOX_CMD 0x420000EE

#define INTEL_SIP_SMC_FIRMWARE_VERSION 0xC200001F

#define INTEL_SIP_SMC_GET_USERCODE 0xC200003D
#define INTEL_SIP_SMC_REG_UPDATE 0xC2000009
#define INTEL_SIP_SMC_REG_READ 0xC2000007
#define INTEL_SIP_SMC_REG_WRITE 0xC2000008
#define INTEL_SIP_SMC_MBOX_SEND_CMD 0xC200003C

#define INTEL_SIP_SMC_FPGA_CONFIG_START 0xC2000001
#define INTEL_SIP_SMC_FPGA_CONFIG_WRITE 0x42000002
#define INTEL_SIP_SMC_FPGA_CONFIG_COMPLETED_WRITE 0xC2000003
#define INTEL_SIP_SMC_FPGA_CONFIG_ISDONE 0xC2000004
#define INTEL_SIP_SMC_FPGA_CONFIG_GET_MEM 0xC2000005
#define INTEL_SIP_SMC_HPS_SET_BRIDGES 0xC2000032

#define INTEL_SIP_SMC_RSU_STATUS 0xC200000B
#define INTEL_SIP_SMC_RSU_UPDATE 0xC200000C
#define INTEL_SIP_SMC_RSU_NOTIFY 0xC200000E
#define INTEL_SIP_SMC_RSU_RETRY_COUNTER 0xC200000F
#define INTEL_SIP_SMC_RSU_MAX_RETRY 0xC2000012
#define INTEL_SIP_SMC_RSU_DCMF_VERSION 0xC2000010
#define INTEL_SIP_SMC_RSU_DCMF_STATUS 0xC2000014
#define INTEL_SIP_SMC_RSU_COPY_DCMF_VERSION 0xC2000011
#define INTEL_SIP_SMC_RSU_COPY_DCMF_STATUS 0xC2000015
#define INTEL_SIP_SMC_RSU_COPY_MAX_RETRY 0xC2000013
#define INTEL_SIP_SMC_ECC_DBE 0xC200000D

#define INTEL_SIP_SMC_SDM_REMAPPER_CONFIG 0xC2000201

#define INTEL_SIP_SMC_SVC_VERSION 0xC2000200

/* ATF build version SiP */
#define INTEL_SIP_SMC_ATF_BUILD_VER 0xC200009B

#define INTEL_SIP_SMC_ASYNC_POLL_ON_IRQ 0x420000C9

#define INTEL_SIP_SMC_FCS_CHIP_ID 0xC2000065

#define SDM_NS_ALLOWED_LIST_DEFAULT { \
	INTEL_SIP_SMC_GET_USERCODE, \
	INTEL_SIP_SMC_REG_UPDATE, \
	INTEL_SIP_SMC_REG_READ, \
	INTEL_SIP_SMC_REG_WRITE, \
	INTEL_SIP_SMC_MBOX_SEND_CMD, \
	INTEL_SIP_SMC_FPGA_CONFIG_START, \
	INTEL_SIP_SMC_FPGA_CONFIG_WRITE, \
	INTEL_SIP_SMC_FPGA_CONFIG_COMPLETED_WRITE, \
	INTEL_SIP_SMC_FPGA_CONFIG_ISDONE, \
	INTEL_SIP_SMC_FPGA_CONFIG_GET_MEM, \
	INTEL_SIP_SMC_HPS_SET_BRIDGES, \
	INTEL_SIP_SMC_RSU_STATUS, \
	INTEL_SIP_SMC_RSU_UPDATE, \
	INTEL_SIP_SMC_RSU_NOTIFY, \
	INTEL_SIP_SMC_RSU_RETRY_COUNTER, \
	INTEL_SIP_SMC_RSU_MAX_RETRY, \
	INTEL_SIP_SMC_RSU_DCMF_VERSION, \
	INTEL_SIP_SMC_RSU_DCMF_STATUS, \
	INTEL_SIP_SMC_RSU_COPY_DCMF_VERSION, \
	INTEL_SIP_SMC_RSU_COPY_DCMF_STATUS, \
	INTEL_SIP_SMC_RSU_COPY_MAX_RETRY, \
	INTEL_SIP_SMC_ECC_DBE, \
	INTEL_SIP_SMC_SDM_REMAPPER_CONFIG, \
	INTEL_SIP_SMC_SVC_VERSION, \
	INTEL_SIP_SMC_ATF_BUILD_VER, \
	ALTERA_SIP_SMC_ASYNC_RESP_POLL, \
	INTEL_SIP_SMC_ASYNC_POLL_ON_IRQ, \
	ALTERA_SIP_SMC_ASYNC_FCS_OPEN_CS_SESSION, \
	ALTERA_SIP_SMC_ASYNC_FCS_CLOSE_CS_SESSION, \
	INTEL_SIP_SMC_FIRMWARE_VERSION, \
	ALTERA_SIP_SMC_ASYNC_GET_IDCODE,  \
	ALTERA_SIP_SMC_ASYNC_FCS_CHIP_ID, \
}

/* NS allow-list sync status (2 = secure-world / busy; not async BUSY=1) */
#define INTEL_SIP_SMC_NS_LIST_STATUS_OK 0
#define INTEL_SIP_SMC_NS_LIST_STATUS_BUSY 2

/* SYSMGR regs reachable via INTEL_SIP_SMC_REG_WRITE */
#define SDM_STREAM_CTRL_REG 0x10D12184U
#define SDM_BE_AWADDR_REMAP_REG 0x10D12280U
#define SDM_BE_ARADDR_REMAP_REG 0x10D12284U

#define INTEL_SIP_SMC_STATUS_OK 0
#define INTEL_SIP_SMC_STATUS_BUSY 1

#define FCS_MODE_DECRYPT 0
#define FCS_MODE_ENCRYPT 1

#define SDM_CRYPT_POLL_MAX 10000

#define SDM_RNG_HDR_BYTES 12U

static void thread_smccc_ext(struct thread_smc_args *args,
			     uint64_t a8, uint64_t a9,
			     uint64_t a10, uint64_t a11)
{
	register uint64_t x0  asm("x0")	 = args->a0;
	register uint64_t x1  asm("x1")	 = args->a1;
	register uint64_t x2  asm("x2")	 = args->a2;
	register uint64_t x3  asm("x3")	 = args->a3;
	register uint64_t x4  asm("x4")	 = args->a4;
	register uint64_t x5  asm("x5")	 = args->a5;
	register uint64_t x6  asm("x6")	 = args->a6;
	register uint64_t x7  asm("x7")	 = args->a7;
	register uint64_t x8  asm("x8")	 = a8;
	register uint64_t x9  asm("x9")	 = a9;
	register uint64_t x10 asm("x10") = a10;
	register uint64_t x11 asm("x11") = a11;

	asm volatile("smc #0"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		: "r"(x4),  "r"(x5),  "r"(x6),	"r"(x7),
		  "r"(x8),  "r"(x9),  "r"(x10), "r"(x11)
		: "memory", "x12", "x13", "x14", "x15", "x16", "x17"
	);

	args->a0 = x0;
	args->a1 = x1;
	args->a2 = x2;
	args->a3 = x3;
}

static TEE_Result poll_until_done(uint64_t trans_id,
				  struct thread_smc_args *out)
{
	struct thread_smc_args args = { };
	int i = 0;

	for (i = 0; i < SDM_CRYPT_POLL_MAX; i++) {
		args.a0 = ALTERA_SIP_SMC_ASYNC_RESP_POLL;
		args.a1 = trans_id;
		thread_smccc(&args);
		if ((uint32_t)args.a0 == INTEL_SIP_SMC_STATUS_OK)
			break;
	}

	if (i == SDM_CRYPT_POLL_MAX) {
		EMSG("SDM async poll timeout (%d)", SDM_CRYPT_POLL_MAX);
		return TEE_ERROR_BUSY;
	}

	if (args.a1 != 0) {
		EMSG("SDM mailbox error: a1=0x%" PRIx64, args.a1);
		return TEE_ERROR_GENERIC;
	}

	if (out)
		*out = args;

	return TEE_SUCCESS;
}

static TEE_Result send_pubkey_program_phase2(uint64_t request_header)
{
	struct thread_smc_args args = { };
	TEE_Result res = TEE_SUCCESS;

	args.a0 = ALTERA_SIP_SMC_ASYNC_SECURE_EFUSE_PUBKEY_PROGRAM_PHASE2;
	args.a1 = request_header;
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("pubkey phase2 submit failed: a0=0x%" PRIx64,
		     args.a0);
		return TEE_ERROR_GENERIC;
	}

	res = poll_until_done(0, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("pubkey phase2 rejected hdr=0x%" PRIx64,
		     request_header);
		return res;
	}

	DMSG("pubkey phase2 accepted hdr=0x%" PRIx64 ")",
	     request_header);
	return TEE_SUCCESS;
}

static TEE_Result
trigger_pubkey_program_phase2_finalize(bool non_volatile,
				       uint32_t *phase2_status_out)
{
	TEE_Result res = TEE_SUCCESS;

	if (phase2_status_out)
		*phase2_status_out = SDM_PHASE2_STATUS_FAILED;

	DMSG("phase2_finalize: holding 1s before phase-2 trigger (mode=%s)",
	     non_volatile ? "physical/NON-VOLATILE" : "virtual/cache-only");
	mdelay(1000);

	res = send_pubkey_program_phase2(0);
	if (res != TEE_SUCCESS) {
		EMSG("phase2_finalize: phase-2 SMC failed (0x%" PRIx32 ")",
		     (uint32_t)res);
		return res;
	}

	if (phase2_status_out)
		*phase2_status_out = non_volatile ? SDM_PHASE2_STATUS_SUCCESS
						  : SDM_PHASE2_STATUS_NOP;

	DMSG("phase2_finalize: complete (%s)",
	     non_volatile ? "SUCCESS / Soft POR will be triggered"
			  : "NOP / Soft POR suppressed (virtual fusing)");
	return TEE_SUCCESS;
}

static TEE_Result get_version(uint32_t ptypes,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	params[0].value.a = PTA_SDM_SVC_API_VERSION;
	return TEE_SUCCESS;
}

static TEE_Result get_id_code(uint32_t ptypes,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_smc_args args = { };
	struct thread_smc_args poll_result = { };
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	args.a0 = ALTERA_SIP_SMC_ASYNC_GET_IDCODE;
	args.a1 = 0; /* trans_id */
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("get_idcode submit failed: a0=0x%" PRIx64, args.a0);
		return TEE_ERROR_GENERIC;
	}

	res = poll_until_done(0, &poll_result);
	if (res != TEE_SUCCESS)
		return res;

	/* JTAG IDCODE bit0 must be 1 (IEEE 1149.1) */
	if (!((uint32_t)poll_result.a2 & 1U)) {
		EMSG("invalid JTAG IDCODE 0x%" PRIx64 " (bit 0 must be 1)",
		     poll_result.a2);
		return TEE_ERROR_GENERIC;
	}

	params[0].value.a = (uint32_t)poll_result.a2;
	params[0].value.b = 0;

	return TEE_SUCCESS;
}

static TEE_Result get_chip_id(uint32_t ptypes,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	struct thread_smc_args args = { };

	if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	args.a0 = INTEL_SIP_SMC_FCS_CHIP_ID;
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("ATF returned status 0x%" PRIx64 " mbox_error 0x%" PRIx64,
		     args.a0, args.a1);
		return TEE_ERROR_GENERIC;
	}

	if (args.a1 != 0) {
		EMSG("mailbox status 0x%" PRIx64, args.a1);
		return TEE_ERROR_GENERIC;
	}

	params[0].value.a = (uint32_t)args.a2;
	params[0].value.b = (uint32_t)args.a3;

	return TEE_SUCCESS;
}

static TEE_Result cmd_sdm_sdos_crypt(uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	struct thread_smc_args poll_result = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t direction = 0;
	void *src_buf = NULL;	/* NS shared memory from CA (input) */
	size_t src_size = 0;
	void *dst_buf = NULL;	/* NS shared memory from CA (output) */
	size_t dst_size = 0;
	void *sec_src = NULL;	/* TZDRAM SDM DMA source */
	void *sec_dst = NULL;	/* TZDRAM SDM DMA destination */
	paddr_t sec_src_phys = 0;
	paddr_t sec_dst_phys = 0;
	uint32_t smmu_src = 0;
	uint32_t smmu_dst = 0;
	uint32_t session_id = 0;
	size_t out_size = 0;
	vaddr_t sysmgr = 0;
	uint32_t awaddr_remap = 0;
	uint32_t araddr_remap = 0;
	uint32_t stream_ctrl = 0;
	uint32_t saved_stream_ctrl = 0;
	bool changed_remap = false;
	bool changed_stream = false;

	if (ptypes != exp_types) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	direction = params[0].value.a;
	src_buf	 = params[1].memref.buffer;
	src_size = params[1].memref.size;
	dst_buf	 = params[2].memref.buffer;
	dst_size = params[2].memref.size;

	if (!src_buf || !src_size || !dst_buf || !dst_size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (direction != FCS_MODE_ENCRYPT && direction != FCS_MODE_DECRYPT) {
		EMSG("invalid direction %" PRIu32, direction);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	sysmgr = (vaddr_t)phys_to_virt(SYSMGR_BASE, MEM_AREA_IO_NSEC,
					SYSMGR_SIZE);
	awaddr_remap = io_read32(sysmgr + SYSMGR_SDM_AWADDR_REMAP_OFF);
	araddr_remap = io_read32(sysmgr + SYSMGR_SDM_ARADDR_REMAP_OFF);
	stream_ctrl  = io_read32(sysmgr + SYSMGR_SDM_STREAM_CTRL_OFF);
	saved_stream_ctrl = stream_ctrl;

	/* SDM DMA targets TZDRAM only; use aligned secure bounce buffers */
	sec_src = memalign(32, src_size);
	if (!sec_src)
		return TEE_ERROR_OUT_OF_MEMORY;

	sec_dst = memalign(32, dst_size);
	if (!sec_dst) {
		free(sec_src);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	sec_src_phys = virt_to_phys(sec_src);
	sec_dst_phys = virt_to_phys(sec_dst);
	smmu_src = (uint32_t)(sec_src_phys - SDM_REMAP_DRAM_BASE);
	smmu_dst = (uint32_t)(sec_dst_phys - SDM_REMAP_DRAM_BASE);

	memmove(sec_src, src_buf, src_size);
	cache_op_inner(DCACHE_AREA_CLEAN, sec_src, src_size);
	cache_op_inner(DCACHE_AREA_CLEAN_INV, sec_dst, dst_size);

	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_OPEN_CS_SESSION;
	args.a1 = 0;
	thread_smccc(&args);
	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("open_cs_session submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bounce;
	}

	res = poll_until_done(0, &poll_result);
	if (res != TEE_SUCCESS)
		goto free_bounce;

	session_id = (uint32_t)poll_result.a2;

	memset(&args, 0, sizeof(args));
	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_CRYPTION_EXT;
	args.a1 = 0;
	args.a2 = session_id;
	args.a3 = 0;
	args.a4 = direction;
	args.a5 = (uint64_t)sec_src_phys; /* TZDRAM phys */
	args.a6 = (uint64_t)src_size;
	args.a7 = (uint64_t)sec_dst_phys; /* TZDRAM phys */

	if (awaddr_remap != SDM_REMAP_DRAM_BASE ||
	    araddr_remap != SDM_REMAP_DRAM_BASE) {
		struct thread_smc_args smc = { };

		smc.a0 = INTEL_SIP_SMC_REG_WRITE;
		smc.a1 = SDM_BE_AWADDR_REMAP_REG;
		smc.a2 = SDM_REMAP_DRAM_BASE;
		thread_smccc(&smc);
		memset(&smc, 0, sizeof(smc));
		smc.a0 = INTEL_SIP_SMC_REG_WRITE;
		smc.a1 = SDM_BE_ARADDR_REMAP_REG;
		smc.a2 = SDM_REMAP_DRAM_BASE;
		thread_smccc(&smc);
		changed_remap = true;
	}

	if (stream_ctrl != SDM_STREAM_SECURE) {
		struct thread_smc_args smc = { };

		smc.a0 = INTEL_SIP_SMC_REG_WRITE;
		smc.a1 = SDM_STREAM_CTRL_REG;
		smc.a2 = SDM_STREAM_SECURE;
		thread_smccc(&smc);
		changed_stream = true;
	}

	thread_smccc_ext(&args, (uint64_t)dst_size, 0,
			 (uint64_t)smmu_src, (uint64_t)smmu_dst);
	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("crypt submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto close_session;
	}

	res = poll_until_done(0, &poll_result);
	if (res != TEE_SUCCESS)
		goto close_session;

	out_size = (size_t)poll_result.a2;
	DMSG("sdos_crypt: dir=%u out_size=%zu", direction, out_size);

	/* Invalidate after SDM DMA; reject out_size > dst_size before copy */
	cache_op_inner(DCACHE_AREA_INVALIDATE, sec_dst, dst_size);
	if (out_size > dst_size) {
		EMSG("sdm_crypt: ATF output size %zu exceeds caller buffer %zu",
		     out_size, dst_size);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto close_session;
	}
	memmove(dst_buf, sec_dst, out_size);
	params[2].memref.size = out_size;

close_session:
	if (changed_stream) {
		struct thread_smc_args smc = { };

		smc.a0 = INTEL_SIP_SMC_REG_WRITE;
		smc.a1 = SDM_STREAM_CTRL_REG;
		smc.a2 = saved_stream_ctrl;
		thread_smccc(&smc);
	}

	if (changed_remap) {
		struct thread_smc_args smc = { };

		smc.a0 = INTEL_SIP_SMC_REG_WRITE;
		smc.a1 = SDM_BE_AWADDR_REMAP_REG;
		smc.a2 = awaddr_remap;	/* restore original value */
		thread_smccc(&smc);
		memset(&smc, 0, sizeof(smc));
		smc.a0 = INTEL_SIP_SMC_REG_WRITE;
		smc.a1 = SDM_BE_ARADDR_REMAP_REG;
		smc.a2 = araddr_remap;	/* restore original value */
		thread_smccc(&smc);
	}

	{
		struct thread_smc_args close_args = { };

		close_args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_CLOSE_CS_SESSION;
		close_args.a1 = 0;
		close_args.a2 = session_id;
		thread_smccc(&close_args);
		if (close_args.a0 == INTEL_SIP_SMC_STATUS_OK)
			poll_until_done(0, NULL);
	}

free_bounce:
	if (sec_src)
		memzero_explicit(sec_src, src_size);
	if (sec_dst)
		memzero_explicit(sec_dst, dst_size);
	free(sec_src);
	free(sec_dst);
	return res;
}

static TEE_Result cmd_sdm_get_random(uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	struct thread_smc_args poll_result = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t size = 0;
	void *out_buf = NULL;
	size_t out_size = 0;
	uint8_t *bounce = NULL;
	paddr_t bounce_phys = 0;
	uint32_t session_id = 0;

	if (ptypes != exp_types) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size	= params[0].value.a;
	out_buf = params[1].memref.buffer;
	out_size = params[1].memref.size;

	if (size == 0 || (size % 4) != 0 || size > SDM_RNG_MAX_BYTES) {
		EMSG("invalid size %" PRIu32 ": must be 4-aligned, 4..%u",
		     size, SDM_RNG_MAX_BYTES);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!out_buf || out_size < size) {
		EMSG("output buffer too small: %zu < %" PRIu32, out_size, size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	bounce = memalign(4, SDM_RNG_HDR_BYTES + size);
	if (!bounce)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(bounce, 0, SDM_RNG_HDR_BYTES + size);
	cache_op_inner(DCACHE_AREA_CLEAN, bounce, SDM_RNG_HDR_BYTES + size);
	bounce_phys = virt_to_phys(bounce);

	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_OPEN_CS_SESSION;
	args.a1 = 0;
	thread_smccc(&args);
	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("open_cs_session submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bounce;
	}

	res = poll_until_done(0, &poll_result);
	if (res != TEE_SUCCESS)
		goto free_bounce;

	session_id = (uint32_t)poll_result.a2;

	memset(&args, 0, sizeof(args));
	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_RANDOM_NUMBER_EXT;
	args.a1 = 0;			/* trans_id */
	args.a2 = session_id;
	args.a3 = 0;			/* context_id */
	args.a4 = (uint64_t)bounce_phys;/* destination (TZDRAM) */
	args.a5 = (uint64_t)size;	/* byte count */
	thread_smccc(&args);
	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("get_random submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto close_session;
	}

	res = poll_until_done(0, NULL);
	if (res != TEE_SUCCESS)
		goto close_session;

	/* Invalidate bounce after ATF/EL3 stores */
	cache_op_inner(DCACHE_AREA_INVALIDATE, bounce,
		       SDM_RNG_HDR_BYTES + size);

	memmove(out_buf, bounce + SDM_RNG_HDR_BYTES, size);
	params[1].memref.size = size;
	DMSG("sdm_get_random: %" PRIu32 " bytes of random data returned", size);

close_session:
	{
		struct thread_smc_args close_args = { };

		close_args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_CLOSE_CS_SESSION;
		close_args.a1 = 0;
		close_args.a2 = session_id;
		thread_smccc(&close_args);
		if (close_args.a0 == INTEL_SIP_SMC_STATUS_OK)
			poll_until_done(0, NULL);
	}

free_bounce:
	if (bounce)
		memzero_explicit(bounce, SDM_RNG_HDR_BYTES + size);
	free(bounce);
	return res;
}

static uint32_t cert_rd32(const uint8_t *cert, size_t off)
{
	return (uint32_t)cert[off] |
	       ((uint32_t)cert[off + 1] << 8) |
	       ((uint32_t)cert[off + 2] << 16) |
	       ((uint32_t)cert[off + 3] << 24);
}

static bool cert_is_key_cancellation(const uint8_t *cert, size_t cert_size)
{
	uint32_t magic = 0;
	uint32_t cert_type = 0;
	uint32_t counter_type = 0;

	if (cert_size < SDM_CERT_MIN_HDR_BYTES) {
		IMSG("sdm_send_cert: blob %zu too short (need %u)",
		     cert_size, SDM_CERT_MIN_HDR_BYTES);
		return false;
	}

	magic = cert_rd32(cert, SDM_CERT_OFF_MAGIC);
	if (magic != SDM_CERT_MAGIC_NUM) {
		IMSG("sdm_send_cert: unexpected cert magic 0x%08" PRIx32
		     " (expected 0x%08" PRIx32 ")", magic, SDM_CERT_MAGIC_NUM);
		return false;
	}

	cert_type = cert_rd32(cert, SDM_CERT_OFF_TYPE);

	switch (cert_type) {
	case SDM_CERT_TYPE_CANCEL_SDOS_ROOT:
		IMSG("sdm_send_cert: cert_type=0x%02" PRIx32
		     " cancellation (SDOS / service root key)", cert_type);
		return true;

	case SDM_CERT_TYPE_CANCEL_AES_ROOT:
		IMSG("sdm_send_cert: cert_type=0x%02" PRIx32
		     " cancellation (user AES root key)", cert_type);
		return true;

	case SDM_CERT_TYPE_COUNTER:
		counter_type = cert_rd32(cert, SDM_CERT_OFF_COUNTER) &
			       SDM_CERT_COUNTER_TYPE_MASK;

		if (counter_type == SDM_CERT_COUNTER_KEYID_CANCEL) {
			uint32_t owner = (cert_rd32(cert,
						    SDM_CERT_OFF_COUNTER) >>
					  SDM_CERT_KEY_OWNER_SHIFT) &
					 SDM_CERT_KEY_OWNER_MASK;

			IMSG("sdm_send_cert: cert_type=0x%02" PRIx32
			     " KEY-ID cancel owner=%s id=%" PRIu32,
			     cert_type, owner ? "Intel" : "user",
			     cert_rd32(cert, SDM_CERT_OFF_ID));
			return true;
		}

		if (counter_type == SDM_CERT_COUNTER_ROOT_HASH_CANCEL) {
			IMSG("sdm_send_cert: cert_type=0x%02" PRIx32
			     " cancellation (owner root-hash slot %" PRIu32 ")",
			     cert_type, cert_rd32(cert, SDM_CERT_OFF_ID));
			return true;
		}

		IMSG("sdm_send_cert: cert_type=0x%02" PRIx32
		     " counter update type %" PRIu32 " (not cancel)",
		     cert_type, counter_type);
		return false;

	default:
		IMSG("sdm_send_cert: cert_type=0x%02" PRIx32
		     " is not a key cancellation", cert_type);
		return false;
	}
}

static TEE_Result cmd_sdm_send_cert(uint32_t ptypes,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	TEE_Result res = TEE_SUCCESS;
	const void *cert_buf = NULL;
	size_t cert_size = 0;
	size_t cert_padded = 0;
	size_t total_size = 0;
	uint8_t *bounce = NULL;
	uint32_t phase2_status = SDM_PHASE2_STATUS_SKIPPED;
	paddr_t bounce_phys = 0;
	bool is_cancellation = false;
	int i = 0;

	if (ptypes != exp_types) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cert_buf  = params[0].memref.buffer;
	cert_size = params[0].memref.size;

	if (!cert_buf || cert_size == 0 || cert_size > SDM_CERT_MAX_SIZE) {
		EMSG("bad cert size %zu max %u", cert_size,
		     SDM_CERT_MAX_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* ATF mailbox payload must be 4-byte aligned */
	cert_padded = ROUNDUP(cert_size, 4);
	total_size  = 4 + cert_padded;	 /* 4-byte zero prefix + padded cert */

	bounce = memalign(4, total_size);
	if (!bounce)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(bounce, 0, total_size);
	memmove(bounce + 4, cert_buf, cert_size);

	is_cancellation = cert_is_key_cancellation(bounce + 4, cert_size);

	cache_op_inner(DCACHE_AREA_CLEAN, bounce, total_size);
	bounce_phys = virt_to_phys(bounce);

	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_SEND_CERTIFICATE;
	args.a1 = 0;			/* trans_id */
	args.a2 = (uint64_t)bounce_phys;
	args.a3 = (uint64_t)total_size;
	thread_smccc(&args);
	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("send_cert submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bounce;
	}

	for (i = 0; i < SDM_CRYPT_POLL_MAX; i++) {
		args.a0 = ALTERA_SIP_SMC_ASYNC_RESP_POLL;
		args.a1 = 0;
		thread_smccc(&args);
		if ((uint32_t)args.a0 == INTEL_SIP_SMC_STATUS_OK)
			break;
	}
	if (i == SDM_CRYPT_POLL_MAX) {
		EMSG("SDM cert auth poll timed out");
		res = TEE_ERROR_BUSY;
		goto free_bounce;
	}

	params[1].value.a = (uint32_t)args.a1;
	params[1].value.b = (uint32_t)args.a2;

	if (args.a1 == 0) {
		IMSG("sdm_send_cert: certificate accepted");

		if (is_cancellation) {
			(void)trigger_pubkey_program_phase2_finalize(true,
						&phase2_status);
			IMSG("sdm_send_cert: phase2_status=%u", phase2_status);
		} else {
			IMSG("sdm_send_cert: not key cancel; skip phase-2");
		}
	} else {
		IMSG("sdm_send_cert: certificate rejected mbox_err=0x%" PRIx64
		     " detail=0x%" PRIx64, args.a1, args.a2);
	}

free_bounce:
	memzero_explicit(bounce, total_size);
	free(bounce);
	return res;
}

static TEE_Result cmd_sdm_get_prov_data(uint32_t ptypes,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	paddr_t bounce_phys = 0;
	void *bounce = NULL;
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size < SDM_PROV_DATA_MAX_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	bounce = memalign(4, SDM_PROV_DATA_MAX_SIZE);
	if (!bounce)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(bounce, 0, SDM_PROV_DATA_MAX_SIZE);

	/* Clean TZDRAM before ATF fills provision data */
	cache_op_inner(DCACHE_AREA_CLEAN, bounce, SDM_PROV_DATA_MAX_SIZE);
	bounce_phys = virt_to_phys(bounce);

	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_GET_PROVISION_DATA;
	args.a1 = 0;			/* trans_id */
	args.a2 = (uint64_t)bounce_phys;
	thread_smccc(&args);
	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("get_prov_data submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bounce;
	}

	res = poll_until_done(0, &args);
	if (res != TEE_SUCCESS) {
		EMSG("get_prov_data poll failed");
		goto free_bounce;
	}

	cache_op_inner(DCACHE_AREA_INVALIDATE, bounce, SDM_PROV_DATA_MAX_SIZE);

	/* Response size from cosign_info (word 2) */
	{
		const uint32_t *w = (const uint32_t *)bounce;
		uint32_t hash_count = SDM_PROV_HASH_COUNT(w[2]);
		uint32_t actual_words = 3U +
			hash_count * (SDM_PROV_HASH_WORDS + 1U) + 6U;
		uint32_t actual_size = actual_words * 4U;

		if (actual_size > SDM_PROV_DATA_MAX_SIZE) {
			EMSG("get_prov_data: size %u > max %u (cosign=0x%08x)",
			     actual_size, SDM_PROV_DATA_MAX_SIZE, w[2]);
			res = TEE_ERROR_GENERIC;
			goto free_bounce;
		}

		memmove(params[0].memref.buffer, bounce, actual_size);
		params[0].memref.size = actual_size;
		DMSG("prov_data: %u B (%u hashes)", actual_size,
		     hash_count);
	}

free_bounce:
	memzero_explicit(bounce, SDM_PROV_DATA_MAX_SIZE);
	free(bounce);
	return res;
}

static TEE_Result cmd_sdm_read_user_fuses(uint32_t ptypes,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	uint32_t *cmd_buf = NULL;
	uint8_t *resp_buf = NULL;
	paddr_t cmd_phys = 0;
	paddr_t resp_phys = 0;
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size < SDM_USER_FUSE_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	cmd_buf = memalign(4, SDM_EFUSE_READ_PAYLOAD_SIZE);
	if (!cmd_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	resp_buf = memalign(4, SDM_EFUSE_RESP_BUF_SIZE);
	if (!resp_buf) {
		free(cmd_buf);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	cmd_buf[0] = SDM_EFUSE_READ_CMD_WORD;
	memset(resp_buf, 0, SDM_EFUSE_RESP_BUF_SIZE);

	cache_op_inner(DCACHE_AREA_CLEAN, cmd_buf, SDM_EFUSE_READ_PAYLOAD_SIZE);
	cache_op_inner(DCACHE_AREA_CLEAN, resp_buf, SDM_EFUSE_RESP_BUF_SIZE);

	cmd_phys  = virt_to_phys(cmd_buf);
	resp_phys = virt_to_phys(resp_buf);

	args.a0 = ALTERA_SIP_SMC_ASYNC_GEN_MBOX_CMD;
	args.a1 = 0;
	args.a2 = SDM_EFUSE_READ_CMD;
	args.a3 = (uint64_t)cmd_phys;
	args.a4 = SDM_EFUSE_READ_PAYLOAD_SIZE;
	args.a5 = (uint64_t)resp_phys;
	args.a6 = SDM_EFUSE_RESP_BUF_SIZE;
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("read_user_fuses submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bufs;
	}

	res = poll_until_done(0, &args);
	if (res != TEE_SUCCESS) {
		EMSG("read_user_fuses poll failed");
		goto free_bufs;
	}

	cache_op_inner(DCACHE_AREA_INVALIDATE, resp_buf,
		       SDM_EFUSE_RESP_BUF_SIZE);

	memmove(params[0].memref.buffer, resp_buf, SDM_USER_FUSE_SIZE);
	params[0].memref.size = SDM_USER_FUSE_SIZE;

	DMSG("read_user_fuses: %u bytes returned", SDM_USER_FUSE_SIZE);

free_bufs:
	memzero_explicit(cmd_buf, SDM_EFUSE_READ_PAYLOAD_SIZE);
	memzero_explicit(resp_buf, SDM_EFUSE_RESP_BUF_SIZE);
	free(cmd_buf);
	free(resp_buf);
	return res;
}

static TEE_Result cmd_sdm_prog_user_fuses(uint32_t ptypes,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	uint32_t *cmd_buf = NULL;
	uint8_t *resp_buf = NULL;
	paddr_t cmd_phys = 0;
	paddr_t resp_phys = 0;
	uint32_t host_flags = 0;
	uint32_t ctrl_word = 0;
	bool non_volatile = false;
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes) {
		EMSG("prog_user_fuses: bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < SDM_USER_FUSE_SIZE) {
		EMSG("prog_user_fuses: input size %zu < %u",
		     params[0].memref.size, SDM_USER_FUSE_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].value.b != 0) {
		EMSG("prog_user_fuses: reserved .b != 0 (0x%" PRIx32 ")",
		     params[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	host_flags = params[1].value.a;
	non_volatile = (host_flags &
			SDM_USER_FUSES_HOST_FLAG_NON_VOLATILE) != 0;

	cmd_buf = memalign(4, SDM_EFUSE_PROG_PAYLOAD_SIZE);
	if (!cmd_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	resp_buf = memalign(4, SDM_EFUSE_RESP_BUF_SIZE);
	if (!resp_buf) {
		free(cmd_buf);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Default T=1 (test); NON_VOLATILE clears T for permanent burn */
	if (non_volatile) {
		ctrl_word = SDM_EFUSE_PROG_CTRL_WORD_BURN;
		EMSG("prog_user_fuses: NON_VOLATILE burn T=0 ctrl=0x%08"
		     PRIx32, ctrl_word);
	} else {
		ctrl_word = SDM_EFUSE_PROG_CTRL_WORD;
	}

	cmd_buf[0] = SDM_EFUSE_PROG_MAGIC;
	cmd_buf[1] = ctrl_word;
	memmove(&cmd_buf[2], params[0].memref.buffer, SDM_USER_FUSE_SIZE);

	memset(resp_buf, 0, SDM_EFUSE_RESP_BUF_SIZE);

	cache_op_inner(DCACHE_AREA_CLEAN, cmd_buf, SDM_EFUSE_PROG_PAYLOAD_SIZE);
	cache_op_inner(DCACHE_AREA_CLEAN, resp_buf, SDM_EFUSE_RESP_BUF_SIZE);

	cmd_phys  = virt_to_phys(cmd_buf);
	resp_phys = virt_to_phys(resp_buf);

	args.a0 = ALTERA_SIP_SMC_ASYNC_GEN_MBOX_CMD;
	args.a1 = 0;
	args.a2 = SDM_EFUSE_PROG_CMD;
	args.a3 = (uint64_t)cmd_phys;
	args.a4 = SDM_EFUSE_PROG_PAYLOAD_SIZE;
	args.a5 = (uint64_t)resp_phys;
	args.a6 = SDM_EFUSE_RESP_BUF_SIZE;
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("prog_user_fuses submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bufs;
	}

	res = poll_until_done(0, &args);
	if (res != TEE_SUCCESS) {
		EMSG("prog_user_fuses poll failed (mode=%s)",
		     non_volatile ? "NON-VOLATILE / eFuse burn"
				  : "test / cache-only");
		goto free_bufs;
	}

	DMSG("prog_user_fuses: completed successfully (%s)",
	     non_volatile ? "NON-VOLATILE / eFuse burned"
			  : "test / cache-only");

free_bufs:
	memzero_explicit(cmd_buf, SDM_EFUSE_PROG_PAYLOAD_SIZE);
	memzero_explicit(resp_buf, SDM_EFUSE_RESP_BUF_SIZE);
	free(cmd_buf);
	free(resp_buf);
	return res;
}

static TEE_Result cmd_sdm_prog_pubkey(uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT);
	struct thread_smc_args args = { };
	const void *hash_buf = NULL;
	size_t hash_size = 0;
	uint8_t *bounce = NULL;
	paddr_t bounce_phys = 0;
	uint32_t host_flags = 0;
	uint32_t flags = 0;
	uint32_t hash_type = 0;
	size_t payload_size = 0;
	size_t payload_words = 0;
	size_t num_hashes = 0;
	size_t submitted = 0;
	bool non_volatile = false;
	uint32_t phase2_status = SDM_PHASE2_STATUS_SKIPPED;
	TEE_Result res = TEE_SUCCESS;
	int i = 0;

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hash_buf  = params[0].memref.buffer;
	hash_size = params[0].memref.size;

	if (!hash_buf) {
		EMSG("hash buffer is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (hash_size == SDM_PUBKEY_HASH_SIZE_SHA256) {
		hash_type    = SDM_PUBKEY_HASH_TYPE_SECP256R1;
		num_hashes   = 1;
		payload_size = SDM_PUBKEY_HASH_OFFSET + hash_size;
	} else if (hash_size != 0 &&
		   (hash_size % SDM_PUBKEY_HASH_SIZE_SHA384) == 0 &&
		   (hash_size / SDM_PUBKEY_HASH_SIZE_SHA384) <=
			SDM_PUBKEY_MAX_HASHES_PER_CALL) {
		hash_type    = SDM_PUBKEY_HASH_TYPE_SECP384R1;
		num_hashes   = hash_size / SDM_PUBKEY_HASH_SIZE_SHA384;
		payload_size = SDM_PUBKEY_HASH_OFFSET + hash_size;
	} else {
		EMSG("invalid hash size %zu (want %u or N*%u, N<=%u)",
		     hash_size, SDM_PUBKEY_HASH_SIZE_SHA256,
		     SDM_PUBKEY_HASH_SIZE_SHA384,
		     SDM_PUBKEY_MAX_HASHES_PER_CALL);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	host_flags = params[1].value.a;

	/* Reject unknown host flag bits */
	if (host_flags & ~SDM_PUBKEY_HOST_FLAGS_VALID_MASK) {
		EMSG("unknown host flag bits 0x%08" PRIx32, host_flags);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	non_volatile = (host_flags & SDM_PUBKEY_HOST_FLAG_NON_VOLATILE) != 0;

	bounce = memalign(4, payload_size);
	if (!bounce)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(bounce, 0, payload_size);
	memmove(bounce + SDM_PUBKEY_HASH_OFFSET, hash_buf, hash_size);

	cache_op_inner(DCACHE_AREA_CLEAN, bounce, payload_size);
	bounce_phys = virt_to_phys(bounce);

	flags = hash_type | SDM_PUBKEY_FLAG_KEY_COUNT(num_hashes);
	if (non_volatile)
		EMSG("program_pubkey: NON_VOLATILE burn type=%u count=%zu",
		     hash_type, num_hashes);
	else
		flags |= SDM_PUBKEY_FLAG_TEST;

	payload_words = payload_size / SDM_PUBKEY_WORD_BYTES;

	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_PROGRAM_OWNER_PUBKEY;
	args.a1 = 0; /* request header / trans_id */
	args.a2 = (uint64_t)flags;
	args.a3 = (uint64_t)bounce_phys;
	args.a4 = (uint64_t)payload_words;

	{
		const uint32_t *w = (const uint32_t *)(uintptr_t)bounce;
		const unsigned int n_words = (unsigned int)payload_words;
		unsigned int j = 0;

		IMSG("program_pubkey: payload buffer @ phys 0x%016" PRIx64
		     " (%u words, %zu hash%s)",
		     (uint64_t)bounce_phys, n_words, num_hashes,
		     num_hashes == 1 ? "" : "es");
		for (j = 0; j < n_words; j++)
			IMSG("	  word[%2u] = 0x%08" PRIx32 "  %s",
			     j, w[j],
			     j < 2U ? "(header)" : "(hash)");
	}

	IMSG("program_pubkey: SMC SUBMIT to ATF (mode=%s)",
	     non_volatile ? "NON_VOLATILE / eFuse burn" : "test/cache-only");
	IMSG("  a0 = 0x%016" PRIx64 "  (FCS_PROGRAM_OWNER_PUBKEY)", args.a0);
	IMSG("  a1 = 0x%016" PRIx64 "  (request header / trans_id)", args.a1);
	IMSG("  a2 = 0x%016" PRIx64 "  (flags: T=%u S=0 keycnt=0x%02" PRIx32
	     " [%zu key%s] hash_type=%" PRIu32 ")",
	     args.a2, (flags & SDM_PUBKEY_FLAG_TEST) ? 1U : 0U,
	     (flags & SDM_PUBKEY_FLAG_KEY_COUNT_MASK) >>
		     SDM_PUBKEY_FLAG_KEY_COUNT_SHIFT,
	     num_hashes, num_hashes == 1 ? "" : "s", hash_type);
	IMSG("  a3 = 0x%016" PRIx64 "  (payload phys addr)", args.a3);
	IMSG("  a4=0x%016" PRIx64 " (%zu words, %zu bytes)",
	     args.a4, payload_words, payload_size);

	thread_smccc(&args);

	IMSG("program_pubkey: SMC SUBMIT response from ATF");
	IMSG("  a0 = 0x%016" PRIx64 "  (%s)", args.a0,
	     args.a0 == INTEL_SIP_SMC_STATUS_OK ? "STATUS_OK / queued"
						: "submit rejected");
	IMSG("  a1 = 0x%016" PRIx64, args.a1);
	IMSG("  a2 = 0x%016" PRIx64, args.a2);
	IMSG("  a3 = 0x%016" PRIx64, args.a3);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("program_pubkey submit failed: 0x%" PRIx64, args.a0);
		res = TEE_ERROR_GENERIC;
		goto free_bounce;
	}

	for (i = 0; i < SDM_CRYPT_POLL_MAX; i++) {
		args.a0 = ALTERA_SIP_SMC_ASYNC_RESP_POLL;
		args.a1 = 0;
		thread_smccc(&args);
		if ((uint32_t)args.a0 == INTEL_SIP_SMC_STATUS_OK)
			break;
	}

	IMSG("program_pubkey: SMC POLL response from ATF (after %d iters)", i);
	IMSG("  a0 = 0x%016" PRIx64 "  (poll status, 0=OK)", args.a0);
	IMSG("  a1 = 0x%016" PRIx64 "  (SDM err_code -> host param[2].value.a)",
	     args.a1);
	IMSG("  a2=0x%016" PRIx64 " (echoed flags)",
	     args.a2);
	IMSG("  a3 = 0x%016" PRIx64 "  (echoed x3 payload addr)", args.a3);

	if (i == SDM_CRYPT_POLL_MAX) {
		EMSG("SDM program_pubkey poll timed out");
		res = TEE_ERROR_BUSY;
		goto free_bounce;
	}

	params[2].value.a = (uint32_t)args.a1;	/* SDM err_code */
	params[2].value.b = (uint32_t)args.a2;	/* echoed flags word */

	if (args.a1 == 0) {
		DMSG("program_pubkey: SDM accepted %zu hash%s (%s)",
		     num_hashes, num_hashes == 1 ? "" : "es",
		     non_volatile ? "NON_VOLATILE / eFuse burned"
				  : "test / cache-only");

		(void)trigger_pubkey_program_phase2_finalize(non_volatile,
							    &phase2_status);
		submitted = num_hashes;
	} else {
		EMSG("program_pubkey: reject %zu hash%s (%zu words) err=0x%"
		     PRIx64,
		     num_hashes, num_hashes == 1 ? "" : "es",
		     payload_words, args.a1);
		}

free_bounce:
	memzero_explicit(bounce, payload_size);
	free(bounce);
	params[3].value.a = phase2_status;
	params[3].value.b = (uint32_t)submitted;
	return res;
}

static TEE_Result
cmd_sdm_efuse_reload_cache(uint32_t ptypes,
			   TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	args.a0 = ALTERA_SIP_SMC_ASYNC_SDM_EFUSE_RELOAD_CACHE;
	args.a1 = 0;	/* trans_id */
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("efuse_reload_cache submit failed: a0=0x%" PRIx64,
		     args.a0);
		return TEE_ERROR_GENERIC;
	}

	res = poll_until_done(0, NULL);
	if (res != TEE_SUCCESS)
		return res;

	DMSG("efuse_reload_cache: SDM accepted reload");
	return TEE_SUCCESS;
}

static TEE_Result cmd_sdm_security_op(uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	uint32_t caller_opt = 0;
	uint32_t opt = 0;
	uint32_t host_flags = 0;
	bool non_volatile = false;
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.b != 0 || params[1].value.b != 0) {
		EMSG("security_op: reserved .b must be 0 (got 0x%" PRIx32
		     ", 0x%" PRIx32 ")",
		     params[0].value.b, params[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	host_flags = params[1].value.a;
	if (host_flags & ~SDM_SECOPT_HOST_FLAGS_VALID_MASK) {
		EMSG("security_op: unknown host flag bits 0x%08" PRIx32,
		     host_flags);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	non_volatile = (host_flags & SDM_SECOPT_HOST_FLAG_NON_VOLATILE) != 0;

	caller_opt = params[0].value.a;
	/* TEST_MODE comes only from host_flags inside the PTA */
	opt = caller_opt & ~SDM_SECOPT_TEST_MODE;
	if (!non_volatile) {
		opt |= SDM_SECOPT_TEST_MODE;
	} else {
		EMSG("security_op: NON_VOLATILE burn T=0 opt=0x%08" PRIx32,
		     caller_opt);
	}

	DMSG("security_op: opt=0x%08" PRIx32 " eff=0x%08" PRIx32 " %s",
	     caller_opt, opt,
	     non_volatile ? "NON-VOLATILE (eFuse burn)" : "test/cache-only");

	args.a0 = ALTERA_SIP_SMC_ASYNC_FCS_EFUSE_USER_SECURITY_OPTION;
	args.a1 = 0;			/* trans_id */
	args.a2 = (uint64_t)opt; /* SDM mailbox 32-bit word */
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("security_op submit failed: a0=0x%" PRIx64, args.a0);
		return TEE_ERROR_GENERIC;
	}

	res = poll_until_done(0, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("security_op: SDM rejected option_word=0x%08" PRIx32, opt);
		return res;
	}

	DMSG("security_op: SDM accepted option_word=0x%08" PRIx32, opt);
	return TEE_SUCCESS;
}

static TEE_Result cmd_sdm_disable_owned_entry(uint32_t ptypes,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	uint32_t host_flags = 0;
	bool non_volatile = false;
	uint32_t mode_word = 0;
	uint32_t phase2_status = SDM_PHASE2_STATUS_SKIPPED;
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.b != 0) {
		EMSG("disable_owned: reserved .b != 0 (0x%" PRIx32 ")",
		     params[0].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	host_flags = params[0].value.a;
	if (host_flags & ~SDM_DEO_HOST_FLAGS_VALID_MASK) {
		EMSG("disable_owned_entry: unknown host flag bits 0x%08" PRIx32,
		     host_flags);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	non_volatile = (host_flags & SDM_DEO_HOST_FLAG_NON_VOLATILE) != 0;

	mode_word = ((non_volatile ? 0ULL : 1ULL) << 31);

	if (non_volatile)
		EMSG("disable_owned: NON_VOLATILE permanent lock");

	DMSG("disable_owned_entry: mode=%s (x2=0x%08" PRIx32 ")",
	     non_volatile ? "physical/NON-VOLATILE" : "virtual/cache-only",
	     mode_word);

	args.a0 = ALTERA_SIP_SMC_ASYNC_SECURE_DISABLE_ENTRY_TO_OWNED;
	args.a1 = 0;		/* request header / trans_id */
	args.a2 = (uint64_t)mode_word;
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("disable_owned_entry submit failed: a0=0x%" PRIx64,
		     args.a0);
		params[1].value.a = phase2_status;	/* SKIPPED */
		params[1].value.b = 0;
		return TEE_ERROR_GENERIC;
	}

	res = poll_until_done(0, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("disable_owned_entry: SDM rejected (mode=%s)",
		     non_volatile ? "physical" : "virtual");
		params[1].value.a = phase2_status;	/* SKIPPED */
		params[1].value.b = 0;
		return res;
	}

	DMSG("disable_owned_entry: SDM accepted (mode=%s)",
	     non_volatile ? "physical/NON-VOLATILE" : "virtual/cache-only");

	/* Phase-2 finalize (NON_VOLATILE Soft-POR; virtual fuse is NOP) */
	(void)trigger_pubkey_program_phase2_finalize(non_volatile,
						    &phase2_status);

	params[1].value.a = phase2_status;
	params[1].value.b = 0;
	return TEE_SUCCESS;
}

static TEE_Result
cmd_sdm_efuse_write_disable(uint32_t ptypes,
			    TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct thread_smc_args args = { };
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	args.a0 = ALTERA_SIP_SMC_ASYNC_SECURE_EFUSE_WRITE_DISABLE;
	args.a1 = 0;	/* request header / trans_id */
	thread_smccc(&args);

	if (args.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("efuse_write_disable submit failed: a0=0x%" PRIx64,
		     args.a0);
		return TEE_ERROR_GENERIC;
	}

	res = poll_until_done(0, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("efuse_write_disable: SDM rejected request");
		return res;
	}

	DMSG("efuse_write_disable: SDM accepted (eFuse writes now disabled)");
	return TEE_SUCCESS;
}

static TEE_Result send_ns_allowed_list_clear(void)
{
	struct thread_smc_args args = { };

	args.a0 = ALTERA_SIP_SMC_NS_ALLOWED_LIST_CLEAR;
	thread_smccc(&args);

	switch ((uint32_t)args.a0) {
	case INTEL_SIP_SMC_NS_LIST_STATUS_OK:
		DMSG("ns_allowed_list_clear: SDM accepted");
		return TEE_SUCCESS;
	case INTEL_SIP_SMC_NS_LIST_STATUS_BUSY:
		EMSG("ns_allowed_list_clear: busy/not allowed (status=2)");
		return TEE_ERROR_BUSY;
	default:
		EMSG("ns_allowed_list_clear: unexpected status 0x%" PRIx64,
		     args.a0);
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result send_ns_allowed_list_add(uint32_t sip_smc_id)
{
	struct thread_smc_args args = { };

	args.a0 = ALTERA_SIP_SMC_NS_ALLOWED_LIST_ADD;
	args.a1 = sip_smc_id;
	thread_smccc(&args);

	switch ((uint32_t)args.a0) {
	case INTEL_SIP_SMC_NS_LIST_STATUS_OK:
		DMSG("ns_list_add FID 0x%08" PRIx32 ": accepted",
		     sip_smc_id);
		return TEE_SUCCESS;
	case INTEL_SIP_SMC_NS_LIST_STATUS_BUSY:
		EMSG("ns_list_add FID 0x%08" PRIx32 ": busy (status=2)",
		     sip_smc_id);
		return TEE_ERROR_BUSY;
	default:
		EMSG("ns_list_add FID 0x%08" PRIx32 ": status 0x%" PRIx64,
		     sip_smc_id, args.a0);
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result send_ns_allowed_list_remove(uint32_t sip_smc_id)
{
	struct thread_smc_args args = { };

	args.a0 = ALTERA_SIP_SMC_NS_ALLOWED_LIST_REMOVE;
	args.a1 = sip_smc_id;
	thread_smccc(&args);

	switch ((uint32_t)args.a0) {
	case INTEL_SIP_SMC_NS_LIST_STATUS_OK:
		DMSG("ns_list_remove FID 0x%08" PRIx32 ": accepted",
		     sip_smc_id);
		return TEE_SUCCESS;
	case INTEL_SIP_SMC_NS_LIST_STATUS_BUSY:
		EMSG("ns_list_remove FID 0x%08" PRIx32 ": busy (status=2)",
		     sip_smc_id);
		return TEE_ERROR_BUSY;
	default:
		EMSG("ns_list_remove FID 0x%08" PRIx32 ": status 0x%" PRIx64,
		     sip_smc_id, args.a0);
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result
cmd_sdm_ns_allowed_list_remove(uint32_t ptypes,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.b != 0) {
		EMSG("ns_list_remove: reserved .b != 0 (0x%" PRIx32 ")",
		     params[0].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return send_ns_allowed_list_remove(params[0].value.a);
}

static TEE_Result send_ns_allowed_list_deactivate(void)
{
	struct thread_smc_args args = { };

	args.a0 = ALTERA_SIP_SMC_NS_ALLOWED_LIST_DEACTIVATE;
	thread_smccc(&args);

	switch ((uint32_t)args.a0) {
	case INTEL_SIP_SMC_NS_LIST_STATUS_OK:
		DMSG("ns_allowed_list_deactivate: SDM accepted");
		return TEE_SUCCESS;
	case INTEL_SIP_SMC_NS_LIST_STATUS_BUSY:
		EMSG("ns_list_deactivate: busy/not allowed (status=2)");
		return TEE_ERROR_BUSY;
	default:
		EMSG("ns_allowed_list_deactivate: unexpected status 0x%" PRIx64,
		     args.a0);
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result
cmd_sdm_ns_allowed_list_deactivate(uint32_t ptypes,
				   TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_ptypes =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (ptypes != exp_ptypes) {
		EMSG("bad param types 0x%" PRIx32, ptypes);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return send_ns_allowed_list_deactivate();
}

static const uint32_t sdm_ns_allowed_list_default[] =
	SDM_NS_ALLOWED_LIST_DEFAULT;

static TEE_Result sdm_ns_allowed_list_boot_init(void)
{
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	res = send_ns_allowed_list_clear();
	if (res != TEE_SUCCESS) {
		EMSG("boot: NS allow-list clear failed (0x%" PRIx32 ")", res);
		return res;
	}

	for (i = 0; i < ARRAY_SIZE(sdm_ns_allowed_list_default); i++) {
		res = send_ns_allowed_list_add(sdm_ns_allowed_list_default[i]);
		if (res != TEE_SUCCESS) {
			EMSG("boot: NS allow-list add[%zu] cmd=0x%" PRIx32
			     " failed (0x%" PRIx32 ")",
			     i, sdm_ns_allowed_list_default[i], res);
			return res;
		}
	}

	IMSG("SDM NS allow-list ready (%zu entries)",
	     ARRAY_SIZE(sdm_ns_allowed_list_default));
	return TEE_SUCCESS;
}

boot_final(sdm_ns_allowed_list_boot_init);

static TEE_Result sdm_remap_boot_init(void)
{
	struct thread_smc_args smc = { };

	smc.a0 = INTEL_SIP_SMC_REG_WRITE;
	smc.a1 = SDM_BE_AWADDR_REMAP_REG;
	smc.a2 = SDM_REMAP_DRAM_BASE;
	thread_smccc(&smc);

	if (smc.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("boot: AWADDR_REMAP write fail 0x%" PRIx64, smc.a0);
		return TEE_ERROR_GENERIC;
	}

	memset(&smc, 0, sizeof(smc));
	smc.a0 = INTEL_SIP_SMC_REG_WRITE;
	smc.a1 = SDM_BE_ARADDR_REMAP_REG;
	smc.a2 = SDM_REMAP_DRAM_BASE;
	thread_smccc(&smc);

	if (smc.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("boot: ARADDR_REMAP write fail 0x%" PRIx64, smc.a0);
		return TEE_ERROR_GENERIC;
	}

	memset(&smc, 0, sizeof(smc));
	smc.a0 = INTEL_SIP_SMC_REG_WRITE;
	smc.a1 = SDM_STREAM_CTRL_REG;
	smc.a2 = SDM_STREAM_SECURE;
	thread_smccc(&smc);

	if (smc.a0 != INTEL_SIP_SMC_STATUS_OK) {
		EMSG("boot: STREAM_CTRL write fail 0x%" PRIx64, smc.a0);
		return TEE_ERROR_GENERIC;
	}

	IMSG("SDM remapper claimed: ARADDR/AWADDR=0x%08x STREAM_CTRL=0x%02x",
	     SDM_REMAP_DRAM_BASE, SDM_STREAM_SECURE);
	return TEE_SUCCESS;
}

boot_final(sdm_remap_boot_init);

static TEE_Result invoke_command(void *session __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_GET_VERSION:
		return get_version(ptypes, params);
	case PTA_CMD_SDM_GET_ID_CODE:
		return get_id_code(ptypes, params);
	case PTA_CMD_SDM_GET_CHIP_ID:
		return get_chip_id(ptypes, params);
	case PTA_CMD_SDM_SDOS_CRYPT:
		return cmd_sdm_sdos_crypt(ptypes, params);
	case PTA_CMD_SDM_GET_RANDOM:
		return cmd_sdm_get_random(ptypes, params);
	case PTA_CMD_SDM_SEND_CERT:
		return cmd_sdm_send_cert(ptypes, params);
	case PTA_CMD_SDM_GET_PROV_DATA:
		return cmd_sdm_get_prov_data(ptypes, params);
	case PTA_CMD_SDM_READ_USER_FUSES:
		return cmd_sdm_read_user_fuses(ptypes, params);
	case PTA_CMD_SDM_PROG_USER_FUSES:
		return cmd_sdm_prog_user_fuses(ptypes, params);
	case PTA_CMD_SDM_PROG_PUBKEY:
		return cmd_sdm_prog_pubkey(ptypes, params);
	case PTA_CMD_SDM_EFUSE_RELOAD_CACHE:
		return cmd_sdm_efuse_reload_cache(ptypes, params);
	case PTA_CMD_SDM_SECURITY_OP:
		return cmd_sdm_security_op(ptypes, params);
	case PTA_CMD_SDM_DISABLE_OWNED_ENTRY:
		return cmd_sdm_disable_owned_entry(ptypes, params);
	case PTA_CMD_SDM_EFUSE_WRITE_DISABLE:
		return cmd_sdm_efuse_write_disable(ptypes, params);
	case PTA_CMD_SDM_NS_ALLOWED_LIST_DEACTIVATE:
		return cmd_sdm_ns_allowed_list_deactivate(ptypes, params);
	case PTA_CMD_SDM_NS_ALLOWED_LIST_REMOVE:
		return cmd_sdm_ns_allowed_list_remove(ptypes, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

pseudo_ta_register(.uuid = PTA_SDM_SVC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
