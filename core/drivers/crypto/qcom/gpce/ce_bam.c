// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * BAM transport for the Qualcomm Crypto Engine.
 */

#include <assert.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <tee_api_defines.h>
#include <trace.h>

#include "bam.h"
#include "ce_bam.h"
#include "hash.h"

#include <gpce_hwio.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, QCOM_GPCE_REG_BASE,
			QCOM_GPCE_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, QCOM_GPCE_BAM_REG_BASE,
			QCOM_GPCE_BAM_REG_SIZE);

/*
 * GPCE BAM configuration.
 *
 * Firmware assigns this TX/RX pipe pair to the secure execution environment.
 * Linux QCE must use a different pipe set. Keep these values synchronized with
 * firmware ownership configuration and the Linux DTS.
 */
#define QCE_BAM_PIPE_SET		U(0)
#define QCE_BAM_TX_PIPE		(QCE_BAM_PIPE_SET * U(2))
#define QCE_BAM_RX_PIPE		(QCE_BAM_TX_PIPE + U(1))
#define QCE_BAM_EE			U(2)
#define QCE_BAM_CMD_DESC_COUNT		U(32)
#define QCE_BAM_RESULT_SIZE		U(128)
#define QCE_BAM_MAX_DATA_DESCS		\
	((BAM_DESC_FIFO_SIZE / BAM_DESC_ENTRY_SIZE) - U(6))

#define QUEUE_TX_PIPE_XFER	true
#define QUEUE_RX_PIPE_XFER	false
#define LAST_PIPE_XFER_REQ	true
#define NEXT_PIPE_XFER_REQ	false

/*
 * struct bam_ce - Crypto Engine command descriptor
 * @reg_addr: Low 24 bits of the Crypto Engine register address
 * @command: Command opcode for the register operation
 * @data: Value written by the command
 * @mask: Bit mask applied by the command
 * @reserved: Must be zero
 */
struct bam_ce {
	uint32_t reg_addr : 24;
	uint32_t command : 8;
	uint32_t data;
	uint32_t mask;
	uint32_t reserved;
};

static_assert(sizeof(struct bam_ce) == U(16));

/*
 * struct ce_bam_result - CE result-dump buffer written through the RX pipe
 * @auth_iv: SHA authentication IV words after the transfer
 * @auth_byte_cnt: SHA authentication byte-count words after the transfer
 * @reserved: Remaining hardware result-dump fields unused by SHA-256
 */
struct ce_bam_result {
	uint32_t auth_iv[QCE_MAX_AUTH_IV_COUNT];
	uint32_t auth_byte_cnt[QCE_MAX_AUTH_BYTE_COUNT];
	uint32_t reserved[12];
};

static_assert(sizeof(struct ce_bam_result) == QCE_BAM_RESULT_SIZE);

/*
 * struct ce_bam_ctx - GPCE BAM resources shared by all SHA transfers
 * @tx_pipe_handle: BAM pipe used to submit CE commands and input data
 * @rx_pipe_handle: BAM pipe used to receive the CE result dump
 * @tx_desc: Transmit-pipe descriptor FIFO allocation
 * @rx_desc: Receive-pipe descriptor FIFO allocation
 * @cmd_desc: CE command descriptors submitted on the TX pipe
 * @result: CE result-dump buffer received on the RX pipe
 * @cmd_desc_pa: Physical address of @cmd_desc
 * @result_pa: Physical address of @result
 * @cmd_count: Number of populated entries in @cmd_desc
 */
struct ce_bam_ctx {
	struct bam_pipe_state *tx_pipe_handle;
	struct bam_pipe_state *rx_pipe_handle;
	uint8_t *tx_desc;
	uint8_t *rx_desc;
	struct bam_ce *cmd_desc;
	struct ce_bam_result *result;
	paddr_t cmd_desc_pa;
	paddr_t result_pa;
	size_t cmd_count;
};

static struct ce_bam_ctx *ce_bam_state;
static vaddr_t ce_base;
static vaddr_t ce_bam_base;

TEE_Result ce_bam_init(void)
{
	struct bam_config config = { };
	TEE_Result ret = TEE_SUCCESS;

	ce_base = (vaddr_t)phys_to_virt(QCOM_GPCE_REG_BASE, MEM_AREA_IO_SEC,
					  QCOM_GPCE_REG_SIZE);
	if (!ce_base) {
		EMSG("GPCE BAM: failed to map Crypto Engine registers");
		return TEE_ERROR_GENERIC;
	}
	ce_bam_base =
		(vaddr_t)phys_to_virt(QCOM_GPCE_BAM_REG_BASE, MEM_AREA_IO_SEC,
					 QCOM_GPCE_BAM_REG_SIZE);
	if (!ce_bam_base) {
		EMSG("GPCE BAM: failed to map BAM registers");
		return TEE_ERROR_GENERIC;
	}
	config.base = ce_bam_base;
	config.pa = QCOM_GPCE_BAM_REG_BASE;
	config.ee = QCE_BAM_EE;
	ret = bam_init(&config);
	if (ret)
		ce_bam_base = 0;
	return ret;
}

static TEE_Result ce_bam_pipe_init(struct ce_sha_ctx *sha_ctx)
{
	struct ce_bam_ctx *bam_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	if (!sha_ctx || !ce_base || !sha_ctx->ce_ctx)
		return TEE_ERROR_BAD_STATE;
	if (ce_bam_state)
		return TEE_SUCCESS;
	bam_ctx = calloc(1, sizeof(*bam_ctx));
	if (!bam_ctx) {
		EMSG("GPCE BAM: context allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	bam_ctx->tx_desc = memalign(BAM_DESC_ENTRY_SIZE, BAM_DESC_FIFO_SIZE);
	bam_ctx->rx_desc = memalign(BAM_DESC_ENTRY_SIZE, BAM_DESC_FIFO_SIZE);
	bam_ctx->cmd_desc =
		memalign(BAM_DESC_ENTRY_SIZE,
			 QCE_BAM_CMD_DESC_COUNT * sizeof(*bam_ctx->cmd_desc));
	bam_ctx->result =
		memalign(QCE_BAM_RESULT_SIZE, sizeof(*bam_ctx->result));
	if (!bam_ctx->tx_desc || !bam_ctx->rx_desc || !bam_ctx->cmd_desc ||
	    !bam_ctx->result) {
		EMSG("GPCE BAM: descriptor allocation failed");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	memset(bam_ctx->cmd_desc, 0,
	       QCE_BAM_CMD_DESC_COUNT * sizeof(*bam_ctx->cmd_desc));
	memset(bam_ctx->result, 0, sizeof(*bam_ctx->result));
	{
		paddr_t tx_desc_pa = virt_to_phys(bam_ctx->tx_desc);
		paddr_t rx_desc_pa = virt_to_phys(bam_ctx->rx_desc);
		struct bam_pipe_config tx_config = {
			.pipe_num = QCE_BAM_TX_PIPE,
			.is_consumer = false,
			.desc_base_va = bam_ctx->tx_desc,
			.desc_base_pa = tx_desc_pa,
		};
		struct bam_pipe_config rx_config = {
			.pipe_num = QCE_BAM_RX_PIPE,
			.is_consumer = true,
			.desc_base_va = bam_ctx->rx_desc,
			.desc_base_pa = rx_desc_pa,
		};

		bam_ctx->tx_pipe_handle = bam_pipe_init(&tx_config);
		bam_ctx->rx_pipe_handle = bam_pipe_init(&rx_config);
	}
	bam_ctx->cmd_desc_pa = virt_to_phys(bam_ctx->cmd_desc);
	bam_ctx->result_pa = virt_to_phys(bam_ctx->result);
	if (!bam_ctx->tx_pipe_handle || !bam_ctx->rx_pipe_handle ||
	    !bam_ctx->cmd_desc_pa || !bam_ctx->result_pa) {
		EMSG("GPCE BAM: descriptor initialization failed");
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}

	ce_bam_state = bam_ctx;
	return TEE_SUCCESS;

err:
	free_wipe(bam_ctx->tx_desc);
	free_wipe(bam_ctx->rx_desc);
	free_wipe(bam_ctx->cmd_desc);
	free_wipe(bam_ctx->result);
	free_wipe(bam_ctx);
	return ret;
}

/*
 * BAM command elements encode a 24-bit register address relative to the
 * CRYPTO_TOP base. CE register offsets are relative to the CE base.
 */
static TEE_Result ce_bam_add_cmd(uint32_t reg_offset, uint32_t value)
{
	struct ce_bam_ctx *bam_ctx = ce_bam_state;
	struct bam_ce *entry = NULL;
	uint32_t reg_addr = 0;

	if (!bam_ctx || bam_ctx->cmd_count >= QCE_BAM_CMD_DESC_COUNT)
		return TEE_ERROR_BAD_STATE;
	if (reg_offset >= QCOM_GPCE_REG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	reg_addr = QCOM_GPCE_REG_BASE + reg_offset - QCOM_GPCE_TOP_REG_BASE;
	if (reg_addr > UINT32_C(0xffffff))
		return TEE_ERROR_BAD_PARAMETERS;

	entry = &bam_ctx->cmd_desc[bam_ctx->cmd_count++];
	entry->reg_addr = reg_addr;
	entry->command = 0;
	entry->data = value;
	entry->mask = UINT32_MAX;
	entry->reserved = 0;
	return TEE_SUCCESS;
}

static void ce_bam_clear_cmds(struct ce_bam_ctx *bam_ctx)
{
	bam_ctx->cmd_count = 0;
}

static TEE_Result ce_bam_pipe_transfer(struct ce_bam_ctx *bam_ctx,
				       bool is_tx_pipe, paddr_t pa, size_t size,
				       uint16_t flags)
{
	struct bam_pipe_state *pipe = NULL;

	pipe = is_tx_pipe ? bam_ctx->tx_pipe_handle : bam_ctx->rx_pipe_handle;
	return bam_pipe_transfer(pipe, pa, size, flags);
}

static TEE_Result ce_bam_poll(struct bam_pipe_state *pipe)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t count = 0;

	if (!pipe)
		return TEE_ERROR_BAD_PARAMETERS;

	/* TODO: Scale the polling timeout with the queued transfer size. */
	for (count = 0; count < BAM_POLL_MAX; count++) {
		ret = bam_pipe_poll(pipe);
		if (ret == TEE_SUCCESS)
			return TEE_SUCCESS;
		if (ret != TEE_ERROR_BUSY) {
			EMSG("GPCE BAM: pipe poll failed");
			return ret;
		}
	}

	EMSG("GPCE BAM: pipe completion timeout");
	return TEE_ERROR_TIMEOUT;
}

static TEE_Result ce_bam_set_common_ctx(struct ce_sha_ctx *sha_ctx,
					size_t seg_sz)
{
	TEE_Result ret = TEE_SUCCESS;
	/*
	 * Configure polling mode for the secure BAM pipe set. Interrupts are
	 * masked because completion is polled, while the active-low high-speed
	 * disable bit remains clear. REQ_SIZE selects eight 8-byte beats.
	 * Byte order follows the CE context below.
	 */
	uint32_t config = CE_CONFIG_MASK_OP_DONE_INTR_MASK |
			  CE_CONFIG_MASK_DIN_INTR_MASK |
			  CE_CONFIG_MASK_DOUT_INTR_MASK |
			  CE_CONFIG_REQ_SIZE_MASK |
			  (QCE_BAM_PIPE_SET << CE_CONFIG_PIPE_SET_SELECT_SHIFT);

	if (!sha_ctx || !sha_ctx->ce_ctx)
		return TEE_ERROR_BAD_STATE;
	ret = ce_bam_add_cmd(CE_STATUS4_ADDR(0), 0);
	if (ret)
		return ret;
	ret = ce_bam_add_cmd(CE_STATUS3_ADDR(0), 0);
	if (ret)
		return ret;
	ret = ce_bam_add_cmd(CE_STATUS2_ADDR(0), 0);
	if (ret)
		return ret;
	ret = ce_bam_add_cmd(CE_STATUS_ADDR(0), 0);
	if (ret)
		return ret;
	if (sha_ctx->ce_ctx->flags & CE_HAL_FLAGS_IS_LITTLE_ENDIAN)
		config |= CE_CONFIG_LITTLE_ENDIAN_MODE_MASK;
	ret = ce_bam_add_cmd(CE_CONFIG_ADDR(0), config);
	if (ret)
		return ret;
	return ce_bam_add_cmd(CE_SEG_SIZE_ADDR(0), seg_sz);
}

static TEE_Result ce_bam_set_auth_ctx(struct ce_sha_ctx *sha_ctx,
				      size_t auth_sz, size_t seg_sz,
				      bool first, bool last)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t auth_cfg = U(1) << CE_AUTH_SEG_CFG_AUTH_ALG_SHIFT |
			    BIT(CE_AUTH_SEG_CFG_AUTH_SIZE_SHIFT) |
			    BIT(CE_AUTH_SEG_CFG_AUTH_POS_SHIFT);
	size_t n = 0;

	if (!sha_ctx || !sha_ctx->ce_ctx)
		return TEE_ERROR_BAD_STATE;
	if (auth_sz > seg_sz)
		return TEE_ERROR_BAD_PARAMETERS;
	if (first)
		auth_cfg |= CE_AUTH_SEG_CFG_FIRST_MASK;
	if (last)
		auth_cfg |= CE_AUTH_SEG_CFG_LAST_MASK;
	ret = ce_bam_add_cmd(CE_AUTH_SEG_SIZE_ADDR(0), auth_sz);
	if (ret)
		return ret;
	ret = ce_bam_add_cmd(CE_AUTH_SEG_START_ADDR(0), 0);
	if (ret)
		return ret;
	for (n = 0; n < QCE_MAX_AUTH_IV_COUNT; n++) {
		ret = ce_bam_add_cmd(CE_AUTH_IVn_ADDR(0, n),
				     sha_ctx->ce_ctx->auth_iv[n]);
		if (ret)
			return ret;
	}
	for (n = 0; n < QCE_MAX_AUTH_BYTE_COUNT; n++) {
		ret = ce_bam_add_cmd(CE_AUTH_BYTECNT0_ADDR(0) + U(4) * (n),
				     sha_ctx->ce_ctx->auth_byte_cnt[n]);
		if (ret)
			return ret;
	}
	return ce_bam_add_cmd(CE_AUTH_SEG_CFG_ADDR(0), auth_cfg);
}

static TEE_Result ce_bam_set_ce_go(void)
{
	uint32_t config = CE_GOPROC_CLR_CNTXT_MASK | CE_GOPROC_GO_MASK |
			  CE_GOPROC_RESULTS_DUMP_MASK;
	TEE_Result ret = ce_bam_add_cmd(CE_ENCR_SEG_CFG_ADDR(0), 0);

	if (ret)
		return ret;

	return ce_bam_add_cmd(CE_GOPROC_ADDR(0), config);
}

static TEE_Result ce_bam_queue_cmd(struct ce_bam_ctx *bam_ctx,
				   uint16_t flags)
{
	size_t cmd_desc_sz = bam_ctx->cmd_count * sizeof(*bam_ctx->cmd_desc);

	dcache_clean_range(bam_ctx->cmd_desc, cmd_desc_sz);
	if (ce_bam_pipe_transfer(bam_ctx, QUEUE_TX_PIPE_XFER,
				 bam_ctx->cmd_desc_pa,
				 bam_ctx->cmd_count *
				 sizeof(*bam_ctx->cmd_desc),
				 flags)) {
		EMSG("GPCE BAM: command descriptor submission failed");
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

static TEE_Result ce_bam_toggle_engine_lock(bool lock)
{
	struct ce_bam_ctx *bam_ctx = NULL;
	uint32_t dummy_config =
		CE_CONFIG_MASK_OP_DONE_INTR_MASK |
		CE_CONFIG_MASK_DIN_INTR_MASK |
		CE_CONFIG_MASK_DOUT_INTR_MASK |
		CE_CONFIG_HIGH_SPD_DATA_EN_N_MASK |
		CE_CONFIG_LITTLE_ENDIAN_MODE_MASK |
		CE_CONFIG_REQ_SIZE_MASK |
		(U(0xf) << CE_CONFIG_PIPE_SET_SELECT_SHIFT);
	uint16_t flags = BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_EOT;
	TEE_Result ret = TEE_SUCCESS;

	if (!ce_bam_state)
		return TEE_ERROR_BAD_STATE;
	bam_ctx = ce_bam_state;
	ce_bam_clear_cmds(bam_ctx);
	ret = ce_bam_add_cmd(CE_CONFIG_ADDR(0), dummy_config);
	if (ret)
		return ret;
	if (lock)
		flags |= BAM_IOVEC_FLAG_LCK;
	else
		flags |= BAM_IOVEC_FLAG_UNLCK;
	ret = ce_bam_queue_cmd(bam_ctx, flags);
	if (ret)
		return ret;

	return ce_bam_poll(bam_ctx->tx_pipe_handle);
}

static TEE_Result ce_bam_set_up_xfer(struct ce_sha_ctx *sha_ctx,
				     bool zero_length)
{
	struct ce_bam_ctx *bam_ctx = ce_bam_state;
	uint16_t flags = BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_INT |
			 BAM_IOVEC_FLAG_LCK;

	if (!sha_ctx || !sha_ctx->ce_ctx ||
	    !(sha_ctx->ce_ctx->flags & CE_HAL_FLAGS_IS_AUTH_ENG_EN))
		return TEE_ERROR_BAD_STATE;
	if (zero_length)
		flags |= BAM_IOVEC_FLAG_EOT;
	else
		flags |= BAM_IOVEC_FLAG_NO_SUBMIT;

	return ce_bam_queue_cmd(bam_ctx, flags);
}

TEE_Result ce_bam_set_ce_ctx(struct ce_sha_ctx *sha_ctx, size_t auth_sz,
			     size_t seg_sz, bool first, bool last)
{
	struct ce_bam_ctx *bam_ctx = NULL;
	TEE_Result ret = TEE_SUCCESS;

	ret = ce_bam_pipe_init(sha_ctx);
	if (ret)
		return ret;
	if (!sha_ctx->ce_ctx)
		return TEE_ERROR_BAD_STATE;
	bam_ctx = ce_bam_state;
	ce_bam_clear_cmds(bam_ctx);
	ret = ce_bam_set_common_ctx(sha_ctx, seg_sz);
	if (ret)
		return ret;
	if (sha_ctx->ce_ctx->flags & CE_HAL_FLAGS_IS_AUTH_ENG_EN) {
		ret = ce_bam_set_auth_ctx(sha_ctx, auth_sz, seg_sz, first,
					  last);
		if (ret)
			return ret;
	}
	ret = ce_bam_set_ce_go();
	if (ret)
		return ret;

	ret = ce_bam_set_up_xfer(sha_ctx, !seg_sz);
	if (ret) {
		if (!bam_pipe_reinit(bam_ctx->tx_pipe_handle))
			EMSG("GPCE BAM: failed to recover TX pipe");
		if (!bam_pipe_reinit(bam_ctx->rx_pipe_handle))
			EMSG("GPCE BAM: failed to recover RX pipe");
	}

	return ret;
}

static TEE_Result ce_bam_queue_xfer(struct ce_bam_ctx *bam_ctx,
				    const uint8_t *buf, paddr_t pa, size_t size,
				    bool last,
				    bool is_tx_pipe)
{
	uint16_t flags = BAM_IOVEC_FLAG_NO_SUBMIT;

	if (!pa) {
		EMSG("GPCE BAM: data physical address lookup failed");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (last)
		flags = BAM_IOVEC_FLAG_INT | BAM_IOVEC_FLAG_EOT;
	if (is_tx_pipe && last)
		flags |= BAM_IOVEC_FLAG_NWD;
	if (is_tx_pipe)
		dcache_clean_range((void *)buf, size);
	else
		dcache_cleaninv_range((void *)buf, size);
	if (ce_bam_pipe_transfer(bam_ctx, is_tx_pipe, pa, size, flags)) {
		EMSG("GPCE BAM: %s descriptor submission failed",
		     is_tx_pipe ? "TX" : "RX");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * Return the physically contiguous prefix of @buf that fits in one BAM
 * descriptor. virt_to_phys() translates one virtual address only, so each
 * following small page is checked before it is included in the descriptor.
 */
static TEE_Result ce_bam_get_contig_size(const uint8_t *buf, size_t size,
					 paddr_t *pa, size_t *contig_size)
{
	size_t limit = MIN(size, (size_t)BAM_MAX_XFER_SIZE);
	size_t page_size = 0;
	paddr_t next_pa = 0;

	if (!buf || !size || !pa || !contig_size)
		return TEE_ERROR_BAD_PARAMETERS;
	*pa = virt_to_phys((void *)buf);
	if (!*pa) {
		EMSG("GPCE BAM: data physical address lookup failed");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	page_size = MIN(limit, (size_t)SMALL_PAGE_SIZE -
			((vaddr_t)buf & SMALL_PAGE_MASK));
	while (page_size < limit) {
		next_pa = virt_to_phys((void *)(buf + page_size));
		if (next_pa != *pa + page_size)
			break;
		page_size += MIN(limit - page_size, (size_t)SMALL_PAGE_SIZE);
	}
	*contig_size = page_size;
	return TEE_SUCCESS;
}

TEE_Result ce_bam_get_xfer_size(const uint8_t *ibuf, size_t isz,
				size_t *xfer_sz)
{
	size_t size = 0;
	size_t desc_count = 0;
	TEE_Result ret = TEE_SUCCESS;
	paddr_t pa = 0;

	if (!ibuf || !isz || !xfer_sz)
		return TEE_ERROR_BAD_PARAMETERS;
	*xfer_sz = 0;
	isz = MIN(isz, (size_t)QCE_BAM_MAX_DATA_SIZE);
	while (isz && desc_count < QCE_BAM_MAX_DATA_DESCS) {
		ret = ce_bam_get_contig_size(ibuf, isz, &pa, &size);
		if (ret)
			return ret;
		ibuf += size;
		isz -= size;
		*xfer_sz += size;
		desc_count++;
	}

	return TEE_SUCCESS;
}

TEE_Result ce_bam_xfer_data(const uint8_t *ibuf, size_t isz)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t size = 0;
	size_t max_size = 0;
	struct ce_bam_ctx *bam_ctx = NULL;
	paddr_t pa = 0;

	if (!ce_bam_state || (!ibuf && isz))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!isz)
		return TEE_SUCCESS;
	bam_ctx = ce_bam_state;
	ret = ce_bam_get_xfer_size(ibuf, isz, &max_size);
	if (ret)
		return ret;
	if (max_size != isz)
		return TEE_ERROR_BAD_PARAMETERS;

	while (isz) {
		ret = ce_bam_get_contig_size(ibuf, isz, &pa, &size);
		if (ret)
			return ret;
		ret = ce_bam_queue_xfer(bam_ctx, ibuf, pa, size,
					(size < isz) ?
					NEXT_PIPE_XFER_REQ : LAST_PIPE_XFER_REQ,
					QUEUE_TX_PIPE_XFER);
		if (ret) {
			if (!bam_pipe_reinit(bam_ctx->tx_pipe_handle))
				EMSG("GPCE BAM: failed to recover TX pipe");
			if (!bam_pipe_reinit(bam_ctx->rx_pipe_handle))
				EMSG("GPCE BAM: failed to recover RX pipe");
			return ret;
		}
		ibuf += size;
		isz -= size;
	}

	return TEE_SUCCESS;
}

static TEE_Result ce_bam_queue_result(void)
{
	struct ce_bam_ctx *bam_ctx = ce_bam_state;

	memset(bam_ctx->result, 0, sizeof(*bam_ctx->result));
	return ce_bam_queue_xfer(bam_ctx, (const uint8_t *)bam_ctx->result,
				 bam_ctx->result_pa,
				 sizeof(*bam_ctx->result), LAST_PIPE_XFER_REQ,
				 QUEUE_RX_PIPE_XFER);
}

static TEE_Result ce_bam_check_ce_status(void)
{
	uint32_t status = io_read32(CE_STATUS_ADDR(ce_base));
	uint32_t status2 = io_read32(CE_STATUS2_ADDR(ce_base));

	if (status2 & (CE_STATUS2_BIST_ERROR_MASK |
	     CE_STATUS2_BIST_BUSY_MASK |
	     CE_STATUS2_KEY_ERR_MASK |
	     CE_STATUS2_AXI_EXTRA_MASK |
	     CE_STATUS2_LOCKED_MASK) ||
	    status & (CE_STATUS_MAC_FAILED_MASK | CE_STATUS_HSD_ERR_MASK))
		return TEE_ERROR_GENERIC;
	if (status & CE_STATUS_AXI_ERR_MASK)
		return TEE_ERROR_GENERIC;
	if (status & (CE_STATUS_ACCESS_VIOL_MASK | CE_STATUS_ERR_INTR_MASK |
		      CE_STATUS_SW_ERR_MASK))
		return TEE_ERROR_GENERIC;
	if (!(status & CE_STATUS_OPERATION_DONE_MASK) ||
	    status & (CE_STATUS_ENCR_BUSY_MASK | CE_STATUS_AUTH_BUSY_MASK))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static TEE_Result ce_bam_wait_for_xfer(void)
{
	struct ce_bam_ctx *bam_ctx = NULL;
	const char *stage = "TX pipe completion";
	TEE_Result ret = TEE_SUCCESS;

	if (!ce_bam_state)
		return TEE_ERROR_BAD_STATE;
	bam_ctx = ce_bam_state;
	ret = ce_bam_poll(bam_ctx->tx_pipe_handle);
	if (!ret) {
		stage = "RX pipe completion";
		ret = ce_bam_poll(bam_ctx->rx_pipe_handle);
	}
	if (!ret) {
		uint32_t count = 0;

		stage = "CE completion";
		for (count = 0; count < BAM_POLL_MAX; count++) {
			ret = ce_bam_check_ce_status();
			if (ret != TEE_ERROR_BUSY)
				break;
		}
		if (ret == TEE_ERROR_BUSY)
			ret = TEE_ERROR_TIMEOUT;
	}
	if (ret) {
		EMSG("GPCE BAM: %s failed: %#"PRIx32" status %#"PRIx32
		     " status2 %#"PRIx32" status3 %#"PRIx32
		     " status4 %#"PRIx32,
		     stage, ret, io_read32(CE_STATUS_ADDR(ce_base)),
		     io_read32(CE_STATUS2_ADDR(ce_base)),
		     io_read32(CE_STATUS3_ADDR(ce_base)),
		     io_read32(CE_STATUS4_ADDR(ce_base)));
		if (!bam_pipe_reinit(bam_ctx->tx_pipe_handle))
			EMSG("GPCE BAM: failed to recover TX pipe");
		if (!bam_pipe_reinit(bam_ctx->rx_pipe_handle))
			EMSG("GPCE BAM: failed to recover RX pipe");
	}

	return ret;
}

static TEE_Result ce_bam_save_ctx(struct ce_sha_ctx *sha_ctx,
				  struct ce_bam_ctx *bam_ctx)
{
	uint32_t byte_cnt = 0;
	size_t n = 0;

	if (!sha_ctx || !sha_ctx->ce_ctx)
		return TEE_ERROR_BAD_STATE;
	dcache_inv_range(bam_ctx->result, sizeof(*bam_ctx->result));
	for (n = 0; n < QCE_MAX_AUTH_IV_COUNT; n++)
		sha_ctx->ce_ctx->auth_iv[n] = bam_ctx->result->auth_iv[n];
	for (n = 0; n < QCE_MAX_AUTH_BYTE_COUNT; n++) {
		byte_cnt = bam_ctx->result->auth_byte_cnt[n];
		sha_ctx->ce_ctx->auth_byte_cnt[n] =
			TEE_U32_TO_BIG_ENDIAN(byte_cnt);
	}
	return TEE_SUCCESS;
}

TEE_Result ce_bam_get_ce_ctx(struct ce_sha_ctx *sha_ctx)
{
	TEE_Result ret = TEE_SUCCESS;

	if (!sha_ctx || !sha_ctx->ce_ctx || !ce_bam_state)
		return TEE_ERROR_BAD_STATE;
	ret = ce_bam_queue_result();
	if (ret) {
		if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
			EMSG("GPCE BAM: failed to recover TX pipe");
		if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
			EMSG("GPCE BAM: failed to recover RX pipe");
		return ret;
	}
	ret = ce_bam_wait_for_xfer();
	if (ret) {
		EMSG("GPCE BAM: transfer failed: %#"PRIx32, ret);
		return ret;
	}
	ret = ce_bam_save_ctx(sha_ctx, ce_bam_state);
	if (ret)
		return ret;
	ret = ce_bam_toggle_engine_lock(false);
	if (ret) {
		if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
			EMSG("GPCE BAM: failed to recover TX pipe");
		if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
			EMSG("GPCE BAM: failed to recover RX pipe");
		return ret;
	}

	return TEE_SUCCESS;
}
