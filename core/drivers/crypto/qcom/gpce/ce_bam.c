// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * BAM transport for the Qualcomm Crypto Engine.
 */

#include <assert.h>
#include <gpce_hwio.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <util.h>

#include "bam.h"
#include "ce_bam.h"
#include "ce_hal.h"

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
#define QCE_BAM_PIPE_SET                   U(0)
#define QCE_BAM_TX_PIPE                    (QCE_BAM_PIPE_SET * U(2))
#define QCE_BAM_RX_PIPE                    (QCE_BAM_TX_PIPE + U(1))
#define QCE_BAM_EE                         U(2)
/* Pipe-set value used by the dummy CE lock and unlock command. */
#define QCE_BAM_DUMMY_PIPE_SET             U(0xf)
/* CE command descriptor register-address field, bits [23:0]. */
#define QCE_BAM_CMD_REG_ADDR_MASK          U(0x00ffffff)
/* SHA-256 uses at most 23 CE commands per transfer. */
#define QCE_BAM_CMD_DESC_COUNT             U(24)
/* CE result dumps contain sixteen authentication IV words. */
#define QCE_BAM_RESULT_AUTH_IV_COUNT       U(16)
/* CE result dumps retain twelve words unused by SHA-256. */
#define QCE_BAM_RESULT_RESERVED_WORDS      U(12)
/* Allow 1 ms setup time plus 1 us for each eight input bytes. */
#define QCE_BAM_TIMEOUT_BASE_US            U(1000)
#define QCE_BAM_TIMEOUT_BYTE_SHIFT         U(3)

#define QCE_CE_STATUS_ERROR_MASK \
	(CE_STATUS_MAC_FAILED_MASK | CE_STATUS_HSD_ERR_MASK | \
	 CE_STATUS_AXI_ERR_MASK | CE_STATUS_ACCESS_VIOL_MASK | \
	 CE_STATUS_ERR_INTR_MASK | CE_STATUS_SW_ERR_MASK)
#define QCE_CE_STATUS_BUSY_MASK \
	(CE_STATUS_ENCR_BUSY_MASK | CE_STATUS_AUTH_BUSY_MASK)
#define QCE_CE_STATUS2_ERROR_MASK \
	(CE_STATUS2_BIST_ERROR_MASK | CE_STATUS2_BIST_BUSY_MASK | \
	 CE_STATUS2_KEY_ERR_MASK | CE_STATUS2_AXI_EXTRA_MASK | \
	 CE_STATUS2_LOCKED_MASK)

#define QCE_BAM_MAX_DATA_DESCS \
	((BAM_DESC_FIFO_SIZE / BAM_DESC_ENTRY_SIZE) - \
	 QCE_BAM_RESERVED_DESC_COUNT)

/*
 * struct bam_ce - Crypto Engine command descriptor
 * @reg_addr_cmd: Register address in bits [23:0] and command opcode in
 *		 bits [31:24]
 * @data: Value written by the command
 * @mask: Bit mask applied by the command
 * @reserved: Must be zero
 */
struct bam_ce {
	uint32_t reg_addr_cmd;
	uint32_t data;
	uint32_t mask;
	uint32_t reserved;
};

/*
 * struct ce_bam_result - CE result-dump buffer written through the RX pipe
 * @auth_iv: SHA authentication IV words after the transfer
 * @auth_byte_cnt: SHA authentication byte-count words after the transfer
 * @reserved: Remaining hardware result-dump fields unused by SHA-256
 */
struct ce_bam_result {
	uint32_t auth_iv[QCE_BAM_RESULT_AUTH_IV_COUNT];
	uint32_t auth_byte_cnt[QCE_MAX_AUTH_BYTE_COUNT];
	uint32_t reserved[QCE_BAM_RESULT_RESERVED_WORDS];
};

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
 * @xfer_size: Payload size used to derive the completion timeout
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
	size_t xfer_size;
	uint8_t cmd_count;
};

static_assert(QCE_BAM_CMD_DESC_COUNT <= UINT8_MAX);

static struct ce_bam_ctx *ce_bam_state;
static vaddr_t ce_base;
static vaddr_t ce_bam_base;

static uint32_t ce_bam_timeout_us(size_t size)
{
	return QCE_BAM_TIMEOUT_BASE_US +
	       (uint32_t)(size >> QCE_BAM_TIMEOUT_BYTE_SHIFT);
}

TEE_Result ce_bam_init(void)
{
	struct bam_config config = { };
	TEE_Result ret = TEE_SUCCESS;

	ce_base = (vaddr_t)phys_to_virt(QCOM_GPCE_REG_BASE,
					MEM_AREA_IO_SEC,
					QCOM_GPCE_REG_SIZE);
	if (!ce_base) {
		EMSG("failed to map Crypto Engine registers");
		return TEE_ERROR_GENERIC;
	}
	ce_bam_base = (vaddr_t)phys_to_virt(QCOM_GPCE_BAM_REG_BASE,
					    MEM_AREA_IO_SEC,
					    QCOM_GPCE_BAM_REG_SIZE);
	if (!ce_bam_base) {
		EMSG("failed to map BAM registers");
		return TEE_ERROR_GENERIC;
	}
	config.base = ce_bam_base;
	config.ee = QCE_BAM_EE;
	ret = bam_init(&config);
	if (ret)
		ce_bam_base = 0;
	return ret;
}

static TEE_Result ce_bam_pipe_init(void)
{
	struct ce_bam_ctx *bam_ctx = NULL;
	size_t cache_line_size = cache_get_max_line_size();
	TEE_Result ret = TEE_SUCCESS;

	if (ce_bam_state)
		return TEE_SUCCESS;
	bam_ctx = calloc(1, sizeof(*bam_ctx));
	if (!bam_ctx) {
		EMSG("context allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	bam_ctx->tx_desc = memalign(BAM_DESC_ENTRY_SIZE, BAM_DESC_FIFO_SIZE);
	bam_ctx->rx_desc = memalign(BAM_DESC_ENTRY_SIZE, BAM_DESC_FIFO_SIZE);
	bam_ctx->cmd_desc =
		memalign(BAM_DESC_ENTRY_SIZE,
			 QCE_BAM_CMD_DESC_COUNT * sizeof(*bam_ctx->cmd_desc));
	/* RX cache invalidation operates on complete cache lines. */
	bam_ctx->result =
		memalign(cache_line_size,
			 ROUNDUP(sizeof(*bam_ctx->result), cache_line_size));
	if (!bam_ctx->tx_desc || !bam_ctx->rx_desc || !bam_ctx->cmd_desc ||
	    !bam_ctx->result) {
		EMSG("descriptor allocation failed");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	memset(bam_ctx->cmd_desc, 0,
	       QCE_BAM_CMD_DESC_COUNT * sizeof(*bam_ctx->cmd_desc));
	memset(bam_ctx->result, 0, sizeof(*bam_ctx->result));
	bam_ctx->tx_pipe_handle =
		bam_pipe_init(QCE_BAM_TX_PIPE, false /*!is_producer*/,
			      bam_ctx->tx_desc);
	bam_ctx->rx_pipe_handle =
		bam_pipe_init(QCE_BAM_RX_PIPE, true /*is_producer*/,
			      bam_ctx->rx_desc);
	bam_ctx->cmd_desc_pa = virt_to_phys(bam_ctx->cmd_desc);
	bam_ctx->result_pa = virt_to_phys(bam_ctx->result);
	if (!bam_ctx->tx_pipe_handle || !bam_ctx->rx_pipe_handle) {
		EMSG("descriptor initialization failed");
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}

	ce_bam_state = bam_ctx;
	return TEE_SUCCESS;

err:
	free(bam_ctx->tx_desc);
	free(bam_ctx->rx_desc);
	free_wipe(bam_ctx->cmd_desc);
	free_wipe(bam_ctx->result);
	free(bam_ctx);
	return ret;
}

/*
 * BAM command elements encode a 24-bit register address relative to the
 * CRYPTO_TOP base. CE register offsets are relative to the CE base.
 */
static void ce_bam_add_cmd(uint32_t reg_offset, uint32_t value)
{
	uint32_t reg_addr = 0;

	assert(ce_bam_state->cmd_count < QCE_BAM_CMD_DESC_COUNT);
	assert(reg_offset < QCOM_GPCE_REG_SIZE);

	reg_addr = QCOM_GPCE_REG_BASE + reg_offset - QCOM_GPCE_TOP_REG_BASE;
	assert(reg_addr <= QCE_BAM_CMD_REG_ADDR_MASK);

	/* Command opcode zero performs a masked register write. */
	ce_bam_state->cmd_desc[ce_bam_state->cmd_count++] = (struct bam_ce){
		.reg_addr_cmd = reg_addr,
		.data = value,
		.mask = UINT32_MAX,
	};
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

	if (is_tx_pipe)
		pipe = bam_ctx->tx_pipe_handle;
	else
		pipe = bam_ctx->rx_pipe_handle;
	return bam_pipe_transfer(pipe, pa, size, flags);
}

static TEE_Result ce_bam_poll(struct bam_pipe_state *pipe, uint64_t timeout)
{
	TEE_Result ret = TEE_SUCCESS;

	do {
		ret = bam_pipe_poll(pipe);
		if (ret == TEE_SUCCESS)
			return TEE_SUCCESS;
		if (ret != TEE_ERROR_BUSY) {
			EMSG("pipe poll failed");
			return ret;
		}
	} while (!timeout_elapsed(timeout));

	EMSG("pipe completion timeout");
	return TEE_ERROR_TIMEOUT;
}

static void ce_bam_set_common_ctx(struct qce_ce_ctx *ce_ctx, size_t seg_sz)
{
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
			  SHIFT_U32(QCE_BAM_PIPE_SET,
				    CE_CONFIG_PIPE_SET_SELECT_SHIFT);

	ce_bam_add_cmd(CE_STATUS4_ADDR(0), 0);
	ce_bam_add_cmd(CE_STATUS3_ADDR(0), 0);
	ce_bam_add_cmd(CE_STATUS2_ADDR(0), 0);
	ce_bam_add_cmd(CE_STATUS_ADDR(0), 0);
	if (ce_ctx->flags & CE_HAL_FLAGS_IS_LITTLE_ENDIAN)
		config |= CE_CONFIG_LITTLE_ENDIAN_MODE_MASK;
	ce_bam_add_cmd(CE_CONFIG_ADDR(0), config);
	ce_bam_add_cmd(CE_SEG_SIZE_ADDR(0), seg_sz);
}

static void ce_bam_set_auth_ctx(struct qce_ce_ctx *ce_ctx, size_t auth_sz,
				bool first, bool last)
{
	size_t n = 0;
	uint32_t auth_cfg =
		SHIFT_U32(CE_AUTH_SEG_CFG_AUTH_ALG_SHA256,
			  CE_AUTH_SEG_CFG_AUTH_ALG_SHIFT) |
		BIT(CE_AUTH_SEG_CFG_AUTH_SIZE_SHIFT) |
		BIT(CE_AUTH_SEG_CFG_AUTH_POS_SHIFT);

	if (first)
		auth_cfg |= CE_AUTH_SEG_CFG_FIRST_MASK;
	if (last)
		auth_cfg |= CE_AUTH_SEG_CFG_LAST_MASK;
	ce_bam_add_cmd(CE_AUTH_SEG_SIZE_ADDR(0), auth_sz);
	ce_bam_add_cmd(CE_AUTH_SEG_START_ADDR(0), 0);
	for (n = 0; n < ARRAY_SIZE(ce_ctx->auth_iv); n++)
		ce_bam_add_cmd(CE_AUTH_IVn_ADDR(0, n), ce_ctx->auth_iv[n]);
	for (n = 0; n < QCE_MAX_AUTH_BYTE_COUNT; n++) {
		ce_bam_add_cmd(CE_AUTH_BYTECNTn_ADDR(0, n),
			       ce_ctx->auth_byte_cnt[n]);
	}
	ce_bam_add_cmd(CE_AUTH_SEG_CFG_ADDR(0), auth_cfg);
}

static void ce_bam_set_ce_go(void)
{
	uint32_t config = CE_GOPROC_CLR_CNTXT_MASK | CE_GOPROC_GO_MASK |
			  CE_GOPROC_RESULTS_DUMP_MASK;

	ce_bam_add_cmd(CE_ENCR_SEG_CFG_ADDR(0), 0);
	ce_bam_add_cmd(CE_GOPROC_ADDR(0), config);
}

static TEE_Result ce_bam_queue_cmd(uint16_t flags)
{
	size_t cmd_desc_sz =
		ce_bam_state->cmd_count * sizeof(*ce_bam_state->cmd_desc);
	TEE_Result ret = TEE_SUCCESS;

	dcache_clean_range(ce_bam_state->cmd_desc, cmd_desc_sz);
	ret = ce_bam_pipe_transfer(ce_bam_state, true /* is_tx_pipe */,
				   ce_bam_state->cmd_desc_pa, cmd_desc_sz,
				   flags);

	if (ret) {
		EMSG("command descriptor submission failed: %#"PRIx32,
		     ret);
		return ret;
	}
	return TEE_SUCCESS;
}

static TEE_Result ce_bam_toggle_engine_lock(bool lock)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t dummy_config =
		CE_CONFIG_MASK_OP_DONE_INTR_MASK |
		CE_CONFIG_MASK_DIN_INTR_MASK |
		CE_CONFIG_MASK_DOUT_INTR_MASK |
		CE_CONFIG_HIGH_SPD_DATA_EN_N_MASK |
		CE_CONFIG_LITTLE_ENDIAN_MODE_MASK |
		CE_CONFIG_REQ_SIZE_MASK |
		SHIFT_U32(QCE_BAM_DUMMY_PIPE_SET,
			  CE_CONFIG_PIPE_SET_SELECT_SHIFT);
	uint16_t flags = BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_EOT;

	ce_bam_clear_cmds(ce_bam_state);
	ce_bam_add_cmd(CE_CONFIG_ADDR(0), dummy_config);
	if (lock)
		flags |= BAM_IOVEC_FLAG_LCK;
	else
		flags |= BAM_IOVEC_FLAG_UNLCK;
	ret = ce_bam_queue_cmd(flags);
	if (ret)
		return ret;

	return ce_bam_poll(ce_bam_state->tx_pipe_handle,
			   timeout_init_us(QCE_BAM_TIMEOUT_BASE_US));
}

static TEE_Result ce_bam_set_up_xfer(struct qce_ce_ctx *ce_ctx,
				     bool zero_length)
{
	uint16_t flags = BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_INT |
			 BAM_IOVEC_FLAG_LCK;

	if (!(ce_ctx->flags & CE_HAL_FLAGS_IS_AUTH_ENG_EN))
		return TEE_ERROR_BAD_STATE;
	if (zero_length)
		flags |= BAM_IOVEC_FLAG_EOT;
	else
		flags |= BAM_IOVEC_FLAG_NO_SUBMIT;

	return ce_bam_queue_cmd(flags);
}

TEE_Result ce_bam_set_ce_ctx(struct qce_ce_ctx *ce_ctx, size_t auth_sz,
			     size_t seg_sz, bool first, bool last)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = ce_bam_pipe_init();
	if (ret)
		return ret;
	ce_bam_state->xfer_size = seg_sz;
	ce_bam_clear_cmds(ce_bam_state);
	ce_bam_set_common_ctx(ce_ctx, seg_sz);
	if (ce_ctx->flags & CE_HAL_FLAGS_IS_AUTH_ENG_EN)
		ce_bam_set_auth_ctx(ce_ctx, auth_sz, first, last);

	ce_bam_set_ce_go();

	ret = ce_bam_set_up_xfer(ce_ctx, !seg_sz /* zero_length */);
	if (ret) {
		if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
			EMSG("failed to recover TX pipe");
		if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
			EMSG("failed to recover RX pipe");
	}

	return ret;
}

static TEE_Result ce_bam_queue_xfer(struct ce_bam_ctx *bam_ctx,
				    const void *buf, paddr_t pa, size_t size,
				    bool last,
				    bool is_tx_pipe)
{
	const char *pipe_name = "RX";
	uint16_t flags = BAM_IOVEC_FLAG_NO_SUBMIT;

	if (is_tx_pipe)
		pipe_name = "TX";

	if (last)
		flags = BAM_IOVEC_FLAG_INT | BAM_IOVEC_FLAG_EOT;
	if (is_tx_pipe && last)
		flags |= BAM_IOVEC_FLAG_NWD;
	if (is_tx_pipe)
		dcache_clean_range((void *)buf, size);
	else
		dcache_cleaninv_range((void *)buf, size);
	if (ce_bam_pipe_transfer(bam_ctx, is_tx_pipe, pa, size, flags)) {
		EMSG("%s descriptor submission failed", pipe_name);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/*
 * Return the physically contiguous prefix of @buf that fits in one BAM
 * descriptor. virt_to_phys() translates one virtual address only, so each
 * following small page is checked before it is included in the descriptor.
 */
static size_t ce_bam_get_contig_size(const uint8_t *buf, size_t size,
				     paddr_t *pa)
{
	paddr_t next_pa = 0;
	size_t contig_len = 0;
	size_t limit = MIN(size, BAM_MAX_XFER_SIZE);

	*pa = virt_to_phys((void *)buf);
	contig_len = SMALL_PAGE_SIZE - ((vaddr_t)buf & SMALL_PAGE_MASK);
	while (contig_len < limit) {
		next_pa = virt_to_phys((void *)(buf + contig_len));
		if (next_pa != *pa + contig_len)
			break;
		contig_len += SMALL_PAGE_SIZE;
	}
	return MIN(contig_len, limit);
}

TEE_Result ce_bam_get_xfer_size(const uint8_t *ibuf, size_t isz,
				size_t *xfer_sz)
{
	paddr_t pa = 0;
	size_t desc_count = 0;
	size_t size = 0;

	*xfer_sz = 0;
	isz = MIN(isz, QCE_BAM_MAX_DATA_SIZE);
	while (isz && desc_count < QCE_BAM_MAX_DATA_DESCS) {
		size = ce_bam_get_contig_size(ibuf, isz, &pa);
		ibuf += size;
		isz -= size;
		*xfer_sz += size;
		desc_count++;
	}

	return TEE_SUCCESS;
}

TEE_Result ce_bam_xfer_data(const uint8_t *ibuf, size_t isz)
{
	paddr_t pa = 0;
	size_t size = 0;
	TEE_Result ret = TEE_SUCCESS;
	bool last = false;

	while (isz) {
		size = ce_bam_get_contig_size(ibuf, isz, &pa);
		last = size == isz;
		ret = ce_bam_queue_xfer(ce_bam_state, ibuf, pa, size,
					last,
					true /* is_tx_pipe */);
		if (ret) {
			if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
				EMSG("failed to recover TX pipe");
			if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
				EMSG("failed to recover RX pipe");
			return ret;
		}
		ibuf += size;
		isz -= size;
	}

	return TEE_SUCCESS;
}

static TEE_Result ce_bam_queue_result(void)
{
	memset(ce_bam_state->result, 0, sizeof(*ce_bam_state->result));
	return ce_bam_queue_xfer(ce_bam_state, ce_bam_state->result,
				 ce_bam_state->result_pa,
				 sizeof(*ce_bam_state->result),
				 true /* last */, false /* !is_tx_pipe */);
}

static TEE_Result ce_bam_check_ce_status(void)
{
	uint32_t status = io_read32(CE_STATUS_ADDR(ce_base));
	uint32_t status2 = io_read32(CE_STATUS2_ADDR(ce_base));

	if (status2 & QCE_CE_STATUS2_ERROR_MASK)
		return TEE_ERROR_GENERIC;
	if (status & QCE_CE_STATUS_ERROR_MASK)
		return TEE_ERROR_GENERIC;
	if (!(status & CE_STATUS_OPERATION_DONE_MASK) ||
	    (status & QCE_CE_STATUS_BUSY_MASK))
		return TEE_ERROR_BUSY;

	return TEE_SUCCESS;
}

static TEE_Result ce_bam_wait_for_xfer(void)
{
	const char *stage = "TX pipe completion";
	uint64_t timeout = 0;
	TEE_Result ret = TEE_SUCCESS;

	timeout = timeout_init_us(ce_bam_timeout_us(ce_bam_state->xfer_size));
	ret = ce_bam_poll(ce_bam_state->tx_pipe_handle, timeout);
	if (!ret) {
		stage = "RX pipe completion";
		ret = ce_bam_poll(ce_bam_state->rx_pipe_handle, timeout);
	}
	if (!ret) {
		stage = "CE completion";
		ret = TEE_ERROR_BUSY;
		do {
			ret = ce_bam_check_ce_status();
			if (ret != TEE_ERROR_BUSY)
				break;
		} while (!timeout_elapsed(timeout));
		if (ret == TEE_ERROR_BUSY)
			ret = TEE_ERROR_TIMEOUT;
	}
	if (ret) {
		EMSG("%s failed: %#"PRIx32" status %#"PRIx32
		     " status2 %#"PRIx32" status3 %#"PRIx32
		     " status4 %#"PRIx32,
		     stage, ret, io_read32(CE_STATUS_ADDR(ce_base)),
		     io_read32(CE_STATUS2_ADDR(ce_base)),
		     io_read32(CE_STATUS3_ADDR(ce_base)),
		     io_read32(CE_STATUS4_ADDR(ce_base)));
		if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
			EMSG("failed to recover TX pipe");
		if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
			EMSG("failed to recover RX pipe");
	}

	return ret;
}

static void ce_bam_save_ctx(struct qce_ce_ctx *ce_ctx)
{
	size_t n = 0;
	uint32_t byte_cnt = 0;

	dcache_inv_range(ce_bam_state->result, sizeof(*ce_bam_state->result));
	for (n = 0; n < ARRAY_SIZE(ce_ctx->auth_iv); n++)
		ce_ctx->auth_iv[n] = ce_bam_state->result->auth_iv[n];
	for (n = 0; n < QCE_MAX_AUTH_BYTE_COUNT; n++) {
		byte_cnt = ce_bam_state->result->auth_byte_cnt[n];
		ce_ctx->auth_byte_cnt[n] =
			TEE_U32_TO_BIG_ENDIAN(byte_cnt);
	}
}

TEE_Result ce_bam_get_ce_ctx(struct qce_ce_ctx *ce_ctx)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = ce_bam_queue_result();
	if (ret) {
		if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
			EMSG("failed to recover TX pipe");
		if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
			EMSG("failed to recover RX pipe");
		return ret;
	}
	ret = ce_bam_wait_for_xfer();
	if (ret) {
		EMSG("transfer failed: %#"PRIx32, ret);
		return ret;
	}
	ce_bam_save_ctx(ce_ctx);
	ret = ce_bam_toggle_engine_lock(false /* unlock */);
	if (ret) {
		if (!bam_pipe_reinit(ce_bam_state->tx_pipe_handle))
			EMSG("failed to recover TX pipe");
		if (!bam_pipe_reinit(ce_bam_state->rx_pipe_handle))
			EMSG("failed to recover RX pipe");
		return ret;
	}

	return TEE_SUCCESS;
}
