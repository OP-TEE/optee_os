// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <assert.h>
#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <drivers/qcom/tlmm/tlmm.h>
#include <drivers/qcom_geni_spi.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/mutex.h>
#include <keep.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <trace.h>
#include <util.h>

/* Generic GENI Serial Engine (SE) registers */
#define SE_GENI_STATUS			0x40
#define GENI_SER_M_CLK_CFG		0x48
#define GENI_FW_REVISION_RO		0x68
#define SE_GENI_CLK_SEL			0x7c
#define SE_GENI_DFS_IF_CFG		0x80
#define SE_GENI_DMA_MODE_EN		0x258
#define SE_GENI_M_CMD0			0x600
#define SE_GENI_M_CMD_CTRL_REG		0x604
#define SE_GENI_M_IRQ_STATUS		0x610
#define SE_GENI_M_IRQ_EN		0x614
#define SE_GENI_M_IRQ_CLEAR		0x618
#define SE_GENI_TX_FIFOn		0x700
#define SE_GENI_RX_FIFOn		0x780
#define SE_GENI_TX_FIFO_STATUS		0x800
#define SE_GENI_RX_FIFO_STATUS		0x804
#define SE_GENI_TX_WATERMARK_REG	0x80c
#define SE_GENI_RX_WATERMARK_REG	0x810
#define SE_GENI_RX_RFR_WATERMARK_REG	0x814
#define SE_GENI_TX_PACKING_CFG0		0x260
#define SE_GENI_TX_PACKING_CFG1		0x264
#define SE_GENI_RX_PACKING_CFG0		0x284
#define SE_GENI_RX_PACKING_CFG1		0x288
#define SE_GENI_BYTE_GRAN		0x254
#define SE_HW_PARAM_0			0xe24

#define GENI_DMA_MODE_EN		BIT32(0)
#define M_OPCODE_SHFT			27
#define M_CMD_DONE_EN			BIT32(0)
#define M_CMD_OVERRUN_EN		BIT32(1)
#define M_ILLEGAL_CMD_EN		BIT32(2)
#define M_CMD_FAILURE_EN		BIT32(3)
#define M_CMD_CANCEL_EN			BIT32(4)
#define M_CMD_ABORT_EN			BIT32(5)
#define M_GENI_CMD_CANCEL		BIT32(0)
#define M_GENI_CMD_ABORT		BIT32(1)
#define M_RX_FIFO_RD_ERR_EN		BIT32(24)
#define M_RX_FIFO_WR_ERR_EN		BIT32(25)
#define M_RX_FIFO_WATERMARK_EN		BIT32(26)
#define M_RX_FIFO_LAST_EN		BIT32(27)
#define M_TX_FIFO_RD_ERR_EN		BIT32(28)
#define M_TX_FIFO_WR_ERR_EN		BIT32(29)
#define M_TX_FIFO_WATERMARK_EN		BIT32(30)

/*
 * Command/FIFO errors that abort an in-flight transfer. Same set mainline
 * spi-geni-qcom.c treats as fatal in its interrupt handler: a command
 * overrun, an illegal command, an outright command failure, or a FIFO
 * read/write error. Without these the SE silently stops making progress
 * and the only symptom is a full transfer timeout with no explanation.
 */
#define QUP_SPI_M_IRQ_ERR_MASK \
	(M_CMD_OVERRUN_EN | M_ILLEGAL_CMD_EN | M_CMD_FAILURE_EN | \
	 M_RX_FIFO_RD_ERR_EN | M_RX_FIFO_WR_ERR_EN | \
	 M_TX_FIFO_RD_ERR_EN | M_TX_FIFO_WR_ERR_EN)

#define QUP_SPI_M_IRQ_EN_MASK \
	(M_CMD_DONE_EN | M_CMD_CANCEL_EN | M_CMD_ABORT_EN | \
	 M_RX_FIFO_WATERMARK_EN | M_RX_FIFO_LAST_EN | M_TX_FIFO_WATERMARK_EN | \
	 QUP_SPI_M_IRQ_ERR_MASK)

#define TX_FIFO_WC_MSK			GENMASK_32(27, 0)
#define RX_FIFO_WC_MSK			GENMASK_32(24, 0)

#define CLK_DIV_SHFT			4
#define CLK_DIV_MSK			GENMASK_32(15, 4)
#define CLK_DIV_MAX			(CLK_DIV_MSK >> CLK_DIV_SHFT)

/*
 * Upper bound on DFS-selectable rows copied out of a SE clock's frequency
 * plan by geni_spi_resolve_clk(). The lemans plans expose 8 (indices 0x00
 * through 0x07); the headroom absorbs a target with a longer plan without
 * silently truncating -- resolve_clk logs if it ever has to.
 */
#define QUP_SPI_MAX_DFS_ROWS		16u
#define SER_CLK_EN			BIT32(0)
#define SER_DFS_EN			BIT32(0)
#define CLK_SEL_MSK			GENMASK_32(2, 0)

#define TX_FIFO_WIDTH_MSK		GENMASK_32(29, 24)
#define TX_FIFO_WIDTH_SHFT		24
#define TX_FIFO_DEPTH_MSK		GENMASK_32(21, 16)
#define TX_FIFO_DEPTH_SHFT		16

#define GENI_STATUS_M_GENI_CMD_ACTIVE	BIT32(0)

/*
 * Byte-packing vector fields: describe how sub-word SPI words are
 * packed into 32-bit FIFO words.
 */
#define NUM_PACKING_VECTORS		4
#define PACKING_START_SHIFT		5
#define PACKING_DIR_SHIFT		4
#define PACKING_LEN_SHIFT		1
#define PACKING_STOP_BIT		BIT32(0)
#define PACKING_VECTOR_SHIFT		10

/*
 * GENI SE firmware-load registers, offsets verified against the IP Catalog
 * register map and against u-boot's qcom_geni.c/qup-fw-load.h for the same
 * GENI SE hardware generation.
 */
#define GENI_INIT_CFG_REVISION		0x0
#define GENI_S_INIT_CFG_REVISION	0x4
#define GENI_FORCE_DEFAULT_REG		0x20
#define GENI_OUTPUT_CTRL		0x24
#define GENI_CGC_CTRL			0x28
#define GENI_CGC_CTRL_PROG_RAM_MSK	(BIT32(9) | BIT32(8))
#define GENI_CGC_CTRL_DEFAULT_EN_MSK	GENMASK_32(6, 0)
#define GENI_FW_REVISION_RO		0x68
#define GENI_CFG_REG0			0x100
#define SE_HW_PARAM_1			0xe28
#define RX_FIFO_WIDTH_SHFT		24
#define RX_FIFO_WIDTH_MSK		GENMASK_32(29, 24)
#define RX_FIFO_DEPTH_SHFT		16
#define RX_FIFO_DEPTH_MSK		GENMASK_32(21, 16)
#define SE_GSI_EVENT_EN			0xe18
#define SE_GSI_EVENT_EN_MSK		GENMASK_32(3, 0)
#define SE_IRQ_EN			0xe1c
#define SE_IRQ_EN_MSK			GENMASK_32(3, 0)
#define SE_DMA_GENERAL_CFG		0xe30
#define SE_DMA_GENERAL_CFG_CGC_ON_MSK	GENMASK_32(3, 0)
#define SE_GENI_S_IRQ_EN		0x644
#define S_CMD_OVERRUN_EN		BIT32(1)
#define S_ILLEGAL_CMD_EN		BIT32(2)
#define S_CMD_CANCEL_EN			BIT32(4)
#define S_CMD_ABORT_EN			BIT32(5)
#define S_GP_IRQ_0_EN			BIT32(9)
#define S_GP_IRQ_1_EN			BIT32(10)
#define S_GP_IRQ_2_EN			BIT32(11)
#define S_GP_IRQ_3_EN			BIT32(12)
#define S_RX_FIFO_WR_ERR_EN		BIT32(25)
#define S_RX_FIFO_RD_ERR_EN		BIT32(24)
#define SE_DMA_TX_IRQ_EN_SET		0xc4c
#define DMA_TX_RESET_DONE_EN_SET	BIT32(3)
#define DMA_TX_SBE_EN_SET		BIT32(2)
#define DMA_TX_DMA_DONE_EN_SET		BIT32(0)
#define SE_DMA_RX_IRQ_EN_SET		0xd4c
#define DMA_RX_FLUSH_DONE_EN_SET	BIT32(4)
#define DMA_RX_RESET_DONE_EN_SET	BIT32(3)
#define DMA_RX_SBE_EN_SET		BIT32(2)
#define DMA_RX_DMA_DONE_EN_SET		BIT32(0)
#define SE_GENI_FW_REVISION		0x1000
#define SE_S_FW_REVISION		0x1004
#define FW_REV_PROTOCOL_SHFT		8
#define SE_GENI_CFG_RAMN		0x1010
#define SE_GENI_CLK_CTRL		0x2000
#define GENI_CLK_CTRL_SER_CLK_SEL	BIT32(0)
#define SE_DMA_IF_EN			0x2004
#define DMA_IF_EN_DMA_IF_EN		BIT32(0)
#define SE_FIFO_IF_DISABLE		0x2008
#define FIFO_IF_DISABLE			BIT32(0)

/* QUPv3 wrapper-common registers, offset from qs->common_base */
#define QUPV3_SE_AHB_M_CFG		0x118
#define AHB_M_CLK_CGC_ON		BIT32(0)
#define QUPV3_COMMON_CFG		0x120
#define FAST_SWITCH_TO_HIGH_DISABLE	BIT32(0)
#define QUPV3_COMMON_CGC_CTRL		0x21c
#define COMMON_CSR_SLV_CLK_CGC_ON	BIT32(0)

#define QUP_FW_MAGIC			0x57464553
#define QUP_FW_HDR_VERSION		1
#define QUP_FW_SERIAL_PROTOCOL_SPI	1

/*
 * GENI SE firmware image header, as embedded at the start of a platform's
 * fw_image[]. Verified byte-for-byte against qup_spi_config[].fw_image and
 * against u-boot's struct elf_se_hdr (qup-fw-load.h) for this SE generation.
 */
struct elf_se_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t core_version;
	uint16_t serial_protocol;
	uint16_t fw_version;
	uint16_t cfg_version;
	uint16_t fw_size_in_items;
	uint16_t fw_offset;
	uint16_t cfg_size_in_items;
	uint16_t cfg_idx_offset;
	uint16_t cfg_val_offset;
};

/* SPI-specific SE registers */
#define SE_SPI_CPHA			0x224
#define CPHA				BIT32(0)

#define SE_SPI_LOOPBACK			0x22c
#define LOOPBACK_ENABLE			0x1

#define SE_SPI_CPOL			0x230
#define CPOL				BIT32(2)

#define SE_SPI_DEMUX_OUTPUT_INV		0x24c
#define SE_SPI_DEMUX_SEL		0x250

#define SE_SPI_TRANS_CFG		0x25c
#define CS_TOGGLE			BIT32(1)

#define SE_SPI_WORD_LEN			0x268
#define WORD_LEN_MSK			GENMASK_32(9, 0)
#define MIN_WORD_LEN			4

#define SE_SPI_TX_TRANS_LEN		0x26c
#define SE_SPI_RX_TRANS_LEN		0x270
#define TRANS_LEN_MSK			GENMASK_32(23, 0)

/*
 * M_CMD opcodes for the SPI protocol. TX_ONLY/RX_ONLY are combined
 * (opcode 3) for a full-duplex transfer -- matching mainline Linux's
 * spi-geni-qcom.c, which builds m_cmd this way and never actually issues
 * a literal opcode 7: that value sets an extra, undefined opcode bit
 * beyond TX_ONLY|RX_ONLY, and this SE's firmware silently drops RX
 * capture for it (TX shifts out fine, RX FIFO never receives anything).
 */
#define SPI_TX_ONLY			1
#define SPI_RX_ONLY			2
#define SPI_CS_ASSERT			8
#define SPI_CS_DEASSERT			9

#define QUP_SPI_M_CMD_TIMEOUT_US	1000000
#define QUP_SPI_CANCEL_TIMEOUT_US	1000000
#define QUP_SPI_ABORT_TIMEOUT_US	1000000

static struct qup_spi_data *to_qup_spi(struct spi_chip *chip)
{
	return container_of(chip, struct qup_spi_data, chip);
}

static TEE_Result qup_spi_pinctrl_setup(struct qup_spi_data *qs);

/* Clock gating helpers, defined below but used by start()/end(). */
static TEE_Result qup_spi_clk_enable(struct qup_spi_data *qs);
static void qup_spi_clk_disable(struct qup_spi_data *qs);

/*
 * Outcome of qup_spi_poll_m_cmd(): DONE is success; ERROR means the SE
 * reported a command/FIFO error, TIMEOUT that the command never
 * finished (and so needs cancel/abort recovery).
 */
enum qup_spi_poll_result {
	QUP_SPI_POLL_DONE,
	QUP_SPI_POLL_ERROR,
	QUP_SPI_POLL_TIMEOUT,
};

/*
 * Polling-mode M_CMD completion wait, defined below (it services TX/RX
 * FIFO via qup_spi_fifo_fill_tx(), defined further down) but used by
 * geni_cancel_and_abort_m_cmd() above that.
 */
static enum qup_spi_poll_result
qup_spi_poll_m_cmd(struct qup_spi_data *qs, uint32_t done_bit,
		    bool check_rem_bytes, unsigned int timeout_us);

static void geni_setup_m_cmd(struct qup_spi_data *qs, uint32_t cmd,
			      uint32_t params)
{
	uint32_t m_cmd = (cmd << M_OPCODE_SHFT) | params;

	io_write32(qs->base + SE_GENI_M_CMD0, m_cmd);
}

/*
 * The active M_CMD did not complete in time: request a cancel, and
 * escalate to an abort if the cancel itself does not complete. This
 * leaves the SE in a clean state before the caller reports failure.
 */
static void geni_cancel_and_abort_m_cmd(struct qup_spi_data *qs)
{
	io_write32(qs->base + SE_GENI_M_CMD_CTRL_REG, M_GENI_CMD_CANCEL);
	if (qup_spi_poll_m_cmd(qs, M_CMD_CANCEL_EN, false,
			       QUP_SPI_CANCEL_TIMEOUT_US) == QUP_SPI_POLL_DONE)
		return;

	EMSG("QUP SPI: cancel timed out, trying abort");
	DMSG("QUP SPI %u: after cancel: GENI_STATUS=%#" PRIx32 " M_IRQ_STATUS=%#" PRIx32 " M_IRQ_EN=%#" PRIx32,
	     qs->id, io_read32(qs->base + SE_GENI_STATUS),
	     io_read32(qs->base + SE_GENI_M_IRQ_STATUS),
	     io_read32(qs->base + SE_GENI_M_IRQ_EN));

	io_write32(qs->base + SE_GENI_M_CMD_CTRL_REG, M_GENI_CMD_ABORT);
	if (qup_spi_poll_m_cmd(qs, M_CMD_ABORT_EN, false,
			       QUP_SPI_ABORT_TIMEOUT_US) != QUP_SPI_POLL_DONE) {
		EMSG("QUP SPI: abort timed out, SE may require re-init");
		DMSG("QUP SPI %u: after abort: GENI_STATUS=%#" PRIx32 " M_IRQ_STATUS=%#" PRIx32 " M_IRQ_EN=%#" PRIx32,
		     qs->id, io_read32(qs->base + SE_GENI_STATUS),
		     io_read32(qs->base + SE_GENI_M_IRQ_STATUS),
		     io_read32(qs->base + SE_GENI_M_IRQ_EN));
	}
}

static void geni_get_fifo_depth_width(struct qup_spi_data *qs)
{
	uint32_t hw_param_0 = io_read32(qs->base + SE_HW_PARAM_0);
	uint32_t hw_param_1 = io_read32(qs->base + SE_HW_PARAM_1);

	qs->tx_fifo_depth = (hw_param_0 & TX_FIFO_DEPTH_MSK) >>
			     TX_FIFO_DEPTH_SHFT;
	qs->fifo_width_bits = (hw_param_0 & TX_FIFO_WIDTH_MSK) >>
			       TX_FIFO_WIDTH_SHFT;
	qs->rx_fifo_depth = (hw_param_1 & RX_FIFO_DEPTH_MSK) >>
			     RX_FIFO_DEPTH_SHFT;

	DMSG("QUP SPI %u: HW_PARAM_0=%#" PRIx32 " HW_PARAM_1=%#" PRIx32
	     " tx_fifo_depth=%u rx_fifo_depth=%u fifo_width=%u",
	     qs->id, hw_param_0, hw_param_1, qs->tx_fifo_depth,
	     qs->rx_fifo_depth, qs->fifo_width_bits);
}

/*
 * Builds the byte-packing vectors that tell the SE how to pack sub-word
 * SPI words into 32-bit FIFO words (and unpack them on receive). Same
 * vector construction as mainline's geni_se_config_packing()
 * (drivers/soc/qcom/qcom-geni-se.c).
 *
 * @pack_words must match the number of protocol words the FIFO helpers
 * move per access (qs->bytes_per_word / (bpw/8)). This driver always
 * passes 1, one word per FIFO entry; changing that would require
 * updating qup_spi_txrx8()/txrx16() in lockstep.
 */
static void geni_config_packing(struct qup_spi_data *qs, unsigned int bpw,
				 unsigned int pack_words)
{
	uint32_t cfg[NUM_PACKING_VECTORS] = { 0 };
	int idx_start = bpw - 1;
	int idx = idx_start;
	int idx_delta = -8;
	int temp_bpw = bpw;
	int ceil_bpw = ROUNDUP(bpw, 8);
	int iter = (ceil_bpw * pack_words) / 8;
	int i = 0;
	int len = 0;

	if (iter <= 0 || iter > NUM_PACKING_VECTORS) {
		EMSG("QUP SPI: invalid bits_per_word %u / pack_words %u", bpw,
		     pack_words);
		return;
	}

	for (i = 0; i < iter; i++) {
		len = MIN(temp_bpw, 8) - 1;
		cfg[i] = idx << PACKING_START_SHIFT;
		cfg[i] |= 1U << PACKING_DIR_SHIFT;
		cfg[i] |= len << PACKING_LEN_SHIFT;

		if (temp_bpw <= 8) {
			idx = ((i + 1) * 8) + idx_start;
			temp_bpw = bpw;
		} else {
			idx = idx + idx_delta;
			temp_bpw = temp_bpw - 8;
		}
	}
	cfg[iter - 1] |= PACKING_STOP_BIT;

	io_write32(qs->base + SE_GENI_TX_PACKING_CFG0,
		   cfg[0] | (cfg[1] << PACKING_VECTOR_SHIFT));
	io_write32(qs->base + SE_GENI_TX_PACKING_CFG1,
		   cfg[2] | (cfg[3] << PACKING_VECTOR_SHIFT));
	io_write32(qs->base + SE_GENI_RX_PACKING_CFG0,
		   cfg[0] | (cfg[1] << PACKING_VECTOR_SHIFT));
	io_write32(qs->base + SE_GENI_RX_PACKING_CFG1,
		   cfg[2] | (cfg[3] << PACKING_VECTOR_SHIFT));

	/*
	 * Number of protocol words packed into each 32-bit FIFO entry:
	 * 0 -> 4x8 bit, 1 -> 2x16 bit, 2 -> 1x32 bit. Written unconditionally,
	 * matching mainline spi-geni-qcom.c's geni_se_config_packing().
	 */
	io_write32(qs->base + SE_GENI_BYTE_GRAN, bpw / 16);
}

/*
 * Resolve the DFS index and serial divider for the requested SPI SCLK
 * from the source clock's DFS frequency plan (only rows with a real DFS
 * performance-state index are selectable). Picks the source rate that
 * yields the SCLK closest to, but not exceeding, speed_hz, so the
 * peripheral is never overclocked. Returns the DFS index and divider to
 * program into SE_GENI_CLK_SEL and GENI_SER_M_CLK_CFG.
 */
static TEE_Result geni_spi_resolve_clk(struct clk *se_clk, uint32_t speed_hz,
				       uint8_t *dfs_idx, uint32_t *clk_div)
{
	unsigned long rates[QUP_SPI_MAX_DFS_ROWS] = { };
	uint8_t indices[QUP_SPI_MAX_DFS_ROWS] = { };
	uint32_t best_sclk = 0;
	uint32_t best_div = 0;
	uint32_t best_src __maybe_unused = 0;
	size_t count = 0;
	size_t i = 0;
	bool found = false;
	TEE_Result res = TEE_SUCCESS;

	if (!se_clk || !speed_hz)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_clk_get_dfs_rates_array(se_clk, 0, NULL, NULL, &count);
	if (res)
		return res;
	if (!count)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (count > QUP_SPI_MAX_DFS_ROWS) {
		EMSG("QUP SPI: clock has %zu DFS rows, only %u inspected -- raise QUP_SPI_MAX_DFS_ROWS",
		     count, QUP_SPI_MAX_DFS_ROWS);
		count = QUP_SPI_MAX_DFS_ROWS;
	}

	res = qcom_clk_get_dfs_rates_array(se_clk, 0, rates, indices, &count);
	if (res)
		return res;

	for (i = 0; i < count; i++) {
		uint32_t src = rates[i];
		uint32_t div = 0;
		uint32_t sclk = 0;

		div = (src + speed_hz - 1) / speed_hz;
		if (div > CLK_DIV_MAX)
			continue;

		sclk = src / div;
		if (sclk > best_sclk) {
			best_sclk = sclk;
			best_div = div;
			best_src = src;
			*dfs_idx = indices[i];
			found = true;
		}
	}

	if (!found)
		return TEE_ERROR_ITEM_NOT_FOUND;

	*clk_div = best_div;

	DMSG("QUP SPI: speed=%u Hz -> src=%u Hz div=%u dfs_idx=%u sclk=%u Hz",
	     speed_hz, best_src, best_div, *dfs_idx, best_sclk);

	return TEE_SUCCESS;
}

static void qup_spi_configure(struct spi_chip *chip)
{
	struct qup_spi_data *qs = to_qup_spi(chip);
	uint32_t trans_cfg = 0;
	uint32_t demux_inv = 0;
	uint32_t val = 0;
	uint8_t dfs_idx = 0;
	uint32_t clk_div = 0;
	TEE_Result res = TEE_SUCCESS;

	qs->configured = false;

	if (!qs->speed_hz) {
		EMSG("QUP SPI %u: speed_hz not set", qs->id);
		return;
	}

	if (qs->bits_per_word != 8 && qs->bits_per_word != 16) {
		EMSG("QUP SPI %u: unsupported bits_per_word=%u (only 8 or 16)",
		     qs->id, qs->bits_per_word);
		return;
	}

	if (qs->cs > 3) {
		EMSG("QUP SPI %u: cs=%u out of range (0..3)", qs->id, qs->cs);
		return;
	}

	DMSG("QUP SPI %u: configure speed=%u Hz bpw=%u mode=%d cs=%u cs_high=%d loopback=%d",
	     qs->id, qs->speed_hz, qs->bits_per_word, qs->mode, qs->cs,
	     qs->cs_high, qs->loopback);

	if (qup_spi_clk_enable(qs))
		return;

	geni_get_fifo_depth_width(qs);

	if (qs->tx_fifo_depth < 4) {
		EMSG("QUP SPI %u: implausible tx_fifo_depth=%u from SE_HW_PARAM_0 (clock gated?)",
		     qs->id, qs->tx_fifo_depth);
		qup_spi_clk_disable(qs);
		return;
	}
	if (qs->rx_fifo_depth < 4) {
		EMSG("QUP SPI %u: implausible rx_fifo_depth=%u from SE_HW_PARAM_1 (clock gated?)",
		     qs->id, qs->rx_fifo_depth);
		qup_spi_clk_disable(qs);
		return;
	}
	io_write32(qs->base + SE_GENI_RX_WATERMARK_REG, qs->rx_fifo_depth - 3);
	io_write32(qs->base + SE_GENI_RX_RFR_WATERMARK_REG,
		   qs->rx_fifo_depth - 2);

	val = io_read32(qs->base + SE_GENI_DMA_MODE_EN);
	val &= ~GENI_DMA_MODE_EN;
	io_write32(qs->base + SE_GENI_DMA_MODE_EN, val);

	io_write32(qs->base + SE_SPI_LOOPBACK,
		   qs->loopback ? LOOPBACK_ENABLE : 0);
	io_write32(qs->base + SE_SPI_CPOL,
		   (qs->mode == SPI_MODE2 || qs->mode == SPI_MODE3) ?
		   CPOL : 0);
	io_write32(qs->base + SE_SPI_CPHA,
		   (qs->mode == SPI_MODE1 || qs->mode == SPI_MODE3) ?
		   CPHA : 0);

	io_write32(qs->base + SE_SPI_DEMUX_SEL, qs->cs);
	if (qs->cs_high)
		demux_inv = BIT32(qs->cs);
	io_write32(qs->base + SE_SPI_DEMUX_OUTPUT_INV, demux_inv);

	trans_cfg = io_read32(qs->base + SE_SPI_TRANS_CFG);
	trans_cfg &= ~CS_TOGGLE;
	io_write32(qs->base + SE_SPI_TRANS_CFG, trans_cfg);

	geni_config_packing(qs, qs->bits_per_word, 1);
	io_write32(qs->base + SE_SPI_WORD_LEN,
		   (qs->bits_per_word - MIN_WORD_LEN) & WORD_LEN_MSK);

	res = geni_spi_resolve_clk(qs->se_clk, qs->speed_hz, &dfs_idx,
				    &clk_div);
	if (res) {
		EMSG("QUP SPI: no DFS source rate for %u Hz: %#" PRIx32,
		     qs->speed_hz, res);
		qup_spi_clk_disable(qs);
		return;
	}

	io_write32(qs->base + SE_GENI_CLK_SEL, dfs_idx & CLK_SEL_MSK);
	io_write32(qs->base + GENI_SER_M_CLK_CFG,
		   ((clk_div << CLK_DIV_SHFT) & CLK_DIV_MSK) | SER_CLK_EN);
	io_write32(qs->base + SE_GENI_M_IRQ_EN, QUP_SPI_M_IRQ_EN_MASK);

	mutex_lock(&qs->lock);
	qs->tx_rem_bytes = 0;
	qs->rx_rem_bytes = 0;
	mutex_unlock(&qs->lock);
	qup_spi_clk_disable(qs);
	qs->configured = true;
}

/*
 * Fills the TX FIFO with whatever currently fits. Caller holds
 * qs->lock. Used both for the initial fill (before the first
 * watermark can possibly latch in M_IRQ_STATUS) and from
 * qup_spi_poll_m_cmd()'s watermark handling.
 */
static void qup_spi_fifo_fill_tx(struct qup_spi_data *qs)
{
	uint32_t tx_wc = io_read32(qs->base + SE_GENI_TX_FIFO_STATUS) &
			  TX_FIFO_WC_MSK;
	uint32_t tx_free_words = 0;

	if (qs->tx_fifo_depth > tx_wc)
		tx_free_words = qs->tx_fifo_depth - tx_wc;

	while (tx_free_words && qs->tx_rem_bytes) {
		uint32_t word = 0;
		unsigned int j = 0;

		for (j = 0; j < qs->bytes_per_word &&
		     qs->tx_rem_bytes; j++, qs->tx_rem_bytes--) {
		    uint8_t b = qs->tx_buf ? *qs->tx_buf++ : 0;
		    word |= (uint32_t)b << (8 * j);
		}
		io_write32(qs->base + SE_GENI_TX_FIFOn, word);
		tx_free_words--;
	}

	if (!qs->tx_rem_bytes)
		io_write32(qs->base + SE_GENI_TX_WATERMARK_REG, 0);
}

/*
 * Drains whatever is currently in the RX FIFO into qs->rx_buf. Used by
 * qup_spi_poll_m_cmd() below.
 */
static void qup_spi_fifo_drain_rx(struct qup_spi_data *qs)
{
	uint32_t rx_wc = io_read32(qs->base + SE_GENI_RX_FIFO_STATUS) &
			  RX_FIFO_WC_MSK;

	while (rx_wc && qs->rx_rem_bytes) {
		uint32_t word = io_read32(qs->base + SE_GENI_RX_FIFOn);
		unsigned int j = 0;

		for (j = 0; j < qs->bytes_per_word &&
		     qs->rx_rem_bytes; j++, qs->rx_rem_bytes--) {
			if (qs->rx_buf)
				*qs->rx_buf++ = (word >> (8 * j)) & 0xff;
		}
		rx_wc--;
	}
}

/*
 * Logs which specific command/FIFO error(s) are set in m_irq.
 */
static void qup_spi_log_errors(struct qup_spi_data *qs, uint32_t m_irq)
{
	if (m_irq & M_CMD_OVERRUN_EN)
		EMSG("QUP SPI %u: command overrun", qs->id);
	if (m_irq & M_ILLEGAL_CMD_EN)
		EMSG("QUP SPI %u: illegal command", qs->id);
	if (m_irq & M_CMD_FAILURE_EN)
		EMSG("QUP SPI %u: command failure", qs->id);
	if (m_irq & M_RX_FIFO_RD_ERR_EN)
		EMSG("QUP SPI %u: RX FIFO read error (underrun)", qs->id);
	if (m_irq & M_RX_FIFO_WR_ERR_EN)
		EMSG("QUP SPI %u: RX FIFO write error (overrun)", qs->id);
	if (m_irq & M_TX_FIFO_RD_ERR_EN)
		EMSG("QUP SPI %u: TX FIFO read error (underrun)", qs->id);
	if (m_irq & M_TX_FIFO_WR_ERR_EN)
		EMSG("QUP SPI %u: TX FIFO write error (overrun)", qs->id);
}

/*
 * Polling-mode replacement for waiting on an interrupt: polls
 * M_IRQ_STATUS directly from the calling thread until done_bit is
 * observed (with the transfer fully drained/filled too, when
 * check_rem_bytes is set -- only meaningful for M_CMD_DONE_EN on a
 * TX/RX transfer), a command/FIFO error is seen
 * (QUP_SPI_M_IRQ_ERR_MASK), or timeout_us elapses. Services any RX/TX
 * FIFO watermark and clears every bit it observes.
 */
static enum qup_spi_poll_result
qup_spi_poll_m_cmd(struct qup_spi_data *qs, uint32_t done_bit,
		    bool check_rem_bytes, unsigned int timeout_us)
{
	uint64_t timeout_ref = timeout_init_us(timeout_us);

	while (!timeout_elapsed(timeout_ref)) {
		uint32_t m_irq = io_read32(qs->base + SE_GENI_M_IRQ_STATUS);

		if (!m_irq)
			continue;

		if ((m_irq & M_RX_FIFO_WATERMARK_EN) ||
		    (m_irq & M_RX_FIFO_LAST_EN))
			qup_spi_fifo_drain_rx(qs);
		if (m_irq & M_TX_FIFO_WATERMARK_EN)
			qup_spi_fifo_fill_tx(qs);

		if (m_irq & QUP_SPI_M_IRQ_ERR_MASK) {
			qup_spi_log_errors(qs, m_irq);
			/* Stop feeding the TX FIFO for a dead transfer. */
			io_write32(qs->base + SE_GENI_TX_WATERMARK_REG, 0);
			io_write32(qs->base + SE_GENI_M_IRQ_CLEAR, m_irq);
			return QUP_SPI_POLL_ERROR;
		}

		io_write32(qs->base + SE_GENI_M_IRQ_CLEAR, m_irq);

		if (!(m_irq & done_bit))
			continue;
		if (check_rem_bytes && (qs->tx_rem_bytes || qs->rx_rem_bytes))
			continue;

		return QUP_SPI_POLL_DONE;
	}

	return QUP_SPI_POLL_TIMEOUT;
}

static void qup_spi_start(struct spi_chip *chip)
{
	struct qup_spi_data *qs = to_qup_spi(chip);

	qs->started = false;

	if (!qs->configured) {
		EMSG("QUP SPI %u: start() called before a successful configure()",
		     qs->id);
		return;
	}

	if (qup_spi_clk_enable(qs))
		return;

	if (qup_spi_pinctrl_setup(qs)) {
		qup_spi_clk_disable(qs);
		return;
	}

	FMSG("QUP SPI %u: start, asserting CS %u", qs->id, qs->cs);
	mutex_lock(&qs->lock);
	qs->tx_rem_bytes = 0;
	qs->rx_rem_bytes = 0;

	geni_setup_m_cmd(qs, SPI_CS_ASSERT, 0);
	if (qup_spi_poll_m_cmd(qs, M_CMD_DONE_EN, false,
			       QUP_SPI_M_CMD_TIMEOUT_US) != QUP_SPI_POLL_DONE) {
		EMSG("QUP SPI: CS assert failed");
		geni_cancel_and_abort_m_cmd(qs);
		mutex_unlock(&qs->lock);
		if (qs->pin_state) {
			tlmm_free_pin_state(qs->pin_state);
			qs->pin_state = NULL;
		}
		qup_spi_clk_disable(qs);
		return;
	}

	qs->started = true;
	mutex_unlock(&qs->lock);
}

static void qup_spi_end(struct spi_chip *chip)
{
	struct qup_spi_data *qs = to_qup_spi(chip);

	if (!qs->started) {
		EMSG("QUP SPI %u: end() called without a successful start()",
		     qs->id);
		return;
	}

	mutex_lock(&qs->lock);

	FMSG("QUP SPI %u: end, deasserting CS %u", qs->id, qs->cs);

	qs->tx_rem_bytes = 0;
	qs->rx_rem_bytes = 0;

	geni_setup_m_cmd(qs, SPI_CS_DEASSERT, 0);
	if (qup_spi_poll_m_cmd(qs, M_CMD_DONE_EN, false,
			       QUP_SPI_M_CMD_TIMEOUT_US) != QUP_SPI_POLL_DONE) {
		EMSG("QUP SPI: CS deassert failed");
		geni_cancel_and_abort_m_cmd(qs);
	}

	qs->started = false;
	mutex_unlock(&qs->lock);

	if (qs->pin_state) {
		tlmm_free_pin_state(qs->pin_state);
		qs->pin_state = NULL;
	}

	qup_spi_clk_disable(qs);
}

/*
 * Drains any leftover RX FIFO content and waits for the command engine to
 * go idle. Callable outside a start()/end() window, so it ungates the
 * clocks itself (refcounted, so nesting inside one is harmless).
 */
static void qup_spi_flushfifo(struct spi_chip *chip)
{
	struct qup_spi_data *qs = to_qup_spi(chip);
	uint64_t timeout_ref = 0;

	if (qup_spi_clk_enable(qs))
		return;

	timeout_ref = timeout_init_us(QUP_SPI_M_CMD_TIMEOUT_US);
	while (io_read32(qs->base + SE_GENI_RX_FIFO_STATUS) & RX_FIFO_WC_MSK) {
		io_read32(qs->base + SE_GENI_RX_FIFOn);
		if (timeout_elapsed(timeout_ref)) {
			EMSG("QUP SPI %u: flushfifo RX drain timed out", qs->id);
			qup_spi_clk_disable(qs);
			return;
		}
	}

	timeout_ref = timeout_init_us(QUP_SPI_M_CMD_TIMEOUT_US);
	while (io_read32(qs->base + SE_GENI_STATUS) &
	       GENI_STATUS_M_GENI_CMD_ACTIVE)
		if (timeout_elapsed(timeout_ref)) {
			EMSG("QUP SPI %u: flushfifo CMD_ACTIVE timed out",
			     qs->id);
			qup_spi_clk_disable(qs);
			return;
		}

	qup_spi_clk_disable(qs);
}

/*
 * QUP_SPI_M_CMD_TIMEOUT_US is sized for size-independent commands (CS
 * assert/deassert, cancel/abort). A data transfer instead needs a
 * deadline that scales with its size: num_pkts accepts up to
 * TRANS_LEN_MSK (0xffffff) words, and at bits_per_word=8/50 MHz that
 * alone is already ~2.7s, well past the fixed floor. Derive the
 * deadline from the resolved SCLK, word size and packet count, with a
 * 4x margin for FIFO-servicing latency and clock-divider rounding, and
 * never go below the fixed floor (data transfers this small are
 * dominated by that same FIFO/CS latency, not by transfer time).
 */
static uint32_t qup_spi_txrx_timeout_us(struct qup_spi_data *qs,
					size_t num_pkts)
{
	uint64_t bits = (uint64_t)num_pkts * qs->bits_per_word;
	uint64_t timeout_us = 0;

	if (!qs->speed_hz)
		return QUP_SPI_M_CMD_TIMEOUT_US;

	timeout_us = (bits * 4 * 1000000) / qs->speed_hz;

	if (timeout_us < QUP_SPI_M_CMD_TIMEOUT_US)
		return QUP_SPI_M_CMD_TIMEOUT_US;
	if (timeout_us > UINT32_MAX)
		return UINT32_MAX;

	return (uint32_t)timeout_us;
}

static enum spi_result qup_spi_txrx(struct qup_spi_data *qs,
				     const uint8_t *wdat, uint8_t *rdat,
				     size_t num_pkts,
				     unsigned int bytes_per_word)
{
	size_t total_bytes = num_pkts * bytes_per_word;
	enum qup_spi_poll_result poll_res = QUP_SPI_POLL_TIMEOUT;
	uint32_t timeout_us = qup_spi_txrx_timeout_us(qs, num_pkts);

	FMSG("QUP SPI %u: txrx num_pkts=%zu bpw=%u total=%zu tx=%d rx=%d",
	     qs->id, num_pkts, bytes_per_word, total_bytes, !!wdat, !!rdat);

	if (!wdat && !rdat) {
		EMSG("QUP SPI %u: txrx() with neither a TX nor an RX buffer",
		     qs->id);
		return SPI_ERR_CFG;
	}

	if (!num_pkts || num_pkts > TRANS_LEN_MSK) {
		EMSG("QUP SPI %u: num_pkts=%zu out of range (1..%u)", qs->id,
		     num_pkts, (unsigned int)TRANS_LEN_MSK);
		return SPI_ERR_PKTCNT;
	}

	mutex_lock(&qs->lock);
	if (!qs->started) {
		EMSG("QUP SPI %u: txrx() called without a successful start()",
		     qs->id);
		mutex_unlock(&qs->lock);
		return SPI_ERR_CFG;
	}

	io_write32(qs->base + SE_SPI_TX_TRANS_LEN, wdat ? num_pkts : 0);
	io_write32(qs->base + SE_SPI_RX_TRANS_LEN, rdat ? num_pkts : 0);

	qs->tx_buf = wdat;
	qs->rx_buf = rdat;
	qs->tx_rem_bytes = wdat ? total_bytes : 0;
	qs->rx_rem_bytes = rdat ? total_bytes : 0;
	qs->bytes_per_word = bytes_per_word;

	geni_setup_m_cmd(qs, (wdat ? SPI_TX_ONLY : 0) | (rdat ? SPI_RX_ONLY : 0),
			  0);
	if (qs->tx_rem_bytes) {
		io_write32(qs->base + SE_GENI_TX_WATERMARK_REG, 1);
		qup_spi_fifo_fill_tx(qs);
	}

	poll_res = qup_spi_poll_m_cmd(qs, M_CMD_DONE_EN, true, timeout_us);
	if (poll_res != QUP_SPI_POLL_DONE) {
		EMSG("QUP SPI %u: transfer %s", qs->id,
		     poll_res == QUP_SPI_POLL_TIMEOUT ? "timed out" : "failed");

		if (poll_res == QUP_SPI_POLL_TIMEOUT ||
		    (io_read32(qs->base + SE_GENI_STATUS) &
		     GENI_STATUS_M_GENI_CMD_ACTIVE))
			geni_cancel_and_abort_m_cmd(qs);

		mutex_unlock(&qs->lock);

		return SPI_ERR_GENERIC;
	}

	if (qs->tx_rem_bytes || qs->rx_rem_bytes) {
		EMSG("QUP SPI %u: short transfer, tx_rem=%zu rx_rem=%zu",
		     qs->id, qs->tx_rem_bytes, qs->rx_rem_bytes);
		mutex_unlock(&qs->lock);

		return SPI_ERR_PKTCNT;
	}

	mutex_unlock(&qs->lock);

	return SPI_OK;
}

static enum spi_result qup_spi_txrx8(struct spi_chip *chip, uint8_t *wdat,
				      uint8_t *rdat, size_t num_pkts)
{
	struct qup_spi_data *qs = to_qup_spi(chip);

	if (qs->bits_per_word != 8) {
		EMSG("QUP SPI %u: txrx8() with bits_per_word=%u (use txrx16())",
		     qs->id, qs->bits_per_word);
		return SPI_ERR_CFG;
	}

	return qup_spi_txrx(qs, wdat, rdat, num_pkts, 1);
}

static enum spi_result qup_spi_txrx16(struct spi_chip *chip, uint16_t *wdat,
				       uint16_t *rdat, size_t num_pkts)
{
	struct qup_spi_data *qs = to_qup_spi(chip);

	if (qs->bits_per_word != 16) {
		EMSG("QUP SPI %u: txrx16() with bits_per_word=%u (use txrx8())",
		     qs->id, qs->bits_per_word);
		return SPI_ERR_CFG;
	}

	return qup_spi_txrx(qs, (const uint8_t *)wdat, (uint8_t *)rdat,
			     num_pkts, 2);
}

static const struct spi_ops qup_spi_ops = {
	.configure = qup_spi_configure,
	.start = qup_spi_start,
	.txrx8 = qup_spi_txrx8,
	.txrx16 = qup_spi_txrx16,
	.end = qup_spi_end,
	.flushfifo = qup_spi_flushfifo,
};

/*
 * Acquire the SE source clock plus the wrapper/common clocks by name and
 * program the SE clock to the platform source rate. All left gated;
 * qup_spi_clk_enable() ungates them before a transfer. This platform has
 * no secure DT, so clocks are resolved via qcom_clk_get_by_name().
 */
static TEE_Result qup_spi_clk_setup(struct qup_spi_data *qs)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;

	if (!qs->se_clock_name) {
		EMSG("QUP SPI: no se clock name for SE %u", qs->id);
		return TEE_ERROR_BAD_STATE;
	}

	res = qcom_clk_get_by_name(qs->se_clock_name, &qs->se_clk);
	if (res) {
		EMSG("QUP SPI: cannot get clock %s: %#" PRIx32,
		     qs->se_clock_name, res);
		return res;
	}

	res = qcom_clk_enable_dfs(qs->se_clk);
	if (res) {
		EMSG("QUP SPI: enable DFS on %s failed: %#" PRIx32,
		     qs->se_clock_name, res);
		qs->se_clk = NULL;
		return res;
	}

	qs->num_common_clks = 0;
	if (!qs->common_clocks_name)
		return TEE_SUCCESS;

	for (i = 0; qs->common_clocks_name[i]; i++) {
		if (i >= QUP_SPI_MAX_COMMON_CLKS) {
			EMSG("QUP SPI: too many common clocks (max %d)",
			     QUP_SPI_MAX_COMMON_CLKS);
			return TEE_ERROR_BAD_STATE;
		}

		res = qcom_clk_get_by_name(qs->common_clocks_name[i],
					   &qs->common_clks[i]);
		if (res) {
			EMSG("QUP SPI: cannot get clock %s: %#" PRIx32,
			     qs->common_clocks_name[i], res);
			return res;
		}
		qs->num_common_clks++;
	}

	return TEE_SUCCESS;
}

/*
 * Ungate the wrapper/common clocks first, then the SE source clock,
 * ahead of a transfer. Unwinds anything already enabled on failure so
 * the enable/disable refcounts stay balanced.
 */
static TEE_Result qup_spi_clk_enable(struct qup_spi_data *qs)
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int i = 0;

	for (i = 0; i < qs->num_common_clks; i++) {
		res = clk_enable(qs->common_clks[i]);
		if (res) {
			EMSG("QUP SPI: clk_enable(%s) failed: %#" PRIx32,
			     qs->common_clocks_name[i], res);
			goto err;
		}
	}

	if (!qs->se_clk) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}

	res = clk_enable(qs->se_clk);
	if (res) {
		EMSG("QUP SPI: clk_enable(%s) failed: %#" PRIx32,
		     qs->se_clock_name, res);
		goto err;
	}

	return TEE_SUCCESS;

err:
	while (i-- > 0)
		clk_disable(qs->common_clks[i]);

	return res;
}

/* Gate the SE source clock, then the wrapper/common clocks, once idle. */
static void qup_spi_clk_disable(struct qup_spi_data *qs)
{
	unsigned int i = qs->num_common_clks;

	if (qs->se_clk)
		clk_disable(qs->se_clk);

	while (i-- > 0)
		clk_disable(qs->common_clks[i]);
}

static TEE_Result qup_spi_pinctrl_setup(struct qup_spi_data *qs)
{
	TEE_Result res = TEE_SUCCESS;

	if (qs->pin_state)
		return TEE_SUCCESS;

	if (!qs->pin_groups || !qs->pin_group_count) {
		DMSG("QUP SPI %u: no pin_groups, skipping pinmux", qs->id);
		return TEE_SUCCESS;
	}

	res = tlmm_make_pin_state(qs->pin_groups, qs->pin_group_count,
				  &qs->pin_state);
	if (res) {
		EMSG("QUP SPI: tlmm_make_pin_state failed: %#" PRIx32, res);
		return res;
	}

	res = tlmm_apply_pin_state(qs->pin_state);
	if (res) {
		EMSG("QUP SPI: tlmm_apply_pin_state failed: %#" PRIx32, res);
		tlmm_free_pin_state(qs->pin_state);
		qs->pin_state = NULL;
		return res;
	}

	IMSG("QUP SPI %u: applied %u pin group(s)", qs->id,
	     qs->pin_group_count);

	return TEE_SUCCESS;
}

/* True if this SE's GENI firmware is already loaded (e.g. by an earlier
 * boot stage), identified by GENI_FW_REVISION_RO already reporting the SPI
 * protocol.
 */
static bool qup_spi_fw_already_loaded(struct qup_spi_data *qs)
{
	uint32_t protocol = io_read32(qs->base + GENI_FW_REVISION_RO) >>
			     FW_REV_PROTOCOL_SHFT;

	return protocol == QUP_FW_SERIAL_PROTOCOL_SPI;
}

/*
 * Validates that hdr's magic/version/protocol match this image, and that
 * its three sub-array offsets and item counts all stay within
 * qs->fw_image_size, mirroring u-boot qcom_geni.c's valid_seg_size().
 */
static bool qup_spi_fw_hdr_valid(struct qup_spi_data *qs,
				  const struct elf_se_hdr *hdr)
{
	if (hdr->magic != QUP_FW_MAGIC || hdr->version != QUP_FW_HDR_VERSION ||
	    hdr->serial_protocol != QUP_FW_SERIAL_PROTOCOL_SPI) {
		EMSG("QUP SPI %u: bad fw header: magic=%#" PRIx32 " version=%" PRIu32 " protocol=%u",
		     qs->id, hdr->magic, hdr->version,
		     (unsigned int)hdr->serial_protocol);
		return false;
	}

	if (qs->fw_image_size < hdr->fw_offset +
	    hdr->fw_size_in_items * sizeof(uint32_t) ||
	    qs->fw_image_size < hdr->cfg_val_offset +
	    hdr->cfg_size_in_items * sizeof(uint32_t) ||
	    qs->fw_image_size < hdr->cfg_idx_offset +
	    hdr->cfg_size_in_items * sizeof(uint8_t)) {
		EMSG("QUP SPI %u: fw image too small for header's offsets/sizes",
		     qs->id);
		return false;
	}

	return true;
}

/*
 * Loads qs->fw_image into the SE's GENI RAM and programs its config
 * register table, following u-boot qcom_geni.c's load_se_firmware() (the
 * verified reference for this GENI SE generation). Runs once per qs: gated
 * by qs->fw_loaded, and a no-op if an earlier boot stage already loaded the
 * firmware or if this SE has no fw_image configured.
 */
static TEE_Result qup_spi_load_fw(struct qup_spi_data *qs)
{
	struct elf_se_hdr hdr = { };
	const uint8_t *fw_val_base = NULL;
	const uint8_t *cfg_val_base = NULL;
	const uint8_t *cfg_idx_arr = NULL;
	uint32_t reg_value = 0;
	uint32_t rx_fifo_width = 0;
	unsigned int i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (qs->fw_loaded)
		return TEE_SUCCESS;

	if (!qs->fw_image) {
		DMSG("QUP SPI %u: no fw_image configured, skipping fw load",
		     qs->id);
		qs->fw_loaded = true;
		return TEE_SUCCESS;
	}

	res = qup_spi_clk_enable(qs);
	if (res)
		return res;

	if (qup_spi_fw_already_loaded(qs)) {
		DMSG("QUP SPI %u: fw already loaded", qs->id);
		qs->fw_loaded = true;
		qup_spi_clk_disable(qs);
		return TEE_SUCCESS;
	}

	if (qs->fw_image_size < sizeof(hdr)) {
		EMSG("QUP SPI %u: fw image smaller than its header", qs->id);
		qup_spi_clk_disable(qs);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	memcpy(&hdr, qs->fw_image, sizeof(hdr));

	if (!qup_spi_fw_hdr_valid(qs, &hdr)) {
		qup_spi_clk_disable(qs);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	fw_val_base = qs->fw_image + hdr.fw_offset;
	cfg_idx_arr = qs->fw_image + hdr.cfg_idx_offset;
	cfg_val_base = qs->fw_image + hdr.cfg_val_offset;

	io_setbits32(qs->common_base + QUPV3_COMMON_CFG,
		     FAST_SWITCH_TO_HIGH_DISABLE);
	io_setbits32(qs->common_base + QUPV3_SE_AHB_M_CFG, AHB_M_CLK_CGC_ON);
	io_setbits32(qs->common_base + QUPV3_COMMON_CGC_CTRL,
		     COMMON_CSR_SLV_CLK_CGC_ON);

	io_write32(qs->base + GENI_OUTPUT_CTRL, 0x0);
	io_setbits32(qs->base + GENI_CGC_CTRL, GENI_CGC_CTRL_PROG_RAM_MSK);
	io_write32(qs->base + SE_GENI_CLK_CTRL, 0x0);
	io_clrbits32(qs->base + GENI_CGC_CTRL, GENI_CGC_CTRL_PROG_RAM_MSK);
	io_setbits32(qs->base + SE_DMA_GENERAL_CFG,
		     SE_DMA_GENERAL_CFG_CGC_ON_MSK);

	io_write32(qs->base + GENI_CGC_CTRL, GENI_CGC_CTRL_DEFAULT_EN_MSK);
	io_write32(qs->base + GENI_INIT_CFG_REVISION, hdr.cfg_version);
	io_write32(qs->base + GENI_S_INIT_CFG_REVISION, hdr.cfg_version);

	for (i = 0; i < hdr.cfg_size_in_items; i++) {
		uint32_t cfg_val = 0;

		memcpy(&cfg_val, cfg_val_base + i * sizeof(cfg_val),
		       sizeof(cfg_val));
		io_write32(qs->base + GENI_CFG_REG0 +
			   cfg_idx_arr[i] * sizeof(uint32_t), cfg_val);
	}

	rx_fifo_width = (io_read32(qs->base + SE_HW_PARAM_1) &
			  RX_FIFO_WIDTH_MSK) >> RX_FIFO_WIDTH_SHFT;
	if (rx_fifo_width >= 2)
		io_write32(qs->base + SE_GENI_RX_RFR_WATERMARK_REG,
			   rx_fifo_width - 2);
	else
		EMSG("QUP SPI %u: implausible rx_fifo_width=%" PRIu32 ", leaving RFR watermark at default",
		     qs->id, rx_fifo_width);

	io_setbits32(qs->base + GENI_OUTPUT_CTRL, 0x7f);
	io_clrbits32(qs->base + SE_GENI_DMA_MODE_EN, GENI_DMA_MODE_EN);
	io_write32(qs->base + SE_IRQ_EN, SE_IRQ_EN_MSK);
	io_write32(qs->base + SE_GSI_EVENT_EN, 0x0);

	io_write32(qs->base + SE_GENI_M_IRQ_EN, QUP_SPI_M_IRQ_EN_MASK);
	reg_value = S_CMD_OVERRUN_EN | S_ILLEGAL_CMD_EN | S_CMD_CANCEL_EN |
		    S_CMD_ABORT_EN | S_GP_IRQ_0_EN | S_GP_IRQ_1_EN |
		    S_GP_IRQ_2_EN | S_GP_IRQ_3_EN | S_RX_FIFO_WR_ERR_EN |
		    S_RX_FIFO_RD_ERR_EN;
	io_write32(qs->base + SE_GENI_S_IRQ_EN, reg_value);
	io_write32(qs->base + SE_DMA_TX_IRQ_EN_SET,
		   DMA_TX_RESET_DONE_EN_SET | DMA_TX_SBE_EN_SET |
		   DMA_TX_DMA_DONE_EN_SET);
	io_write32(qs->base + SE_DMA_RX_IRQ_EN_SET,
		   DMA_RX_FLUSH_DONE_EN_SET | DMA_RX_RESET_DONE_EN_SET |
		   DMA_RX_SBE_EN_SET | DMA_RX_DMA_DONE_EN_SET);

	reg_value = (hdr.serial_protocol << FW_REV_PROTOCOL_SHFT) |
		    (hdr.fw_version & 0xff);
	io_write32(qs->base + SE_GENI_FW_REVISION, reg_value);
	io_write32(qs->base + SE_S_FW_REVISION, reg_value);

	for (i = 0; i < hdr.fw_size_in_items; i++) {
		uint32_t fw_val = 0;

		memcpy(&fw_val, fw_val_base + i * sizeof(fw_val),
		       sizeof(fw_val));
		io_write32(qs->base + SE_GENI_CFG_RAMN + i * sizeof(uint32_t),
			   fw_val);
	}

	io_write32(qs->base + SE_GENI_DFS_IF_CFG, SER_DFS_EN);
	io_write32(qs->base + GENI_FORCE_DEFAULT_REG, 0x1);

	io_setbits32(qs->base + GENI_CGC_CTRL, GENI_CGC_CTRL_PROG_RAM_MSK);
	io_setbits32(qs->base + SE_GENI_CLK_CTRL, GENI_CLK_CTRL_SER_CLK_SEL);
	io_clrbits32(qs->base + GENI_CGC_CTRL, GENI_CGC_CTRL_PROG_RAM_MSK);

	io_setbits32(qs->base + SE_DMA_IF_EN, DMA_IF_EN_DMA_IF_EN);
	io_clrbits32(qs->base + SE_FIFO_IF_DISABLE, FIFO_IF_DISABLE);

	qup_spi_clk_disable(qs);

	qs->fw_loaded = true;
	IMSG("QUP SPI %u: fw loaded (protocol=%u fw_version=%#x cfg_version=%#x)",
	     qs->id, (unsigned int)hdr.serial_protocol,
	     (unsigned int)hdr.fw_version, (unsigned int)hdr.cfg_version);

	return TEE_SUCCESS;
}

bool qup_spi_get_platform_data(unsigned int qup_spi_id,
				struct qup_spi_data *qs)
{
	size_t i = 0;

	for (i = 0; i < qup_spi_config_count; i++) {
		if (qup_spi_config[i].id != qup_spi_id)
			continue;

		qs->base = (vaddr_t)phys_to_virt(qup_spi_config[i].base,
						  MEM_AREA_IO_SEC,
						  QUP_SPI_REG_SIZE);
		if (!qs->base) {
			EMSG("QUP SPI: failed to map SE %u regs at %#" PRIxPA,
			     qup_spi_id, qup_spi_config[i].base);
			return false;
		}

		qs->common_base = (vaddr_t)phys_to_virt(qup_spi_config[i].common_base,
							 MEM_AREA_IO_SEC,
							 QUP_SPI_COMMON_REG_SIZE);
		if (!qs->common_base) {
			EMSG("QUP SPI: failed to map SE %u wrapper-common regs at %#" PRIxPA,
			     qup_spi_id, qup_spi_config[i].common_base);
			return false;
		}

		qs->itr_num = qup_spi_config[i].itr_num;
		qs->clk_hz = qup_spi_config[i].clk_hz;
		qs->se_clock_name = qup_spi_config[i].se_clock_name;
		qs->common_clocks_name = qup_spi_config[i].common_clocks_name;
		qs->pin_groups = qup_spi_config[i].pin_groups;
		qs->pin_group_count = qup_spi_config[i].pin_group_count;
		qs->fw_image = qup_spi_config[i].fw_image;
		qs->fw_image_size = qup_spi_config[i].fw_image_size;
		DMSG("QUP SPI %u: base=%#" PRIxVA " irq=%zu se_clk=%s",
		     qup_spi_id, qs->base, qs->itr_num, qs->se_clock_name);
		return true;
	}

	EMSG("QUP SPI: no platform data for SE id %u", qup_spi_id);
	return false;
}

TEE_Result qup_spi_init(struct qup_spi_data *qs, unsigned int qup_spi_id)
{
	TEE_Result res = TEE_SUCCESS;

	assert(qs);
	qs->id = qup_spi_id;

	/*
	 * Internal/derived state (as opposed to the caller-owned config
	 * documented in struct qup_spi_data) is not something a caller is
	 * expected to set, so it may still hold whatever garbage was on
	 * the stack/heap if *qs was not zero-initialized. Reset it here
	 * rather than trusting that, so fw_loaded/configured/started never
	 * start out true and pin_state is never a garbage pointer later
	 * passed to tlmm_free_pin_state().
	 */
	qs->se_clk = NULL;
	qs->num_common_clks = 0;
	qs->pin_state = NULL;
	qs->fw_loaded = false;
	qs->configured = false;
	qs->started = false;
	qs->tx_buf = NULL;
	qs->rx_buf = NULL;
	qs->tx_rem_bytes = 0;
	qs->rx_rem_bytes = 0;
	qs->bytes_per_word = 0;

	if (!qup_spi_get_platform_data(qup_spi_id, qs))
		return TEE_ERROR_ITEM_NOT_FOUND;

	qs->chip.ops = &qup_spi_ops;
	mutex_init(&qs->lock);

	res = qup_spi_clk_setup(qs);
	if (res)
		return res;

	res = qup_spi_load_fw(qs);
	if (res)
		return res;

	IMSG("QUP SPI %u: initialized (irq %zu)", qs->id, qs->itr_num);

	return TEE_SUCCESS;
}

void qup_spi_set_loopback(struct qup_spi_data *qs, bool enable)
{
	assert(qs);

	qs->loopback = enable;
	DMSG("QUP SPI %u: loopback %s (applied on next configure)",
	     qs->id, enable ? "enabled" : "disabled");
}
