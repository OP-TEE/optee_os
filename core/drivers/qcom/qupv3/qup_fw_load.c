// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * QUPv3 Serial Engine firmware loader.
 *
 * The boot chain authenticates the QUP FW ELF and loads its segments to DDR
 * (flashless). Only the ELF + program headers are kept in the OP-TEE image;
 * each PT_LOAD segment's paddr points at a SE FW image in DDR. For every SE
 * marked for loading in the platform permission table, the best matching FW
 * for its protocol is copied into the SE's FW RAM and the SE is initialized,
 * following tzbsp_qupv3_bring_up() in TZ. The GSI ("QSI ") segment, if
 * present, is then loaded into each wrapper's GSI as gpi_firmware_load() does.
 */

#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <drivers/qcom/qup_fw_load.h>
#include <initcall.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>
#include <util.h>

/* QUPV3 common (wrapper) registers */
#define QUPV3_HW_VERSION		0x004
#define QUPV3_SE_AHB_M_CFG		0x118
#define QUPV3_COMMON_CFG		0x120
#define QUPV3_COMMON_CGC_CTRL		0x21c

/* SE GENI registers */
#define GENI_INIT_CFG_REVISION		0x000
#define GENI_S_INIT_CFG_REVISION	0x004
#define GENI_FORCE_DEFAULT_REG		0x020
#define GENI_OUTPUT_CTRL		0x024
#define GENI_CGC_CTRL			0x028
#define GENI_FW_REVISION_RO		0x068
#define GENI_DFS_IF_CFG			0x080
#define GENI_CFG_REG(n)			(0x100 + (n) * 4)
#define GENI_CFG_REG42			0x228
#define GENI_CFG_REG48			0x240
#define GENI_DMA_MODE_EN		0x258
#define GENI_CFG_REG55			0x25c
#define GENI_CFG_REG58			0x268
#define GENI_M_IRQ_EN			0x614
#define GENI_S_IRQ_EN			0x644
#define GENI_RX_RFR_WATERMARK		0x814
#define SE_DMA_TX_IRQ_EN_SET		0xc4c
#define SE_DMA_RX_IRQ_EN_SET		0xd4c
#define SE_GSI_EVENT_EN			0xe18
#define SE_IRQ_EN			0xe1c
#define SE_HW_PARAM_1			0xe28
#define SE_DMA_GENERAL_CFG		0xe30
#define GENI_FW_REVISION		0x1000
#define GENI_S_FW_REVISION		0x1004
#define GENI_FW_RAM(n)			(0x1010 + (n) * 4)
#define GENI_CLK_CTRL			0x2000
#define GENI_DMA_IF_EN			0x2004
#define GENI_FIFO_IF_DISABLE		0x2008
#define GENI_MULTILOCK_PROTNS		0x200c
#define GENI_DFS_IF_EN			0x2050

#define CGC_CTRL_PROG_RAM_CLK		GENMASK_32(9, 8)
#define CFG_REG48_QSPI_MASK		GENMASK_32(9, 8)
#define CFG_REG58_I2C_MM_MASK		GENMASK_32(9, 0)
#define HW_PARAM_1_RX_FIFO_DEPTH(v)	(((v) >> 16) & 0xff)

#define M_IRQ_EN_DEFAULT		0x33c0007e
#define S_IRQ_EN_DEFAULT		0x03001e36
#define DMA_TX_IRQ_EN_DEFAULT		0xd
#define DMA_RX_IRQ_EN_DEFAULT		0x1d
#define SE_IRQ_EN_ALL			0xf
#define SE_GSI_EVENT_EN_ALL		0xf
#define OUTPUT_CTRL_ALL			0x7f
#define CGC_CTRL_ALL			0x7f
#define DMA_GENERAL_CFG_ALL		0xf

/* HW revision from which DMA_GENERAL_CFG/CGC_CTRL need explicit setup */
#define QUPV3_HW_VER_1_1		0x10010000

#define QUPV3_SE_SIZE			0x4000

/* SE firmware segment header */
#define SEFW_MAGIC			0x57464553	/* "SEFW" */
#define SEFW_VERSION			1
#define QSI_MAGIC			0x20495351	/* "QSI " (GSI FW) */

struct sefw_hdr {
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

/* GSI registers, offsets from the wrapper's GSI top */
#define GSI_CFG				0x0000
#define GSI_MANAGER_MCS_CODE_VER	0x0008
#define GSI_CGC_CTRL			0x0060
#define GSI_MCS_CFG			0xb000
#define GSI_TZ_FW_AUTH_LOCK		0xb008
#define GSI_EE0_GENERIC_CMD		0xf018
#define GSI_EE0_CNTXT_SCRATCH_0		0xf400
#define GSI_INST_RAM(n)			(0x4c000 + (n) * 4)
#define GSI_INST_RAM_WORDS		6144

#define GSI_CFG_GSI_ENABLE		BIT(0)
#define GSI_CFG_DOUBLE_MCS_CLK_FREQ	BIT(2)
#define GSI_CGC_CTRL_REGION_2_HW_CGC_EN	BIT(1)
#define GSI_MCS_CFG_MCS_ENABLE		BIT(0)
#define GSI_AUTH_LOCK_DIS_IRAM_WRITE	BIT(0)
#define GSI_AUTH_LOCK_DIS_SHRAM_WRITE	BIT(1)
#define GSI_GENERIC_CMD_FW_READY	0x81

#define GSI_FW_READY_POLL_US		5
#define GSI_FW_READY_TIMEOUT_US		10000

#define QUPV3_HW_VER_MAJOR(v)		(((v) >> 28) & 0xf)
#define QUPV3_HW_VER_MINOR(v)		(((v) >> 16) & 0xfff)

/* GSI firmware segment header, followed by IEP and IRAM entries */
struct gsi_fw_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t core_version;
	uint32_t fw_version;
	uint16_t fw_size_in_items;	/* IRAM lines, 8 bytes each */
	uint16_t fw_offset;
	uint16_t iep_size_in_items;	/* {offset, value} pairs */
	uint16_t iep_offset;
};

#define GSI_FW_LINE_SIZE		8
#define GSI_FW_IEP_SIZE			8

/* Minimal ELF32 definitions, the header blob is read with memcpy() */
#define ELF_PT_LOAD			1

struct elf32_ehdr {
	uint8_t e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct elf32_phdr {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
};

/* Qualcomm MBN segment attributes encoded in p_flags */
#define SEG_PAGE_MODE(f)		(((f) & 0x00100000) >> 20)
#define SEG_ACCESS_TYPE(f)		(((f) & 0x00e00000) >> 21)
#define SEG_TYPE(f)			(((f) & 0x07000000) >> 24)
#define SEG_PAGE_MODE_NON_PAGED		0
#define SEG_TYPE_HASH			2
#define SEG_ACCESS_NOTUSED		3
#define SEG_ACCESS_SHARED		4

/* FW slots, one per distinct firmware image (UART_2W/4W share one, etc.) */
enum qupv3_fw_idx {
	FW_IDX_NONE,
	FW_IDX_SPI,
	FW_IDX_UART,
	FW_IDX_I2C,
	FW_IDX_I3C,
	FW_IDX_SPI_SLAVE,
	FW_IDX_AFC,
	FW_IDX_I3C_IBI,
	FW_IDX_SPMI,
	FW_IDX_QSPI,
	FW_IDX_UFCS,
	FW_IDX_Q2SPI,
	FW_IDX_DB_UART,
	FW_IDX_SPI_3W_4W,
	FW_IDX_MAX,
};

struct qupv3_fw_seg {
	vaddr_t va;
	uint32_t size;
	uint32_t core_version;
};

struct qupv3_fw_ctx {
	const struct qupv3_fw_platform *plat;
	vaddr_t ddr_va;
	uint32_t hw_ver;
	struct qupv3_fw_seg fw[FW_IDX_MAX];
	struct qupv3_fw_seg gsi;
};

static enum qupv3_fw_idx protocol_to_idx(uint32_t protocol)
{
	switch (protocol) {
	case QUPV3_PROTOCOL_SPI:
		return FW_IDX_SPI;
	case QUPV3_PROTOCOL_UART_2W:
	case QUPV3_PROTOCOL_UART_4W:
		return FW_IDX_UART;
	case QUPV3_PROTOCOL_I2C:
	case QUPV3_PROTOCOL_I2C_MM:
		return FW_IDX_I2C;
	case QUPV3_PROTOCOL_I3C:
		return FW_IDX_I3C;
	case QUPV3_PROTOCOL_SPI_SLAVE:
		return FW_IDX_SPI_SLAVE;
	case QUPV3_PROTOCOL_AFC:
		return FW_IDX_AFC;
	case QUPV3_PROTOCOL_I3C_IBI:
		return FW_IDX_I3C_IBI;
	case QUPV3_PROTOCOL_SPMI:
		return FW_IDX_SPMI;
	case QUPV3_PROTOCOL_QSPI:
	case QUPV3_PROTOCOL_QSPI_HID:
		return FW_IDX_QSPI;
	case QUPV3_PROTOCOL_UFCS:
		return FW_IDX_UFCS;
	case QUPV3_PROTOCOL_Q2SPI:
		return FW_IDX_Q2SPI;
	case QUPV3_PROTOCOL_DB_UART:
		return FW_IDX_DB_UART;
	case QUPV3_PROTOCOL_SPI_3W_4W:
		return FW_IDX_SPI_3W_4W;
	default:
		return FW_IDX_NONE;
	}
}

static bool is_uart_like(enum qupv3_protocol p)
{
	return p == QUPV3_PROTOCOL_UART_2W || p == QUPV3_PROTOCOL_UART_4W ||
	       p == QUPV3_PROTOCOL_UFCS;
}

static vaddr_t se_va(const struct qupv3_se_hw *se)
{
	vaddr_t va = (vaddr_t)phys_to_virt(se->base, MEM_AREA_IO_SEC,
					   QUPV3_SE_SIZE);

	if (!va)
		panic("QUPv3 SE not mapped");
	return va;
}

static vaddr_t common_va(const struct qupv3_common_hw *c)
{
	vaddr_t va = (vaddr_t)phys_to_virt(c->base, MEM_AREA_IO_SEC,
					   SMALL_PAGE_SIZE);

	if (!va)
		panic("QUPv3 common not mapped");
	return va;
}

/* Translate a FW DDR physical range into the temporary mapping */
static vaddr_t fw_pa_to_va(struct qupv3_fw_ctx *ctx, paddr_t pa, size_t len)
{
	const struct qupv3_fw_platform *plat = ctx->plat;
	paddr_t end = 0;
	paddr_t window_end = 0;

	if (ADD_OVERFLOW(plat->fw_ddr_base, plat->fw_ddr_size, &window_end) ||
	    ADD_OVERFLOW(pa, len, &end) || pa < plat->fw_ddr_base ||
	    end > window_end)
		return 0;

	return ctx->ddr_va + (pa - plat->fw_ddr_base);
}

/*
 * Every clock named by the QUP data is mandatory: accessing the hardware
 * without its vote would make a failed configuration look like a successful
 * FW load.
 */
struct qupv3_clk_state {
	struct clk *clk;
	bool enabled;
};

static TEE_Result qupv3_clk_get(const char *name, struct clk **clk)
{
	TEE_Result res = TEE_SUCCESS;

	if (!name || !clk)
		return TEE_ERROR_BAD_PARAMETERS;

	res = qcom_clk_get_by_name(name, clk);
	if (res)
		EMSG("QUPv3: cannot get clock %s: %#"PRIx32, name, res);

	return res;
}

/* Record only a vote this loader acquired, never release another owner's. */
static TEE_Result qupv3_clk_on(struct clk *clk, bool *enabled)
{
	TEE_Result res = TEE_SUCCESS;

	if (!clk || !enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	*enabled = false;
	if (clk_is_enabled(clk))
		return TEE_SUCCESS;

	res = clk_enable(clk);
	if (res) {
		EMSG("QUPv3: failed to enable %s: %#"PRIx32,
		     clk_get_name(clk), res);
		return res;
	}

	*enabled = true;
	return TEE_SUCCESS;
}

static void qupv3_clk_off(struct clk *clk, bool enabled)
{
	if (clk && enabled)
		clk_disable(clk);
}

static size_t common_clk_count(const struct qupv3_fw_platform *plat)
{
	size_t count = 0;
	size_t n = 0;

	for (n = 0; n < plat->num_common; n++)
		count += plat->common[n].num_clks;

	return count;
}

static void common_clks_disable(struct qupv3_clk_state *clks, size_t count)
{
	while (count--) {
		qupv3_clk_off(clks[count].clk, clks[count].enabled);
		clks[count].enabled = false;
	}
}

/* Enable wrapper dependencies in declaration order, unwind in reverse order. */
static TEE_Result common_clks_enable(const struct qupv3_fw_platform *plat,
				     struct qupv3_clk_state *clks, size_t max)
{
	size_t n = 0;
	size_t i = 0;
	size_t count = 0;
	TEE_Result res = TEE_SUCCESS;

	if (common_clk_count(plat) > max)
		return TEE_ERROR_BAD_STATE;

	for (n = 0; n < plat->num_common; n++) {
		const struct qupv3_common_hw *common = plat->common + n;

		for (i = 0; i < common->num_clks; i++, count++) {
			res = qupv3_clk_get(common->clk_names[i],
					    &clks[count].clk);
			if (res)
				goto err;

			res = qupv3_clk_on(clks[count].clk,
					   &clks[count].enabled);
			if (res)
				goto err;
		}
	}

	return TEE_SUCCESS;

err:
	common_clks_disable(clks, count);
	return res;
}

static bool is_valid_segment(const struct elf32_phdr *ph)
{
	uint32_t f = ph->p_flags;

	return ph->p_type == ELF_PT_LOAD &&
	       SEG_PAGE_MODE(f) == SEG_PAGE_MODE_NON_PAGED &&
	       SEG_TYPE(f) != SEG_TYPE_HASH &&
	       SEG_ACCESS_TYPE(f) != SEG_ACCESS_NOTUSED &&
	       SEG_ACCESS_TYPE(f) != SEG_ACCESS_SHARED;
}

static bool segment_range_is_valid(uint32_t offset, uint32_t length,
				   uint32_t size)
{
	return offset <= size && length <= size - offset;
}

static bool sefw_hdr_is_valid(const struct sefw_hdr *h, uint32_t filesz)
{
	size_t fw_size = h->fw_size_in_items * sizeof(uint32_t);
	size_t cfg_val_size = h->cfg_size_in_items * sizeof(uint32_t);

	return h->version == SEFW_VERSION &&
	       segment_range_is_valid(h->fw_offset, fw_size, filesz) &&
	       segment_range_is_valid(h->cfg_idx_offset, h->cfg_size_in_items,
				      filesz) &&
	       segment_range_is_valid(h->cfg_val_offset, cfg_val_size, filesz);
}

static void track_best(struct qupv3_fw_seg *slot, vaddr_t va, uint32_t size,
		       uint32_t core_version)
{
	if (slot->va && slot->core_version >= core_version)
		return;

	slot->va = va;
	slot->size = size;
	slot->core_version = core_version;
}

static TEE_Result parse_elf_segments(struct qupv3_fw_ctx *ctx)
{
	const struct qupv3_fw_platform *plat = ctx->plat;
	struct elf32_ehdr eh = { };
	struct elf32_phdr ph = { };
	struct sefw_hdr h = { };
	size_t phend = 0;
	size_t n = 0;

	if (plat->elf_hdr_size < sizeof(eh))
		return TEE_ERROR_BAD_FORMAT;
	memcpy(&eh, plat->elf_hdr, sizeof(eh));

	if (memcmp(eh.e_ident, "\177ELF", 4) ||
	    eh.e_ident[4] != 1 || eh.e_ident[5] != 1 ||
	    eh.e_version != 1 || eh.e_ehsize != sizeof(eh) ||
	    eh.e_phentsize != sizeof(ph) ||
	    MUL_OVERFLOW(eh.e_phnum, sizeof(ph), &phend) ||
	    ADD_OVERFLOW(phend, eh.e_phoff, &phend) ||
	    phend > plat->elf_hdr_size) {
		EMSG("Invalid QUPv3 FW ELF header");
		return TEE_ERROR_BAD_FORMAT;
	}

	IMSG("QUPv3 ELF: ident %02"PRIx8" %02"PRIx8" %02"PRIx8
	     " %02"PRIx8" %02"PRIx8" %02"PRIx8" %02"PRIx8
	     " %02"PRIx8" %02"PRIx8" %02"PRIx8" %02"PRIx8
	     " %02"PRIx8" %02"PRIx8" %02"PRIx8" %02"PRIx8
	     " %02"PRIx8,
	     eh.e_ident[0], eh.e_ident[1], eh.e_ident[2], eh.e_ident[3],
	     eh.e_ident[4], eh.e_ident[5], eh.e_ident[6], eh.e_ident[7],
	     eh.e_ident[8], eh.e_ident[9], eh.e_ident[10], eh.e_ident[11],
	     eh.e_ident[12], eh.e_ident[13], eh.e_ident[14], eh.e_ident[15]);

	DMSG("QUPv3 ELF: type %#"PRIx16" machine %#"PRIx16
	     " ver %#"PRIx32" entry %#"PRIx32" phoff %#"PRIx32
	     " shoff %#"PRIx32" flags %#"PRIx32,
	     eh.e_type, eh.e_machine, eh.e_version, eh.e_entry, eh.e_phoff,
	     eh.e_shoff, eh.e_flags);

	DMSG("QUPv3 ELF: ehsize %#"PRIx16" phentsize %#"PRIx16
	     " phnum %#"PRIx16" shentsize %#"PRIx16" shnum %#"PRIx16
	     " shstrndx %#"PRIx16,
	     eh.e_ehsize, eh.e_phentsize, eh.e_phnum, eh.e_shentsize,
	     eh.e_shnum, eh.e_shstrndx);

	for (n = 0; n < eh.e_phnum; n++) {
		enum qupv3_fw_idx idx = FW_IDX_NONE;
		vaddr_t va = 0;

		memcpy(&ph, plat->elf_hdr + eh.e_phoff + n * sizeof(ph),
		       sizeof(ph));
		DMSG("QUPv3 PH[%zu]: type %#"PRIx32" off %#"PRIx32
		     " vaddr %#"PRIx32" paddr %#"PRIx32" filesz %#"PRIx32
		     " memsz %#"PRIx32" flags %#"PRIx32" align %#"PRIx32,
		     n, ph.p_type, ph.p_offset, ph.p_vaddr, ph.p_paddr,
		     ph.p_filesz, ph.p_memsz, ph.p_flags, ph.p_align);

		if (!is_valid_segment(&ph) || !ph.p_memsz)
			continue;
		if (ph.p_filesz < sizeof(h))
			continue;

		va = fw_pa_to_va(ctx, ph.p_paddr, ph.p_filesz);
		if (!va) {
			EMSG("FW segment %zu @%#"PRIx32" outside DDR window",
			     n, ph.p_paddr);
			continue;
		}
		memcpy(&h, (void *)va, sizeof(h));
		DMSG("QUPv3 FW seg %zu: file %#"PRIx32" DDR %#"PRIx32
		     " size %#"PRIx32" magic %#"PRIx32,
		     n, ph.p_offset, ph.p_paddr, ph.p_filesz, h.magic);

		if (h.magic == QSI_MAGIC) {
			if (h.version != SEFW_VERSION ||
			    ctx->hw_ver < h.core_version ||
			    !fw_pa_to_va(ctx, ph.p_paddr, ph.p_memsz)) {
				EMSG("GSI FW seg %zu rejected: ver %"PRIx32, n,
				     h.version);
				EMSG("core %#"PRIx32" HW %#"PRIx32,
				     h.core_version, ctx->hw_ver);
			} else {
				track_best(&ctx->gsi, va, ph.p_memsz,
					   h.core_version);
			}
			continue;
		}

		if (h.magic != SEFW_MAGIC) {
			EMSG("QUPv3 FW seg %zu @%#"PRIx32
			     " bad magic %#"PRIx32" size %#"PRIx32,
			     n, ph.p_paddr, h.magic, ph.p_filesz);
			continue;
		}
		if (!sefw_hdr_is_valid(&h, ph.p_filesz)) {
			EMSG("QUPv3 SE FW seg %zu rejected: ver %#"PRIx32
			     " proto %"PRIu16" FW %#"PRIx16" size %#"PRIx32,
			     n, h.version, h.serial_protocol, h.fw_version,
			     ph.p_filesz);
			continue;
		}

		idx = protocol_to_idx(h.serial_protocol);
		if (idx == FW_IDX_NONE) {
			EMSG("QUPv3 SE FW seg %zu unsupported proto %"PRIu16,
			     n, h.serial_protocol);
			continue;
		}
		if (ctx->hw_ver < h.core_version) {
			EMSG("QUPv3 SE FW seg %zu rejected: core %#"PRIx32
			     " exceeds HW %#"PRIx32,
			     n, h.core_version, ctx->hw_ver);
			continue;
		}

		track_best(ctx->fw + idx, va, ph.p_memsz, h.core_version);
		DMSG("QUPv3 SE FW seg %zu: proto %"PRIu16" ver %#"PRIx16
		     " core %#"PRIx32,
		     n, h.serial_protocol, h.fw_version, h.core_version);
	}

	return TEE_SUCCESS;
}

static void toggle_prog_ram_clk(vaddr_t base, uint32_t ser_clk_sel)
{
	io_setbits32(base + GENI_CGC_CTRL, CGC_CTRL_PROG_RAM_CLK);
	io_write32(base + GENI_CLK_CTRL, ser_clk_sel);
	io_clrbits32(base + GENI_CGC_CTRL, CGC_CTRL_PROG_RAM_CLK);
}

static void copy_init_se_firmware(struct qupv3_fw_ctx *ctx, vaddr_t base,
				  const struct qupv3_se_perms *perm,
				  const struct qupv3_fw_seg *seg)
{
	const uint8_t *img = (const uint8_t *)seg->va;
	struct sefw_hdr h = { };
	uint32_t protocol = 0;
	uint32_t depth = 0;
	uint32_t rev = 0;
	size_t i = 0;

	memcpy(&h, img, sizeof(h));

	io_clrbits32(base + GENI_DFS_IF_CFG, BIT(0));
	io_write32(base + GENI_OUTPUT_CTRL, 0);
	toggle_prog_ram_clk(base, 0);

	if (!is_uart_like(perm->protocol))
		io_write32(base + GENI_DFS_IF_EN, 1);

	if (ctx->hw_ver >= QUPV3_HW_VER_1_1) {
		io_write32(base + SE_DMA_GENERAL_CFG, DMA_GENERAL_CFG_ALL);
		io_write32(base + GENI_CGC_CTRL, CGC_CTRL_ALL);
	}

	io_write32(base + GENI_INIT_CFG_REVISION, h.cfg_version & 0xff);
	io_write32(base + GENI_S_INIT_CFG_REVISION, h.cfg_version & 0xff);

	for (i = 0; i < h.cfg_size_in_items; i++) {
		uint8_t idx = img[h.cfg_idx_offset + i];
		uint32_t val = get_unaligned_le32(img + h.cfg_val_offset +
						  i * 4);

		io_write32(base + GENI_CFG_REG(idx), val);
	}

	if (perm->protocol == QUPV3_PROTOCOL_QSPI ||
	    perm->protocol == QUPV3_PROTOCOL_QSPI_HID) {
		io_write32(base + GENI_CFG_REG42, 0xa);
		io_clrsetbits32(base + GENI_CFG_REG48, CFG_REG48_QSPI_MASK,
				SHIFT_U32(1, 8));
	} else if (perm->protocol == QUPV3_PROTOCOL_I2C_MM) {
		io_setbits32(base + GENI_CFG_REG55, BIT(2));
		io_clrsetbits32(base + GENI_CFG_REG58, CFG_REG58_I2C_MM_MASK,
				0x98);
	}

	depth = HW_PARAM_1_RX_FIFO_DEPTH(io_read32(base + SE_HW_PARAM_1));
	io_write32(base + GENI_RX_RFR_WATERMARK, (depth - 2) & 0xff);

	io_write32(base + GENI_OUTPUT_CTRL, OUTPUT_CTRL_ALL);

	switch (perm->mode) {
	case QUPV3_MODE_GSI:
		io_setbits32(base + GENI_DMA_MODE_EN, BIT(0));
		io_write32(base + SE_IRQ_EN, 0);
		io_write32(base + SE_GSI_EVENT_EN, SE_GSI_EVENT_EN_ALL);
		break;
	case QUPV3_MODE_CPU_DMA:
		io_setbits32(base + GENI_DMA_MODE_EN, BIT(0));
		io_write32(base + SE_IRQ_EN, SE_IRQ_EN_ALL);
		io_write32(base + SE_GSI_EVENT_EN, 0);
		break;
	case QUPV3_MODE_FIFO:
	default:
		io_clrbits32(base + GENI_DMA_MODE_EN, BIT(0));
		io_write32(base + SE_IRQ_EN, SE_IRQ_EN_ALL);
		io_write32(base + SE_GSI_EVENT_EN, 0);
		break;
	}

	io_setbits32(base + GENI_M_IRQ_EN, M_IRQ_EN_DEFAULT);
	io_setbits32(base + GENI_S_IRQ_EN, S_IRQ_EN_DEFAULT);
	io_write32(base + SE_DMA_TX_IRQ_EN_SET, DMA_TX_IRQ_EN_DEFAULT);
	io_write32(base + SE_DMA_RX_IRQ_EN_SET, DMA_RX_IRQ_EN_DEFAULT);

	/* QSPI_HID shares the QSPI image but reports its own protocol */
	protocol = h.serial_protocol;
	if (protocol == QUPV3_PROTOCOL_QSPI_HID)
		protocol = perm->protocol;
	rev = (SHIFT_U32(QUPV3_TO_HW(protocol), 8) & 0xff00) |
	      (h.fw_version & 0xff);
	io_write32(base + GENI_FW_REVISION, rev);
	rev = (SHIFT_U32(QUPV3_TO_HW(h.serial_protocol), 8) & 0xff00) |
	      (h.fw_version & 0xff);
	io_write32(base + GENI_S_FW_REVISION, rev);

	for (i = 0; i < h.fw_size_in_items; i++)
		io_write32(base + GENI_FW_RAM(i),
			   get_unaligned_le32(img + h.fw_offset + i * 4));

	io_write32(base + GENI_FORCE_DEFAULT_REG, 1);
	toggle_prog_ram_clk(base, 1);

	io_write32(base + GENI_DMA_IF_EN, 1);
	io_write32(base + GENI_FIFO_IF_DISABLE,
		   perm->mode == QUPV3_MODE_FIFO ? 0 : 1);
	io_write32(base + GENI_MULTILOCK_PROTNS, 1);
}

static TEE_Result load_fw(struct qupv3_fw_ctx *ctx,
			  const struct qupv3_se_perms *perm)
{
	const struct qupv3_se_hw *se = ctx->plat->se + perm->periph_id;
	enum qupv3_fw_idx idx = protocol_to_idx(perm->protocol);
	const struct qupv3_fw_seg *seg = NULL;
	vaddr_t base = 0;
	struct clk *clk = NULL;
	bool clk_enabled = false;
	TEE_Result res = TEE_SUCCESS;

	if (idx == FW_IDX_NONE)
		return TEE_ERROR_BAD_PARAMETERS;

	seg = ctx->fw + idx;
	if (!seg->va) {
		EMSG("QUPv3: SE%"PRIu32" no FW proto %u idx %u",
		     perm->periph_id, QUPV3_TO_HW(perm->protocol), idx);
		return TEE_ERROR_NO_DATA;
	}

	base = se_va(se);

	res = qupv3_clk_get(se->clk_name, &clk);
	if (res)
		return res;

	if (!is_uart_like(perm->protocol)) {
		res = qcom_clk_enable_dfs(clk);
		if (res == TEE_ERROR_BAD_PARAMETERS) {
			DMSG("QUPv3: %s has no DFS configuration",
			     se->clk_name);
		} else if (res) {
			EMSG("QUPv3: failed to enable DFS on %s: %#"PRIx32,
			     se->clk_name, res);
			return res;
		}
	}

	res = qupv3_clk_on(clk, &clk_enabled);
	if (res)
		return res;
	copy_init_se_firmware(ctx, base, perm, seg);

	IMSG("QUPv3 SE%"PRIu32" @%#"PRIxPA
	     ": FW proto %d loaded (rev %#"PRIx32")",
	     perm->periph_id, se->base, perm->protocol,
	     io_read32(base + GENI_FW_REVISION_RO));
	qupv3_clk_off(clk, clk_enabled);

	return TEE_SUCCESS;
}

static void common_init(const struct qupv3_fw_platform *plat)
{
	size_t n = 0;

	for (n = 0; n < plat->num_common; n++) {
		vaddr_t base = common_va(plat->common + n);

		io_setbits32(base + QUPV3_COMMON_CFG, BIT(0));
		io_setbits32(base + QUPV3_SE_AHB_M_CFG, BIT(0));
		io_setbits32(base + QUPV3_COMMON_CGC_CTRL, BIT(0));
	}
}

static unsigned int load_and_init(struct qupv3_fw_ctx *ctx)
{
	const struct qupv3_fw_platform *plat = ctx->plat;
	unsigned int failures = 0;
	size_t n = 0;

	common_init(plat);

	for (n = 0; n < plat->num_perms; n++) {
		const struct qupv3_se_perms *perm = plat->perms + n;
		TEE_Result res = TEE_SUCCESS;

		if (perm->periph_id >= plat->num_se) {
			EMSG("Invalid QUPv3 periph %"PRIu32, perm->periph_id);
			failures++;
			continue;
		}

		if (!perm->load)
			continue;

		res = load_fw(ctx, perm);
		if (res) {
			EMSG("QUPv3 SE%"PRIu32" FW load failed: %#"PRIx32,
			     perm->periph_id, res);
			failures++;
		}
	}

	return failures;
}

static TEE_Result gsi_fw_validate(const struct qupv3_fw_seg *seg,
				  struct gsi_fw_hdr *h)
{
	size_t iep_len = 0;
	size_t fw_len = 0;

	if (seg->size < sizeof(*h))
		return TEE_ERROR_BAD_FORMAT;
	memcpy(h, (void *)seg->va, sizeof(*h));

	iep_len = h->iep_size_in_items * GSI_FW_IEP_SIZE;
	fw_len = h->fw_size_in_items * GSI_FW_LINE_SIZE;

	/* Same size rule as TZ, plus bounds for the offsets we dereference */
	if (h->magic != QSI_MAGIC || h->version != SEFW_VERSION ||
	    sizeof(*h) + iep_len + fw_len != seg->size ||
	    !segment_range_is_valid(h->iep_offset, iep_len, seg->size) ||
	    !segment_range_is_valid(h->fw_offset, fw_len, seg->size) ||
	    !h->fw_size_in_items ||
	    h->fw_size_in_items * 2 > GSI_INST_RAM_WORDS)
		return TEE_ERROR_BAD_FORMAT;

	return TEE_SUCCESS;
}

static TEE_Result gsi_fw_load_one(const struct qupv3_common_hw *c,
				  const struct qupv3_fw_seg *seg,
				  const struct gsi_fw_hdr *h)
{
	const uint8_t *img = (const uint8_t *)seg->va;
	vaddr_t base = (vaddr_t)phys_to_virt(c->gsi_base, MEM_AREA_IO_SEC,
					     c->gsi_size);
	uint32_t hw_ver = io_read32(common_va(c) + QUPV3_HW_VERSION);
	uint32_t cfg = GSI_CFG_GSI_ENABLE;
	uint64_t tmo = 0;
	size_t i = 0;

	if (!base)
		panic("QUPv3 GSI not mapped");

	if (io_read32(base + GSI_CFG) & GSI_CFG_GSI_ENABLE) {
		DMSG("GSI @%#"PRIxPA" already enabled", c->gsi_base);
		return TEE_SUCCESS;
	}

	/* HW errata: keep the MCS clock ungated (CGC region 2) */
	io_clrbits32(base + GSI_CGC_CTRL, GSI_CGC_CTRL_REGION_2_HW_CGC_EN);

	for (i = 0; i < h->iep_size_in_items; i++) {
		const uint8_t *e = img + h->iep_offset + i * GSI_FW_IEP_SIZE;
		uint32_t off = get_unaligned_le32(e);

		if (off < c->gsi_size && IS_ALIGNED(off, 4))
			io_write32(base + off, get_unaligned_le32(e + 4));
	}

	io_write32(base + GSI_MANAGER_MCS_CODE_VER,
		   get_unaligned_le32(img + h->fw_offset));
	for (i = 0; i < h->fw_size_in_items * 2; i++)
		io_write32(base + GSI_INST_RAM(i),
			   get_unaligned_le32(img + h->fw_offset + i * 4));

	io_setbits32(base + GSI_MCS_CFG, GSI_MCS_CFG_MCS_ENABLE);

	/* From v1.1 core and core2x clocks run at 1:2 */
	if (QUPV3_HW_VER_MAJOR(hw_ver) != 1 || QUPV3_HW_VER_MINOR(hw_ver))
		cfg |= GSI_CFG_DOUBLE_MCS_CLK_FREQ;
	io_write32(base + GSI_CFG, cfg);

	/* Poke the FW until it reports ready through EE0 scratch 0 */
	io_write32(base + GSI_EE0_CNTXT_SCRATCH_0, 0);
	tmo = timeout_init_us(GSI_FW_READY_TIMEOUT_US);
	while (true) {
		io_write32(base + GSI_EE0_GENERIC_CMD,
			   GSI_GENERIC_CMD_FW_READY);
		udelay(GSI_FW_READY_POLL_US);
		if (io_read32(base + GSI_EE0_CNTXT_SCRATCH_0) >= 1)
			break;
		if (timeout_elapsed(tmo)) {
			EMSG("GSI @%#"PRIxPA" FW not ready", c->gsi_base);
			return TEE_ERROR_TIMEOUT;
		}
	}

	io_setbits32(base + GSI_TZ_FW_AUTH_LOCK,
		     GSI_AUTH_LOCK_DIS_SHRAM_WRITE |
		     GSI_AUTH_LOCK_DIS_IRAM_WRITE);

	IMSG("QUPv3 GSI @%#"PRIxPA": FW ver %#"PRIx32" loaded", c->gsi_base,
	     h->fw_version);

	return TEE_SUCCESS;
}

static TEE_Result gsi_fw_load(struct qupv3_fw_ctx *ctx)
{
	const struct qupv3_fw_platform *plat = ctx->plat;
	struct gsi_fw_hdr h = { };
	TEE_Result res = TEE_SUCCESS;
	size_t n = 0;

	if (!ctx->gsi.va)
		return TEE_ERROR_NO_DATA;

	res = gsi_fw_validate(&ctx->gsi, &h);
	if (res) {
		EMSG("QUPv3 GSI FW integrity check failed");
		return res;
	}

	for (n = 0; n < plat->num_common; n++) {
		if (!plat->common[n].gsi_base)
			continue;

		res = gsi_fw_load_one(plat->common + n, &ctx->gsi, &h);
		if (res)
			return res;
	}

	return TEE_SUCCESS;
}

static uint32_t read_hw_version(const struct qupv3_fw_platform *plat)
{
	uint32_t ver = 0;
	uint32_t v = 0;
	size_t n = 0;

	for (n = 0; n < plat->num_common; n++) {
		v = io_read32(common_va(plat->common + n) + QUPV3_HW_VERSION);
		if (!n)
			ver = v;
		else if (v != ver)
			return 0;
	}

	return ver;
}

static TEE_Result qupv3_fw_init(void)
{
	/* Maximum number of wrapper dependencies supported by this loader. */
	struct qupv3_clk_state common_clks[16] = { };
	struct qupv3_fw_ctx ctx = { };
	TEE_Result res = TEE_SUCCESS;

	ctx.plat = qupv3_fw_get_platform();
	if (!ctx.plat || !ctx.plat->num_perms)
		return TEE_SUCCESS;

	res = common_clks_enable(ctx.plat, common_clks,
				 ARRAY_SIZE(common_clks));
	if (res)
		goto out;

	ctx.hw_ver = read_hw_version(ctx.plat);
	if (!ctx.hw_ver) {
		EMSG("QUPv3 HW version mismatch across wrappers");
		res = TEE_ERROR_BAD_STATE;
		goto out_clk;
	}

	ctx.ddr_va = (vaddr_t)core_mmu_add_mapping(MEM_AREA_RAM_NSEC,
						   ctx.plat->fw_ddr_base,
						   ctx.plat->fw_ddr_size);
	if (!ctx.ddr_va) {
		EMSG("Failed to map QUPv3 FW DDR %#"PRIxPA,
		     ctx.plat->fw_ddr_base);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_clk;
	}

	res = parse_elf_segments(&ctx);
	if (res)
		goto out_unmap;

	if (load_and_init(&ctx))
		EMSG("QUPv3 SE FW load failures; verify ELF placement in DDR");

	res = gsi_fw_load(&ctx);
	if (res)
		EMSG("QUPv3 GSI FW load failed: %#"PRIx32, res);

out_unmap:
	core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, (void *)ctx.ddr_va,
				ctx.plat->fw_ddr_size);
out_clk:
	common_clks_disable(common_clks, ARRAY_SIZE(common_clks));
out:
	/* QUP FW load failure must not prevent the rest of OP-TEE booting */
	if (res)
		EMSG("QUPv3 FW loading failed: %#"PRIx32, res);
	return TEE_SUCCESS;
}

driver_init(qupv3_fw_init);
