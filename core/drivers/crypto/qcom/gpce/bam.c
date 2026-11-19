// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Low-level BAM controller and pipe support for GPCE.
 */

#include <inttypes.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>

#include "bam.h"

/* BAM controller register offsets and field definitions. */
/* TODO: Move these to bam_hwio.h when another BAM client needs this layout. */
#define BAM_CTRL				U(0x0)
#define BAM_DESC_CNT_TRSHLD			U(0x8)
#define BAM_CNFG_BITS				U(0x7c)
#define BAM_NUM_PIPES				U(0x1008)
#define BAM_PIPE_ATTR_EE(ee)			(U(0x300c) + U(0x1000) * (ee))
#define BAM_P_CTRL(pipe) \
	(U(0x13000) + U(0x1000) * (pipe))
#define BAM_P_RST(pipe)			(U(0x13004) + U(0x1000) * (pipe))
#define BAM_P_CNSMR_SDBND(pipe)		(U(0x13028) + U(0x1000) * (pipe))
#define BAM_P_SW_OFSTS(pipe) \
	(U(0x13800) + U(0x1000) * (pipe))
#define BAM_P_EVNT_REG(pipe) \
	(U(0x13818) + U(0x1000) * (pipe))
#define BAM_P_DESC_FIFO_ADDR(pipe) \
	(U(0x1381c) + U(0x1000) * (pipe))
#define BAM_P_FIFO_SIZES(pipe) \
	(U(0x13820) + U(0x1000) * (pipe))
#define BAM_P_EVNT_GEN_TRSHLD(pipe) \
	(U(0x13828) + U(0x1000) * (pipe))
#define BAM_P_DESC_FIFO_ADDR_MSB(pipe)	(U(0x13914) + U(0x1000) * (pipe))

#define BAM_CTRL_SW_RST_MASK			BIT(0)
#define BAM_CTRL_SW_RST_SHIFT			U(0)
#define BAM_CTRL_EN_MASK			BIT(1)
#define BAM_CTRL_EN_SHIFT			U(1)
#define BAM_CTRL_LOCAL_CLK_GATING_MASK		(U(0x3) << U(17))
#define BAM_CTRL_LOCAL_CLK_GATING_SHIFT	U(17)
#define BAM_PIPE_ATTR_ENABLED_MASK		BIT(31)
#define BAM_PIPE_ATTR_ENABLED_SHIFT		U(31)
#define BAM_NUM_PIPES_COUNT_MASK		U(0xff)
#define BAM_NUM_PIPES_COUNT_SHIFT		U(0)
#define BAM_NUM_PIPES_ADDR_WIDTH_MASK		(U(0x3) << U(14))
#define BAM_NUM_PIPES_ADDR_WIDTH_SHIFT	U(14)
#define BAM_P_CTRL_LOCK_GROUP_MASK		(U(0x1f) << U(16))
#define BAM_P_CTRL_LOCK_GROUP_SHIFT		U(16)
#define BAM_P_CTRL_SYS_MODE_MASK		BIT(5)
#define BAM_P_CTRL_SYS_MODE_SHIFT		U(5)
#define BAM_P_CTRL_SYS_STRM_MASK		BIT(4)
#define BAM_P_CTRL_SYS_STRM_SHIFT		U(4)
#define BAM_P_CTRL_DIRECTION_MASK		BIT(3)
#define BAM_P_CTRL_DIRECTION_SHIFT		U(3)
#define BAM_P_CTRL_EN_MASK			BIT(1)
#define BAM_P_CTRL_EN_SHIFT			U(1)
#define BAM_P_CNSMR_SDBND_CTRL_MASK		(U(0xf) << U(16))
#define BAM_P_CNSMR_SDBND_CTRL_SHIFT		U(16)
#define BAM_P_SW_OFSTS_DESC_OFFSET_MASK	U(0xffff)
#define BAM_P_SW_OFSTS_DESC_OFFSET_SHIFT	U(0)
#define BAM_P_EVNT_REG_DESC_OFFSET_MASK	U(0xffff)
#define BAM_P_EVNT_REG_DESC_OFFSET_SHIFT	U(0)
#define BAM_P_FIFO_SIZES_DESC_SIZE_MASK	U(0xffff)
#define BAM_P_FIFO_SIZES_DESC_SIZE_SHIFT	U(0)

/* Linux BAM reset defaults for descriptor mode. */
#define BAM_RESET_CNFG_BITS			U(0x0ffff004)
#define BAM_RESET_DESC_CNT_TRSHLD		U(4)

#define BAM_PIPE_BIT(n)	(UINT32_C(1) << (n))
#define BAM_IOVEC_HW_FLAGS	(BAM_IOVEC_FLAG_INT | BAM_IOVEC_FLAG_EOT | \
				 BAM_IOVEC_FLAG_NWD | BAM_IOVEC_FLAG_CMD | \
				 BAM_IOVEC_FLAG_LCK | BAM_IOVEC_FLAG_UNLCK | \
				 BAM_IOVEC_FLAG_IMM_CMD)

#define ADDR_LPAE_MSB(x)	((((uint64_t)(x)) >> 32) & U(0xff))
#define ADDR_LPAE_LSB(x)	((uint32_t)((x) & UINT32_MAX))

/*
 * struct bam_iovec - BAM descriptor FIFO entry
 * @buf_pa: Low 32 bits of the buffer physical address
 * @buf_size: Number of bytes in the buffer
 * @buf_pa_msb: Bits 39:32 of the physical address when LPAE is enabled
 * @flags: BAM hardware descriptor flags
 */
struct bam_iovec {
	uint32_t buf_pa;
	uint32_t buf_size : 16;
	uint32_t buf_pa_msb : 8;
	uint32_t flags : 8;
};

static_assert(sizeof(struct bam_iovec) == BAM_DESC_ENTRY_SIZE);

/*
 * struct bam_pipe_state - Software state for one configured BAM pipe
 * @pipe_num: Hardware pipe number
 * @is_consumer: True when the pipe transfers data from CE to memory
 * @desc_base_va: Virtual address of the descriptor FIFO
 * @desc_base_pa: Physical address of the descriptor FIFO
 * @read_offset: Software-consumed descriptor FIFO offset
 * @write_offset: Next descriptor FIFO offset to populate
 * @last_offset: Last submitted descriptor FIFO offset
 */
struct bam_pipe_state {
	uint32_t pipe_num;
	bool is_consumer;
	uint8_t *desc_base_va;
	paddr_t desc_base_pa;
	uint32_t read_offset;
	uint32_t write_offset;
	uint32_t last_offset;
};

/*
 * struct bam_state - Global state of the BAM controller used by GPCE
 * @bam_va: Virtual base address of BAM registers
 * @bam_pa: Physical base address of BAM registers
 * @ee: Execution environment that owns the configured pipes
 * @lpae: True when descriptor addresses require LPAE encoding
 * @pipes: Per-pipe software state, indexed by hardware pipe number
 */
struct bam_state {
	vaddr_t bam_va;
	paddr_t bam_pa;
	uint32_t ee;
	bool lpae;
	struct bam_pipe_state *pipes;
};

static struct bam_state bam;

static void bam_barrier(void)
{
	__asm__ volatile("dsb sy" : : : "memory");
}

static uint32_t bam_read(uint32_t offset)
{
	return io_read32(bam.bam_va + offset);
}

static void bam_write(uint32_t offset, uint32_t value)
{
	io_write32(bam.bam_va + offset, value);
}

static uint32_t bam_read_field(uint32_t offset, uint32_t mask,
			       uint32_t shift)
{
	return (bam_read(offset) & mask) >> shift;
}

static void bam_write_field(uint32_t offset, uint32_t mask, uint32_t shift,
			    uint32_t value)
{
	uint32_t reg = bam_read(offset);

	reg &= ~mask;
	reg |= (value << shift) & mask;
	bam_write(offset, reg);
}

static bool bam_enabled(void)
{
	return bam_read_field(BAM_CTRL, BAM_CTRL_EN_MASK, BAM_CTRL_EN_SHIFT);
}

static bool bam_pipe_enabled(uint32_t pipe)
{
	return bam_read_field(BAM_P_CTRL(pipe), BAM_P_CTRL_EN_MASK,
			      BAM_P_CTRL_EN_SHIFT);
}

static uint32_t bam_read_offset(uint32_t pipe)
{
	return bam_read_field(BAM_P_SW_OFSTS(pipe),
			      BAM_P_SW_OFSTS_DESC_OFFSET_MASK,
			      BAM_P_SW_OFSTS_DESC_OFFSET_SHIFT);
}

static uint32_t bam_pipe_count(void)
{
	uint32_t value = bam_read(BAM_NUM_PIPES);

	return (value & BAM_NUM_PIPES_COUNT_MASK) >>
	       BAM_NUM_PIPES_COUNT_SHIFT;
}

static uint32_t bam_data_addr_bus_width(void)
{
	uint32_t value = bam_read(BAM_NUM_PIPES);

	return (value & BAM_NUM_PIPES_ADDR_WIDTH_MASK) >>
	       BAM_NUM_PIPES_ADDR_WIDTH_SHIFT;
}

static bool bam_nwd_done(uint32_t pipe)
{
	uint32_t state = bam_read_field(BAM_P_CNSMR_SDBND(pipe),
		BAM_P_CNSMR_SDBND_CTRL_MASK, BAM_P_CNSMR_SDBND_CTRL_SHIFT);

	return !(state & BAM_PIPE_BIT(1));
}

static void bam_submit_offset(uint32_t pipe, uint32_t offset)
{
	bam_write_field(BAM_P_EVNT_REG(pipe),
			BAM_P_EVNT_REG_DESC_OFFSET_MASK,
			BAM_P_EVNT_REG_DESC_OFFSET_SHIFT,
			offset);
}

static void bam_pipe_reset(uint32_t pipe)
{
	bam_write(BAM_P_RST(pipe), 1);
	bam_barrier();
	bam_write(BAM_P_RST(pipe), 0);
}

static void bam_configure_pipe(struct bam_pipe_state *pipe)
{
	bam_pipe_reset(pipe->pipe_num);
	bam_write_field(BAM_P_CTRL(pipe->pipe_num), BAM_P_CTRL_DIRECTION_MASK,
			BAM_P_CTRL_DIRECTION_SHIFT, pipe->is_consumer);
	bam_write_field(BAM_P_CTRL(pipe->pipe_num), BAM_P_CTRL_SYS_MODE_MASK,
			BAM_P_CTRL_SYS_MODE_SHIFT, 1);
	bam_write_field(BAM_P_CTRL(pipe->pipe_num), BAM_P_CTRL_SYS_STRM_MASK,
			BAM_P_CTRL_SYS_STRM_SHIFT, 0);
	bam_write(BAM_P_EVNT_GEN_TRSHLD(pipe->pipe_num), 1);
	bam_write(BAM_P_DESC_FIFO_ADDR(pipe->pipe_num),
		  ADDR_LPAE_LSB(pipe->desc_base_pa));
	if (bam.lpae)
		bam_write(BAM_P_DESC_FIFO_ADDR_MSB(pipe->pipe_num),
			  ADDR_LPAE_MSB(pipe->desc_base_pa));
	bam_write_field(BAM_P_FIFO_SIZES(pipe->pipe_num),
			BAM_P_FIFO_SIZES_DESC_SIZE_MASK,
			BAM_P_FIFO_SIZES_DESC_SIZE_SHIFT,
			BAM_DESC_FIFO_SIZE);
	bam_write_field(BAM_P_CTRL(pipe->pipe_num), BAM_P_CTRL_LOCK_GROUP_MASK,
			BAM_P_CTRL_LOCK_GROUP_SHIFT, 0);
	bam_write_field(BAM_P_CTRL(pipe->pipe_num), BAM_P_CTRL_EN_MASK,
			BAM_P_CTRL_EN_SHIFT, 1);
}

TEE_Result bam_init(const struct bam_config *config)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t width = 0;
	uint32_t pipe_count = 0;
	uint32_t n = 0;
	struct bam_pipe_state *pipes = NULL;

	if (!config || !config->base || !config->pa)
		return TEE_ERROR_BAD_PARAMETERS;
	if (bam.bam_va)
		return bam.bam_va == config->base &&
		       bam.bam_pa == config->pa && bam.ee == config->ee &&
		       bam.pipes ? TEE_SUCCESS : TEE_ERROR_BAD_STATE;
	bam.bam_va = config->base;
	bam.bam_pa = config->pa;
	bam.ee = config->ee;
	if (!bam_enabled()) {
		bam_write_field(BAM_CTRL, BAM_CTRL_SW_RST_MASK,
				BAM_CTRL_SW_RST_SHIFT, 1);
		bam_write_field(BAM_CTRL, BAM_CTRL_SW_RST_MASK,
				BAM_CTRL_SW_RST_SHIFT, 0);
		bam_write_field(BAM_CTRL, BAM_CTRL_LOCAL_CLK_GATING_MASK,
				BAM_CTRL_LOCAL_CLK_GATING_SHIFT, 1);
		bam_write_field(BAM_CTRL, BAM_CTRL_EN_MASK,
				BAM_CTRL_EN_SHIFT, 1);
		bam_write(BAM_DESC_CNT_TRSHLD, BAM_RESET_DESC_CNT_TRSHLD);
		bam_write(BAM_CNFG_BITS, BAM_RESET_CNFG_BITS);
	}
	if (!bam_read_field(BAM_PIPE_ATTR_EE(bam.ee),
			    BAM_PIPE_ATTR_ENABLED_MASK,
			    BAM_PIPE_ATTR_ENABLED_SHIFT)) {
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}
	pipe_count = bam_pipe_count();
	if (!pipe_count) {
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}
	pipes = calloc(pipe_count, sizeof(*pipes));
	if (!pipes) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	bam.pipes = pipes;
	for (n = 0; n < pipe_count; n++) {
		bam.pipes[n].pipe_num = n;
		bam.pipes[n].last_offset = UINT32_MAX;
	}
	width = bam_data_addr_bus_width();
	bam.lpae = width == 1 || width == 2;
	return TEE_SUCCESS;
err:
	free(bam.pipes);
	bam.pipes = NULL;
	bam.bam_va = 0;
	bam.bam_pa = 0;
	bam.ee = 0;
	bam.lpae = false;
	return ret;
}

struct bam_pipe_state *bam_pipe_init(const struct bam_pipe_config *config)
{
	struct bam_pipe_state *pipe = NULL;

	if (!config || !bam.bam_va || !bam.bam_pa || !bam.pipes ||
	    !config->desc_base_va || !config->desc_base_pa)
		return NULL;
	if (config->pipe_num >= bam_pipe_count())
		return NULL;
	pipe = &bam.pipes[config->pipe_num];
	pipe->is_consumer = config->is_consumer;
	pipe->desc_base_va = config->desc_base_va;
	pipe->desc_base_pa = config->desc_base_pa;
	return bam_pipe_reinit(pipe);
}

struct bam_pipe_state *bam_pipe_reinit(struct bam_pipe_state *pipe)
{
	if (!bam.bam_va || !bam.bam_pa || !pipe || !pipe->desc_base_va ||
	    !pipe->desc_base_pa)
		return NULL;
	memset(pipe->desc_base_va, 0, BAM_DESC_FIFO_SIZE);
	pipe->read_offset = 0;
	pipe->write_offset = 0;
	pipe->last_offset = UINT32_MAX;
	dcache_clean_range(pipe->desc_base_va, BAM_DESC_FIFO_SIZE);
	bam_configure_pipe(pipe);
	if (!bam_pipe_enabled(pipe->pipe_num))
		return NULL;
	return pipe;
}

TEE_Result bam_pipe_transfer(struct bam_pipe_state *pipe, paddr_t pa,
			     uint64_t size, uint16_t flags)
{
	struct bam_iovec *entry = NULL;
	uint32_t next = 0;

	if (!pipe || !pipe->desc_base_va || !bam_pipe_enabled(pipe->pipe_num))
		return TEE_ERROR_BAD_STATE;
	if (size > UINT16_MAX || (!bam.lpae && ADDR_LPAE_MSB(pa)))
		return TEE_ERROR_BAD_PARAMETERS;
	next = pipe->write_offset + BAM_DESC_ENTRY_SIZE;
	if (next == BAM_DESC_FIFO_SIZE)
		next = 0;
	if (next == pipe->read_offset)
		return TEE_ERROR_BUSY;
	if ((flags & BAM_IOVEC_FLAG_CMD) && pipe->last_offset != UINT32_MAX) {
		entry = (void *)(vaddr_t)
			(pipe->desc_base_va + pipe->last_offset);
		if (!(entry->flags & (BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_NWD)))
			return TEE_ERROR_BAD_PARAMETERS;
	}
	if ((flags & BAM_IOVEC_FLAG_CMD) && (flags & BAM_IOVEC_FLAG_IMM_CMD))
		return TEE_ERROR_BAD_PARAMETERS;
	if ((flags & BAM_IOVEC_FLAG_NWD) &&
	    !(flags & (BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_EOT)))
		return TEE_ERROR_BAD_PARAMETERS;
	entry = (void *)(vaddr_t)(pipe->desc_base_va + pipe->write_offset);
	entry->buf_pa = ADDR_LPAE_LSB(pa);
	entry->buf_pa_msb = ADDR_LPAE_MSB(pa);
	entry->buf_size = size;
	entry->flags = flags & BAM_IOVEC_HW_FLAGS;
	pipe->last_offset = pipe->write_offset;
	pipe->write_offset = next;
	if (!(flags & BAM_IOVEC_FLAG_NO_SUBMIT)) {
		dcache_clean_range(pipe->desc_base_va, BAM_DESC_FIFO_SIZE);
		bam_barrier();
		bam_submit_offset(pipe->pipe_num, next);
		bam_barrier();
	}
	return TEE_SUCCESS;
}

TEE_Result bam_pipe_poll(struct bam_pipe_state *pipe)
{
	struct bam_iovec *entry = NULL;
	uint32_t end = 0;

	if (!pipe || !pipe->desc_base_va)
		return TEE_ERROR_BAD_PARAMETERS;
	end = bam_read_offset(pipe->pipe_num);
	while (pipe->read_offset != end) {
		entry = (void *)(vaddr_t)
			(pipe->desc_base_va + pipe->read_offset);
		/*
		 * BAM may advance the descriptor offset after handing a data
		 * descriptor to CE but before CE reports NWD completion.
		 * Command descriptors do not need an NWD completion indication.
		 */
		if (!(entry->flags & BAM_IOVEC_FLAG_CMD) &&
		    !bam_nwd_done(pipe->pipe_num))
			break;
		pipe->read_offset += BAM_DESC_ENTRY_SIZE;
		if (pipe->read_offset == BAM_DESC_FIFO_SIZE)
			pipe->read_offset = 0;
		if (entry->flags & BAM_IOVEC_FLAG_EOT)
			return TEE_SUCCESS;
	}
	return TEE_ERROR_BUSY;
}
