// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Low-level BAM controller and pipe support for GPCE.
 */

#include <arm.h>
#include <assert.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "bam.h"
#include "bam_hwio.h"

#define BAM_IOVEC_HW_FLAGS \
	(BAM_IOVEC_FLAG_INT | \
	 BAM_IOVEC_FLAG_EOT | \
	 BAM_IOVEC_FLAG_NWD | \
	 BAM_IOVEC_FLAG_CMD | \
	 BAM_IOVEC_FLAG_LCK | \
	 BAM_IOVEC_FLAG_UNLCK | \
	 BAM_IOVEC_FLAG_IMM_CMD)

/*
 * struct bam_iovec - BAM descriptor FIFO entry
 * @buf_pa: Low 32 bits of the buffer physical address
 * @buf_size: Number of bytes in the buffer
 * @buf_pa_msb: Bits 39:32 of the physical address when LPAE is enabled
 * @flags: BAM hardware descriptor flags
 */
struct bam_iovec {
	uint32_t buf_pa;
	uint16_t buf_size;
	uint8_t buf_pa_msb;
	uint8_t flags;
};

static_assert(sizeof(struct bam_iovec) == BAM_DESC_ENTRY_SIZE);
static_assert(BAM_DESC_FIFO_SIZE <= UINT16_MAX);

/*
 * struct bam_pipe_state - Software state for one configured BAM pipe
 * @pipe_num: Hardware pipe number
 * @is_producer: Value programmed in BAM_P_CTRL_DIRECTION
 * @desc_base: Descriptor FIFO allocation
 * @desc_base_pa: Physical address of the descriptor FIFO
 * @read_offset: Software-consumed descriptor FIFO offset
 * @write_offset: Next descriptor FIFO offset to populate
 * @last_offset: Last submitted descriptor FIFO offset
 *
 * @is_producer selects BAM_P_CTRL_DIRECTION pipe direction:
 * - 1'b1: The pipe can be written (producer mode).
 * - 1'b0: The pipe can be read (consumer mode).
 *
 * This field is not valid for BAM revision 0x1e.
 */
struct bam_pipe_state {
	struct bam_iovec *desc_base;
	paddr_t desc_base_pa;
	uint16_t read_offset;
	uint16_t write_offset;
	uint16_t last_offset;
	uint8_t pipe_num;
	bool is_producer;
};

/*
 * struct bam_state - Global state of the BAM controller used by GPCE
 * @bam_va: Virtual base address of BAM registers
 * @pipes: Per-pipe software state, indexed by hardware pipe number
 * @ee: Execution environment that owns the configured pipes
 * @lpae: True when descriptor addresses require LPAE encoding
 */
struct bam_state {
	vaddr_t bam_va;
	struct bam_pipe_state *pipes;
	uint32_t ee;
	bool lpae;
};

static struct bam_state bam;

static uint32_t bam_read(uint32_t offset)
{
	return io_read32(bam.bam_va + offset);
}

static void bam_write(uint32_t offset, uint32_t value)
{
	io_write32(bam.bam_va + offset, value);
}

static bool bam_enabled(void)
{
	return io_read32_off_field(bam.bam_va, BAM_CTRL, BAM_CTRL_EN_MASK);
}

static bool bam_pipe_enabled(uint32_t pipe)
{
	return io_read32_off_field(bam.bam_va, BAM_P_CTRL(pipe),
				   BAM_P_CTRL_EN_MASK);
}

static uint32_t bam_read_offset(uint32_t pipe)
{
	return io_read32_off_field(bam.bam_va, BAM_P_SW_OFSTS(pipe),
				   BAM_P_SW_OFSTS_DESC_OFFSET_MASK);
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

/* CTRL[1] remains set while NWD is pending for the current descriptor. */
static bool bam_nwd_pending(uint32_t pipe)
{
	uint32_t state =
		io_read32_off_field(bam.bam_va, BAM_P_CNSMR_SDBND(pipe),
				    BAM_P_CNSMR_SDBND_CTRL_MASK);

	return state & BAM_P_CNSMR_SDBND_CTRL_NWD_MASK;
}

static void bam_submit_offset(uint32_t pipe, uint32_t offset)
{
	io_write32_off_field(bam.bam_va, BAM_P_EVNT_REG(pipe),
			     BAM_P_EVNT_REG_DESC_OFFSET_MASK, offset);
}

static void bam_pipe_reset(uint32_t pipe)
{
	bam_write(BAM_P_RST(pipe), BAM_P_RST_ASSERT);
	dsb();
	bam_write(BAM_P_RST(pipe), BAM_P_RST_DEASSERT);
}

static void bam_configure_pipe(struct bam_pipe_state *pipe)
{
	bam_pipe_reset(pipe->pipe_num);
	io_write32_off_field(bam.bam_va, BAM_P_CTRL(pipe->pipe_num),
			     BAM_P_CTRL_DIRECTION_MASK, pipe->is_producer);
	io_write32_off_field(bam.bam_va, BAM_P_CTRL(pipe->pipe_num),
			     BAM_P_CTRL_SYS_MODE_MASK, true);
	io_write32_off_field(bam.bam_va, BAM_P_CTRL(pipe->pipe_num),
			     BAM_P_CTRL_SYS_STRM_MASK, false);
	bam_write(BAM_P_EVNT_GEN_TRSHLD(pipe->pipe_num),
		  BAM_P_EVNT_GEN_TRSHLD_DEFAULT);
	bam_write(BAM_P_DESC_FIFO_ADDR(pipe->pipe_num),
		  low32_from_64(pipe->desc_base_pa));
	if (bam.lpae)
		bam_write(BAM_P_DESC_FIFO_ADDR_MSB(pipe->pipe_num),
			  (high32_from_64(pipe->desc_base_pa) &
			   BAM_LPAE_ADDR_MSB_MASK));
	io_write32_off_field(bam.bam_va, BAM_P_FIFO_SIZES(pipe->pipe_num),
			     BAM_P_FIFO_SIZES_DESC_SIZE_MASK,
			     BAM_DESC_FIFO_SIZE);
	io_write32_off_field(bam.bam_va, BAM_P_CTRL(pipe->pipe_num),
			     BAM_P_CTRL_LOCK_GROUP_MASK,
			     BAM_P_CTRL_LOCK_GROUP_NONE);
	io_write32_off_field(bam.bam_va, BAM_P_CTRL(pipe->pipe_num),
			     BAM_P_CTRL_EN_MASK, true);
}

TEE_Result bam_init(const struct bam_config *config)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t pipe_count = 0;
	uint32_t width = 0;
	uint32_t n = 0;

	if (bam.bam_va)
		return TEE_SUCCESS;
	bam.bam_va = config->base;
	bam.ee = config->ee;
	if (!bam_enabled()) {
		io_write32_off_field(bam.bam_va, BAM_CTRL, BAM_CTRL_SW_RST_MASK,
				     true);
		io_write32_off_field(bam.bam_va, BAM_CTRL, BAM_CTRL_SW_RST_MASK,
				     false);
		io_write32_off_field(bam.bam_va, BAM_CTRL,
				     BAM_CTRL_LOCAL_CLK_GATING_MASK, true);
		io_write32_off_field(bam.bam_va, BAM_CTRL, BAM_CTRL_EN_MASK,
				     true);
		bam_write(BAM_DESC_CNT_TRSHLD, BAM_RESET_DESC_CNT_TRSHLD);
		bam_write(BAM_CNFG_BITS, BAM_RESET_CNFG_BITS);
	}
	if (!io_read32_off_field(bam.bam_va, BAM_PIPE_ATTR_EE(bam.ee),
				 BAM_PIPE_ATTR_ENABLED_MASK)) {
		EMSG("BAM EE%"PRIu32" disabled: base %#"PRIxVA
		     " pipe attribute %#"PRIx32, bam.ee, bam.bam_va,
		     bam_read(BAM_PIPE_ATTR_EE(bam.ee)));
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}
	pipe_count = bam_pipe_count();
	if (!pipe_count || pipe_count > UINT8_MAX) {
		EMSG("invalid BAM pipe count %"PRIu32": base %#"PRIxVA
		     " BAM_NUM_PIPES %#"PRIx32, pipe_count, bam.bam_va,
		     bam_read(BAM_NUM_PIPES));
		ret = TEE_ERROR_BAD_STATE;
		goto err;
	}
	bam.pipes = calloc(pipe_count, sizeof(*bam.pipes));
	if (!bam.pipes) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	for (n = 0; n < pipe_count; n++) {
		bam.pipes[n].pipe_num = n;
		bam.pipes[n].last_offset = UINT16_MAX;
	}
	width = bam_data_addr_bus_width();
	bam.lpae = width == BAM_NUM_PIPES_ADDR_WIDTH_36_BIT ||
		   width == BAM_NUM_PIPES_ADDR_WIDTH_40_BIT;
	return TEE_SUCCESS;
err:
	free(bam.pipes);
	memset(&bam, 0, sizeof(bam));
	return ret;
}

struct bam_pipe_state *bam_pipe_init(uint8_t pipe_num, bool is_producer,
				     void *desc_base)
{
	struct bam_pipe_state *pipe;
	paddr_t desc_base_pa;

	assert(pipe_num < bam_pipe_count());
	desc_base_pa = virt_to_phys(desc_base);
	pipe = &bam.pipes[pipe_num];
	pipe->is_producer = is_producer;
	pipe->desc_base = desc_base;
	pipe->desc_base_pa = desc_base_pa;
	return bam_pipe_reinit(pipe);
}

struct bam_pipe_state *bam_pipe_reinit(struct bam_pipe_state *pipe)
{
	memset(pipe->desc_base, 0, BAM_DESC_FIFO_SIZE);
	pipe->read_offset = 0;
	pipe->write_offset = 0;
	pipe->last_offset = UINT16_MAX;
	dcache_clean_range(pipe->desc_base, BAM_DESC_FIFO_SIZE);
	bam_configure_pipe(pipe);
	if (!bam_pipe_enabled(pipe->pipe_num))
		return NULL;
	return pipe;
}

TEE_Result bam_pipe_transfer(struct bam_pipe_state *pipe, paddr_t pa,
			     uint64_t size, uint16_t flags)
{
	struct bam_iovec *entry;
	uint16_t next;

	if (!bam_pipe_enabled(pipe->pipe_num))
		return TEE_ERROR_BAD_STATE;
	if (size > UINT16_MAX || (!bam.lpae && high32_from_64(pa)))
		return TEE_ERROR_BAD_PARAMETERS;
	next = pipe->write_offset + BAM_DESC_ENTRY_SIZE;
	if (next == BAM_DESC_FIFO_SIZE)
		next = 0;
	if (next == pipe->read_offset)
		return TEE_ERROR_BUSY;
	if ((flags & BAM_IOVEC_FLAG_CMD) && pipe->last_offset != UINT16_MAX) {
		entry = &pipe->desc_base[pipe->last_offset /
					 sizeof(*pipe->desc_base)];
		assert(entry->flags &
		       (BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_NWD));
	}
	assert(!((flags & BAM_IOVEC_FLAG_CMD) &&
		 (flags & BAM_IOVEC_FLAG_IMM_CMD)));
	assert(!(flags & BAM_IOVEC_FLAG_NWD) ||
	       (flags & (BAM_IOVEC_FLAG_CMD | BAM_IOVEC_FLAG_EOT)));
	entry = &pipe->desc_base[pipe->write_offset /
				 sizeof(*pipe->desc_base)];
	entry->buf_pa = low32_from_64(pa);
	entry->buf_pa_msb = high32_from_64(pa) & BAM_LPAE_ADDR_MSB_MASK;
	entry->buf_size = size;
	entry->flags = flags & BAM_IOVEC_HW_FLAGS;
	pipe->last_offset = pipe->write_offset;
	pipe->write_offset = next;
	if (!(flags & BAM_IOVEC_FLAG_NO_SUBMIT)) {
		dcache_clean_range(pipe->desc_base, BAM_DESC_FIFO_SIZE);
		bam_submit_offset(pipe->pipe_num, next);
		dsb();
	}
	return TEE_SUCCESS;
}

TEE_Result bam_pipe_poll(struct bam_pipe_state *pipe)
{
	struct bam_iovec *entry;
	uint32_t end;

	end = bam_read_offset(pipe->pipe_num);
	while (pipe->read_offset != end) {
		entry = &pipe->desc_base[pipe->read_offset /
					 sizeof(*pipe->desc_base)];
		/*
		 * BAM may advance the descriptor offset after handing the data
		 * descriptor to CE, before CE clears its NWD indication.
		 * Command descriptors do not use NWD completion.
		 */
		if (!(entry->flags & BAM_IOVEC_FLAG_CMD) &&
		    bam_nwd_pending(pipe->pipe_num))
			break;
		pipe->read_offset += BAM_DESC_ENTRY_SIZE;
		if (pipe->read_offset == BAM_DESC_FIFO_SIZE)
			pipe->read_offset = 0;
		if (entry->flags & BAM_IOVEC_FLAG_EOT)
			return TEE_SUCCESS;
	}
	return TEE_ERROR_BUSY;
}
