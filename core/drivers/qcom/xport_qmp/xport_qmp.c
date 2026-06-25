// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "xport_qmp.h"
#include "xport_qmp_config.h"
#include "glink_xport.h"

/*
 * QMP Descriptor Bit Positions
 */
#define QMP_DESC_LOCAL_LINK_STATE_BIT		0
#define QMP_DESC_REMOTE_LINK_STATE_ACK_BIT	1
#define QMP_DESC_LOCAL_CH_STATE_BIT		2
#define QMP_DESC_REMOTE_CH_STATE_ACK_BIT	3
#define QMP_DESC_LOCAL_TX_BIT			4
#define QMP_DESC_REMOTE_TX_ACK_BIT		5
#define QMP_DESC_LOCAL_RX_DONE_BIT		6
#define QMP_DESC_REMOTE_RX_DONE_ACK_BIT		7
#define QMP_DESC_LOCAL_READ_INT_BIT		8
#define QMP_DESC_REMOTE_READ_INT_ACK_BIT	9

/*
 * QMP Descriptor Flag Manipulation Macros
 * Operate on in-RAM descriptor snapshots using READ_ONCE/WRITE_ONCE.
 */

#define QMP_DESC_WORD_READ(ctx, place) \
	READ_ONCE((ctx)->place##_desc.word)

#define QMP_DESC_WORD_WRITE(ctx, place, val) \
	WRITE_ONCE((ctx)->place##_desc.word, (val))

#define QMP_FLAG_GET(ctx, place, flag_bit) \
	((QMP_DESC_WORD_READ(ctx, place) >> (flag_bit)) & 1U)

#define QMP_FLAG_SET(ctx, place, flag_bit) \
	QMP_DESC_WORD_WRITE(ctx, place, \
		QMP_DESC_WORD_READ(ctx, place) | (1U << (flag_bit)))

#define QMP_FLAG_CLR(ctx, place, flag_bit) \
	QMP_DESC_WORD_WRITE(ctx, place, \
		QMP_DESC_WORD_READ(ctx, place) & ~(1U << (flag_bit)))

#define QMP_LOCAL_FLAG_TOGGLE(ctx, flag) \
	QMP_DESC_WORD_WRITE(ctx, local, \
		QMP_DESC_WORD_READ(ctx, local) ^ \
			(1U << QMP_DESC_LOCAL_##flag##_BIT))

#define QMP_LOCAL_FLAG_GET(ctx, flag) \
	QMP_FLAG_GET(ctx, local, QMP_DESC_LOCAL_##flag##_BIT)

#define QMP_LOCAL_FLAG_SET(ctx, flag) \
	QMP_FLAG_SET(ctx, local, QMP_DESC_LOCAL_##flag##_BIT)

#define QMP_LOCAL_FLAG_CLR(ctx, flag) \
	QMP_FLAG_CLR(ctx, local, QMP_DESC_LOCAL_##flag##_BIT)

#define QMP_LOCAL_FLAG_ACK_CLR(ctx, flag) \
	QMP_FLAG_CLR(ctx, local, QMP_DESC_REMOTE_##flag##_ACK_BIT)

#define QMP_REMOTE_FLAG_GET(ctx, flag) \
	QMP_FLAG_GET(ctx, remote, QMP_DESC_LOCAL_##flag##_BIT)

#define QMP_REMOTE_ACKED_CHECK(ctx, flag) \
	(QMP_LOCAL_FLAG_GET(ctx, flag) == \
	 QMP_FLAG_GET(ctx, remote, QMP_DESC_REMOTE_##flag##_ACK_BIT))

#define QMP_LOCAL_ACKED_CHECK(ctx, flag) \
	(QMP_REMOTE_FLAG_GET(ctx, flag) == \
	 QMP_FLAG_GET(ctx, local, QMP_DESC_REMOTE_##flag##_ACK_BIT))

#define QMP_LOCAL_ACK_UPDATE(ctx, flag) \
	do { \
		uint32_t __ack_bit = QMP_DESC_REMOTE_##flag##_ACK_BIT; \
		if (QMP_REMOTE_FLAG_GET(ctx, flag)) \
			QMP_FLAG_SET(ctx, local, __ack_bit); \
		else \
			QMP_FLAG_CLR(ctx, local, __ack_bit); \
	} while (0)

#define QMP_REMOTE_FLAG_TOGGLED_CHECK(ctx, flag) \
	(QMP_REMOTE_FLAG_GET(ctx, flag) != \
	 QMP_FLAG_GET(ctx, local, QMP_DESC_REMOTE_##flag##_ACK_BIT))

enum xport_qmp_state {
	LINK_DOWN = 0,
	LINK_NEGOTIATION = 1,
	LINK_UP = 2,
	LOCAL_CONNECTING = 3,
	LOCAL_CONNECTED = 4,
	E2ECONNECTED = 5,
	LOCAL_DISCONNECTING = 6,
};

struct xport_qmp_desc {
	uint32_t local_link_state:1;
	uint32_t remote_link_state_ack:1;
	uint32_t local_ch_state:1;
	uint32_t remote_ch_state_ack:1;
	uint32_t local_tx:1;
	uint32_t remote_tx_ack:1;
	uint32_t local_rx_done:1;
	uint32_t remote_rx_done_ack:1;
	uint32_t local_read_int:1;
	uint32_t remote_read_int_ack:1;
	uint32_t reserved:6;
	uint32_t cur_frag_size:8;
	uint32_t rem_frags_cnt:8;
};

/*
 * Union to access descriptor as a bitfield struct or atomic 32-bit word.
 * Enables READ/WRITE_ONCE operations while avoiding strict-aliasing warnings.
 */
union qmp_desc_word {
	struct xport_qmp_desc desc;
	uint32_t word;
};

struct xport_qmp_ctx {
	struct glink_transport_if xport_if;
	const struct xport_qmp_config *cfg;
	unsigned int cs;
	enum xport_qmp_state state;
	union qmp_desc_word local_desc;
	union qmp_desc_word remote_desc;
	struct glink_core_tx_pkt *tx_pkt_ctx;
	uint8_t *rx_pkt_buf;
	uint32_t rx_pkt_size;
	uint32_t rx_pkt_read_size;
	vaddr_t shared_local_desc;
	vaddr_t shared_remote_desc;
	vaddr_t shared_local_mailbox;
	vaddr_t shared_remote_mailbox;
	uint32_t cfg_local_mailbox_size;
	uint32_t cfg_tx_max_pkt_size;
	uint32_t cfg_remote_mailbox_size;
	uint32_t cfg_rx_max_pkt_size;
};

static struct xport_qmp_ctx xport_qmp_ctxs[GLINK_CFG_MAX_REMOTE_HOSTS];
static struct xport_qmp_ctx *g_tmel_ctx;

static void xport_qmp_intr_send(struct xport_qmp_ctx *ctx)
{
	uint32_t local_desc = READ_ONCE(ctx->local_desc.word);
	vaddr_t reg_addr = ctx->cfg->irq_out.reg_addr;
	uint32_t reg_val = ctx->cfg->irq_out.reg_val;

	io_write32(ctx->shared_local_desc, local_desc);
	io_setbits32(reg_addr, reg_val);
	io_clrbits32(reg_addr, reg_val);
}

static void xport_qmp_mailbox_write(struct xport_qmp_ctx *ctx,
				    void *buf,
				    uint32_t size)
{
	uint32_t size_remainder = size % 4;
	uint32_t size_rounddown = size - size_remainder;
	uint32_t *src_end = (uint32_t *)((uintptr_t)buf + size_rounddown);
	uint32_t *src = (uint32_t *)buf;
	vaddr_t dst = ctx->shared_local_mailbox;
	uint32_t data = 0;

	while (src < src_end) {
		memcpy(&data, src, sizeof(uint32_t));
		io_write32(dst, data);
		dst += sizeof(uint32_t);
		src++;
	}

	if (size_remainder) {
		data = 0;
		memcpy(&data, src, size_remainder);
		io_write32(dst, data);
	}
}

static void xport_qmp_mailbox_read(struct xport_qmp_ctx *ctx,
				   void *buf,
				   uint32_t size)
{
	uint32_t size_remainder = size % 4;
	uint32_t size_rounddown = size - size_remainder;
	uint32_t *dst_end = (uint32_t *)((uintptr_t)buf + size_rounddown);
	vaddr_t src = ctx->shared_remote_mailbox;
	uint32_t *dst = (uint32_t *)buf;

	while (dst < dst_end) {
		*dst++ = io_read32(src);
		src += sizeof(uint32_t);
	}

	if (size_remainder) {
		uint32_t data = io_read32(src);

		memcpy(dst, &data, size_remainder);
	}
}

static void xport_qmp_pkt_send(struct xport_qmp_ctx *ctx)
{
	struct glink_core_tx_pkt *pkt = ctx->tx_pkt_ctx;
	uint32_t mbox_size = ctx->cfg_local_mailbox_size;
	size_t remaining = pkt->size_remaining;
	uint32_t cur_frag_size = 0;
	uint32_t rem_frags_cnt = 0;

	if (!remaining)
		return;

	if (remaining <= mbox_size) {
		pkt->size_remaining = 0;
		cur_frag_size = remaining;
		rem_frags_cnt = 0;
	} else {
		cur_frag_size = mbox_size;
		pkt->size_remaining -= cur_frag_size;
		rem_frags_cnt = (remaining / mbox_size) - 1;
		rem_frags_cnt += ((remaining % mbox_size) != 0) ? 1 : 0;
	}

	xport_qmp_mailbox_write(ctx,
				(void *)((uintptr_t)pkt->data +
					 (pkt->size - remaining)),
				cur_frag_size);

	ctx->local_desc.desc.cur_frag_size = cur_frag_size;
	ctx->local_desc.desc.rem_frags_cnt = rem_frags_cnt;

	QMP_LOCAL_FLAG_TOGGLE(ctx, TX);
}

static void xport_qmp_state_ch_flags_clr(struct xport_qmp_ctx *ctx)
{
	QMP_LOCAL_FLAG_CLR(ctx, CH_STATE);
	QMP_LOCAL_FLAG_ACK_CLR(ctx, CH_STATE);
	QMP_LOCAL_FLAG_CLR(ctx, TX);
	QMP_LOCAL_FLAG_ACK_CLR(ctx, TX);
	QMP_LOCAL_FLAG_CLR(ctx, RX_DONE);
	QMP_LOCAL_FLAG_ACK_CLR(ctx, RX_DONE);
	QMP_LOCAL_FLAG_CLR(ctx, READ_INT);
	QMP_LOCAL_FLAG_ACK_CLR(ctx, READ_INT);

	ctx->local_desc.desc.cur_frag_size = 0;
	ctx->local_desc.desc.rem_frags_cnt = 0;

	ctx->tx_pkt_ctx = NULL;
	ctx->rx_pkt_buf = NULL;
	ctx->rx_pkt_size = 0;
	ctx->rx_pkt_read_size = 0;
}

static bool xport_qmp_state_handler(struct xport_qmp_ctx *ctx,
				    uint32_t *exceptions)
{
	struct glink_transport_if *xport_if = &ctx->xport_if;
	bool notify_remote_close = false;
	bool notify_remote_open = false;
	bool notify_close_ack = false;
	bool notify_linkup = false;
	bool ret = true;

	if (ctx->state >= LINK_UP && !QMP_REMOTE_FLAG_GET(ctx, LINK_STATE)) {
		ctx->state = LINK_NEGOTIATION;

		cpu_spin_unlock_xrestore(&ctx->cs, *exceptions);
		glink_core_rx_cmd_link_down(xport_if);
		*exceptions = cpu_spin_lock_xsave(&ctx->cs);

		QMP_LOCAL_ACK_UPDATE(ctx, LINK_STATE);
		return ret;
	}

	switch (ctx->state) {
	case LINK_DOWN:
		if (!QMP_REMOTE_ACKED_CHECK(ctx, LINK_STATE)) {
			QMP_LOCAL_ACK_UPDATE(ctx, LINK_STATE);
			break;
		}

		if (QMP_LOCAL_FLAG_GET(ctx, LINK_STATE)) {
			QMP_LOCAL_FLAG_CLR(ctx, LINK_STATE);
			break;
		}

		QMP_LOCAL_FLAG_SET(ctx, LINK_STATE);
		ctx->state = LINK_NEGOTIATION;
		break;

	case LINK_NEGOTIATION:
		if (!QMP_REMOTE_ACKED_CHECK(ctx, LINK_STATE)) {
			QMP_LOCAL_ACK_UPDATE(ctx, LINK_STATE);
			break;
		}

		if (!QMP_REMOTE_FLAG_GET(ctx, LINK_STATE)) {
			ret = false;
			break;
		}

		xport_qmp_state_ch_flags_clr(ctx);
		QMP_LOCAL_ACK_UPDATE(ctx, LINK_STATE);
		ctx->state = LINK_UP;
		notify_linkup = true;
		break;

	case LINK_UP:
		ret = false;
		break;

	case LOCAL_CONNECTING:
		QMP_LOCAL_ACK_UPDATE(ctx, CH_STATE);

		if (!QMP_REMOTE_ACKED_CHECK(ctx, CH_STATE))
			break;

		if (!QMP_REMOTE_FLAG_GET(ctx, CH_STATE))
			break;

		ctx->state = E2ECONNECTED;
		notify_remote_open = true;
		break;

	case E2ECONNECTED:
		if (!QMP_REMOTE_FLAG_GET(ctx, CH_STATE)) {
			ctx->state = LOCAL_CONNECTING;
			QMP_LOCAL_ACK_UPDATE(ctx, CH_STATE);
			notify_remote_close = true;
			break;
		}
		ret = false;
		break;

	case LOCAL_DISCONNECTING:
		if (!QMP_REMOTE_FLAG_GET(ctx, CH_STATE) &&
		    !QMP_LOCAL_ACKED_CHECK(ctx, CH_STATE))
			QMP_LOCAL_ACK_UPDATE(ctx, CH_STATE);

		if (!QMP_REMOTE_ACKED_CHECK(ctx, CH_STATE)) {
			ret = false;
			break;
		}

		xport_qmp_state_ch_flags_clr(ctx);
		ctx->state = LINK_UP;
		notify_close_ack = true;
		break;

	default:
		ret = false;
		break;
	}

	cpu_spin_unlock_xrestore(&ctx->cs, *exceptions);

	if (notify_close_ack)
		glink_core_rx_cmd_ch_close_ack(xport_if);
	if (notify_remote_open)
		glink_core_rx_cmd_remote_open(xport_if);
	if (notify_remote_close)
		glink_core_rx_cmd_remote_close(xport_if);
	if (notify_linkup)
		glink_core_rx_cmd_link_up(xport_if);

	*exceptions = cpu_spin_lock_xsave(&ctx->cs);

	return ret;
}

static bool xport_qmp_tx_handler(struct xport_qmp_ctx *ctx,
				 uint32_t *exceptions)
{
	struct glink_core_tx_pkt *pkt = ctx->tx_pkt_ctx;
	bool ret = false;

	if (!pkt || !pkt->data)
		return ret;

	if (pkt->size_remaining) {
		if (QMP_REMOTE_ACKED_CHECK(ctx, TX)) {
			xport_qmp_pkt_send(ctx);
			ret = true;
		}
	} else if (QMP_REMOTE_FLAG_TOGGLED_CHECK(ctx, RX_DONE)) {
		QMP_LOCAL_ACK_UPDATE(ctx, RX_DONE);
		ctx->tx_pkt_ctx = NULL;

		cpu_spin_unlock_xrestore(&ctx->cs, *exceptions);
		glink_core_rx_cmd_tx_done(&ctx->xport_if, pkt);
		*exceptions = cpu_spin_lock_xsave(&ctx->cs);

		ret = true;
	}

	return ret;
}

static bool xport_qmp_rx_handler(struct xport_qmp_ctx *ctx,
				 uint32_t *exceptions)
{
	uint32_t mbox_size = ctx->cfg_remote_mailbox_size;
	uint32_t *rx_read = &ctx->rx_pkt_read_size;
	uint32_t *rx_size = &ctx->rx_pkt_size;
	uint32_t cur_frag_size = 0;
	uint32_t rem_frags_cnt = 0;
	bool ret = false;

	if (!QMP_REMOTE_FLAG_TOGGLED_CHECK(ctx, TX))
		return ret;

	cur_frag_size = ctx->remote_desc.desc.cur_frag_size;
	rem_frags_cnt = ctx->remote_desc.desc.rem_frags_cnt;

	if (!cur_frag_size || cur_frag_size > mbox_size) {
		DMSG("RX fragment size(%u) invalid (max %u)",
		     cur_frag_size, mbox_size);
		QMP_LOCAL_ACK_UPDATE(ctx, TX);
		return true;
	}

	if (!*rx_size && !*rx_read) {
		uint64_t total = (uint64_t)cur_frag_size +
				 (uint64_t)rem_frags_cnt * mbox_size;

		if (total > ctx->cfg_rx_max_pkt_size) {
			DMSG("Max RX size(%llu) > max pkt size(%u)",
			     (unsigned long long)total,
			     ctx->cfg_rx_max_pkt_size);
			QMP_LOCAL_ACK_UPDATE(ctx, TX);
			return true;
		}

		*rx_size = (uint32_t)total;

		ctx->rx_pkt_buf = (uint8_t *)ctx->cfg->rx_pkt_static_buf;
		*rx_read = cur_frag_size;

		if (ctx->cfg->rx_pkt_static_buf != ctx->shared_remote_mailbox)
			xport_qmp_mailbox_read(ctx, ctx->rx_pkt_buf,
					       cur_frag_size);

		QMP_LOCAL_ACK_UPDATE(ctx, TX);
		ret = true;

		if (*rx_size == *rx_read) {
			cpu_spin_unlock_xrestore(&ctx->cs, *exceptions);
			glink_core_rx_cmd_data(&ctx->xport_if,
					       ctx->rx_pkt_buf, *rx_size);
			*exceptions = cpu_spin_lock_xsave(&ctx->cs);
		}
	} else if (*rx_size && *rx_read != *rx_size) {
		if ((*rx_read + cur_frag_size +
		     (rem_frags_cnt * mbox_size)) > *rx_size) {
			DMSG("RX size overflow");
			*rx_size = 0;
			*rx_read = 0;
			QMP_LOCAL_ACK_UPDATE(ctx, TX);
			return true;
		}

		xport_qmp_mailbox_read(ctx, &ctx->rx_pkt_buf[*rx_read],
				       cur_frag_size);
		*rx_read += cur_frag_size;

		QMP_LOCAL_ACK_UPDATE(ctx, TX);
		ret = true;

		if (!rem_frags_cnt &&
		    (*rx_size - *rx_read) <= mbox_size) {
			*rx_size = *rx_read;

			cpu_spin_unlock_xrestore(&ctx->cs, *exceptions);
			glink_core_rx_cmd_data(&ctx->xport_if,
					       ctx->rx_pkt_buf, *rx_size);
			*exceptions = cpu_spin_lock_xsave(&ctx->cs);
		}
	}

	return ret;
}

static enum itr_return xport_qmp_isr(struct itr_handler *h __unused)
{
	struct xport_qmp_ctx *ctx = g_tmel_ctx;
	enum xport_qmp_state prv_state = LINK_DOWN;
	uint32_t shared_remote_desc = 0;
	uint32_t exceptions = 0;
	bool intr_send = false;

	if (!ctx)
		return ITRR_HANDLED;

	exceptions = cpu_spin_lock_xsave(&ctx->cs);

	shared_remote_desc = io_read32(ctx->shared_remote_desc);
	WRITE_ONCE(ctx->remote_desc.word, shared_remote_desc);

	do {
		prv_state = ctx->state;
		intr_send |= xport_qmp_state_handler(ctx, &exceptions);
	} while (prv_state != ctx->state);

	if (ctx->state == E2ECONNECTED) {
		intr_send |= xport_qmp_tx_handler(ctx, &exceptions);
		intr_send |= xport_qmp_rx_handler(ctx, &exceptions);
	}

	if (intr_send)
		xport_qmp_intr_send(ctx);

	cpu_spin_unlock_xrestore(&ctx->cs, exceptions);

	return ITRR_HANDLED;
}

static enum glink_err_type
xport_qmp_tx_cmd_ch_open(struct glink_transport_if *if_ptr)
{
	struct xport_qmp_ctx *ctx = (struct xport_qmp_ctx *)if_ptr;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&ctx->cs);

	if (ctx->state != LINK_UP) {
		cpu_spin_unlock_xrestore(&ctx->cs, exceptions);
		return GLINK_STATUS_NOT_INIT;
	}

	QMP_LOCAL_FLAG_SET(ctx, CH_STATE);
	ctx->state = LOCAL_CONNECTING;
	xport_qmp_intr_send(ctx);

	cpu_spin_unlock_xrestore(&ctx->cs, exceptions);

	return GLINK_STATUS_SUCCESS;
}

static enum glink_err_type
xport_qmp_tx_cmd_ch_close(struct glink_transport_if *if_ptr)
{
	struct xport_qmp_ctx *ctx = (struct xport_qmp_ctx *)if_ptr;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&ctx->cs);

	if (ctx->state == LOCAL_CONNECTED ||
	    ctx->state == LOCAL_CONNECTING ||
	    ctx->state == E2ECONNECTED) {
		QMP_LOCAL_FLAG_CLR(ctx, CH_STATE);
		ctx->state = LOCAL_DISCONNECTING;
		xport_qmp_intr_send(ctx);
	}

	cpu_spin_unlock_xrestore(&ctx->cs, exceptions);

	return GLINK_STATUS_SUCCESS;
}

static enum glink_err_type
xport_qmp_tx_cmd_local_rx_done(struct glink_transport_if *if_ptr,
			       const void *ptr)
{
	struct xport_qmp_ctx *ctx = (struct xport_qmp_ctx *)if_ptr;
	enum glink_err_type status = GLINK_STATUS_SUCCESS;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&ctx->cs);

	if (ctx->state != E2ECONNECTED) {
		status = GLINK_STATUS_CH_NOT_FULLY_OPENED;
		goto unlock_return;
	}

	if (ctx->rx_pkt_buf != ptr ||
	    !ctx->rx_pkt_size ||
	    ctx->rx_pkt_size != ctx->rx_pkt_read_size) {
		status = GLINK_STATUS_INVALID_PARAM;
		goto unlock_return;
	}

	ctx->rx_pkt_size = 0;
	ctx->rx_pkt_buf = NULL;
	ctx->rx_pkt_read_size = 0;

	QMP_LOCAL_FLAG_TOGGLE(ctx, RX_DONE);
	xport_qmp_intr_send(ctx);

unlock_return:
	cpu_spin_unlock_xrestore(&ctx->cs, exceptions);
	return status;
}

static enum glink_err_type xport_qmp_tx_data(struct glink_transport_if *if_ptr,
					     struct glink_core_tx_pkt *pkt)
{
	struct xport_qmp_ctx *ctx = (struct xport_qmp_ctx *)if_ptr;
	enum glink_err_type ret = GLINK_STATUS_SUCCESS;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&ctx->cs);

	if (ctx->state != E2ECONNECTED) {
		ret = GLINK_STATUS_CH_NOT_FULLY_OPENED;
		goto exit;
	}

	if (pkt->size > ctx->cfg_tx_max_pkt_size) {
		ret = GLINK_STATUS_OUT_OF_RESOURCES;
		goto exit;
	}

	ctx->tx_pkt_ctx = pkt;
	xport_qmp_pkt_send(ctx);
	xport_qmp_intr_send(ctx);

exit:
	cpu_spin_unlock_xrestore(&ctx->cs, exceptions);
	return ret;
}

void xport_qmp_init(void)
{
	uint32_t i = 0;

	for (i = 0; i < GLINK_CFG_MAX_REMOTE_HOSTS; i++) {
		struct xport_qmp_ctx *ctx = &xport_qmp_ctxs[i];
		struct glink_transport_if *xport_if = &ctx->xport_if;
		const struct xport_qmp_config *cfg = xport_qmp_get_config(i);
		const size_t desc_size = sizeof(struct xport_qmp_desc);
		struct xport_qmp_config *cfg_rw = NULL;
		uint32_t shared_loc_desc = 0;
		vaddr_t mapped_addr = 0;
		vaddr_t desc_addr = 0;
		TEE_Result res = TEE_SUCCESS;

		if (!cfg)
			continue;

		cfg_rw = (struct xport_qmp_config *)cfg;

		mapped_addr = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
				cfg->local_shared_mem,
				cfg->local_shared_mem_size);
		if (!mapped_addr)
			panic("Failed to map local shared memory");

		mapped_addr = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
				cfg->remote_shared_mem,
				cfg->remote_shared_mem_size);
		if (!mapped_addr)
			panic("Failed to map remote shared memory");
		cfg_rw->rx_pkt_static_buf = mapped_addr + desc_size;

		mapped_addr = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
				cfg->irq_out.reg_addr, sizeof(uint32_t));
		if (!mapped_addr)
			panic("Failed to map IPC interrupt register");
		cfg_rw->irq_out.reg_addr = mapped_addr;

		ctx->cfg = cfg;
		ctx->cs = SPINLOCK_UNLOCK;
		ctx->state = LINK_DOWN;

		desc_addr = (vaddr_t)phys_to_virt(cfg->local_shared_mem,
						  MEM_AREA_IO_SEC, desc_size);
		ctx->shared_local_desc = desc_addr;
		ctx->shared_local_mailbox = desc_addr + desc_size;
		ctx->cfg_local_mailbox_size =
			cfg->local_shared_mem_size - desc_size;

		desc_addr = (vaddr_t)phys_to_virt(cfg->remote_shared_mem,
						  MEM_AREA_IO_SEC, desc_size);
		ctx->shared_remote_desc = desc_addr;
		ctx->shared_remote_mailbox = desc_addr + desc_size;
		ctx->cfg_remote_mailbox_size =
			cfg->remote_shared_mem_size - desc_size;

		ctx->cfg_tx_max_pkt_size = cfg->tx_max_pkt_size;
		ctx->cfg_rx_max_pkt_size = cfg->rx_max_pkt_size;

		shared_loc_desc = io_read32(ctx->shared_local_desc);
		WRITE_ONCE(ctx->local_desc.word, shared_loc_desc);

		g_tmel_ctx = ctx;

		xport_if->remote_ss = cfg->remote_ss;
		xport_if->ch_name = cfg->ch_name;
		xport_if->tx_cmd_ch_open = xport_qmp_tx_cmd_ch_open;
		xport_if->tx_cmd_ch_close = xport_qmp_tx_cmd_ch_close;
		xport_if->tx_cmd_local_rx_done = xport_qmp_tx_cmd_local_rx_done;
		xport_if->tx_data = xport_qmp_tx_data;

		glink_core_register_transport(xport_if);

		res = interrupt_create_handler(interrupt_get_main_chip(),
					       cfg->irq_in,
					       xport_qmp_isr, 0u, 0u,
					       NULL);
		if (res)
			panic("Failed to register QMP interrupt");

		interrupt_enable(interrupt_get_main_chip(), cfg->irq_in);

		xport_qmp_isr(NULL);
	}
}
