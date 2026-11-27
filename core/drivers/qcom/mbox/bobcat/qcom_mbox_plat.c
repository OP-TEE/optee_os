// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * The QMP-Lite link of the bobcat SoCs to TME-Lite.
 * TME_QMP_LITE_{INBOUND,OUTBOUND}_MBOX_ADDR are named from the TME's point of
 * view: INBOUND is what the TME reads (our TX mailbox), OUTBOUND is what it
 * writes (our RX mailbox). Each starts with the 4-byte QMP-Lite descriptor
 * register, followed by the payload.
 */

#include <assert.h>
#include <drivers/mailbox_controller.h>
#include <drivers/qcom/mbox/qcom_mbox.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "qcom_mbox_qmp_lite.h"

/* The descriptor register followed by the payload */
#define TME_QMP_LITE_MBOX_REGION_SIZE \
	(QMP_LITE_DESC_SIZE + TME_QMP_LITE_MBOX_SIZE)

/* The doorbell is a single 32-bit register */
#define TME_QMP_LITE_IRQ_OUT_REG_SIZE	sizeof(uint32_t)

/* Doorbell bit in the remote-signal register (APCS_*_TZ_IPC_INTERRUPT) */
#define TME_QMP_LITE_IRQ_OUT_BIT_MASK	BIT32(21)

static_assert(TME_QMP_LITE_MBOX_SIZE > 0 &&
	      TME_QMP_LITE_MBOX_SIZE <= QMP_LITE_MAX_MSG_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
			TME_QMP_LITE_MBOX_REGION_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_INBOUND_MBOX_ADDR,
			TME_QMP_LITE_MBOX_REGION_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_IRQ_OUT_REG_ADDR,
			TME_QMP_LITE_IRQ_OUT_REG_SIZE);

static struct qcom_mbox_qmp_lite_config tme_qmp_lite_cfg;
static struct qcom_mbox_qmp_lite_priv tme_qmp_lite_priv;

/* The framework keeps a pointer to the descriptor */
static const struct mbox_controller_desc tme_qmp_lite_desc = {
	.ops = &qcom_mbox_qmp_lite_ops,
	.priv = &tme_qmp_lite_priv,
};

static struct mbox_controller *tme_qmp_lite_controller;

static TEE_Result plat_qcom_mbox_init(void)
{
	vaddr_t tx_base = 0;
	vaddr_t rx_base = 0;
	vaddr_t irq_reg = 0;

	tx_base = core_mmu_get_va(TME_QMP_LITE_INBOUND_MBOX_ADDR,
				  MEM_AREA_IO_SEC,
				  TME_QMP_LITE_MBOX_REGION_SIZE);
	if (!tx_base) {
		EMSG("mbox_plat: failed to map TX mbox at PA %#" PRIxPA,
		     TME_QMP_LITE_INBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	rx_base = core_mmu_get_va(TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
				  MEM_AREA_IO_SEC,
				  TME_QMP_LITE_MBOX_REGION_SIZE);
	if (!rx_base) {
		EMSG("mbox_plat: failed to map RX mbox at PA %#" PRIxPA,
		     TME_QMP_LITE_OUTBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	irq_reg = core_mmu_get_va(TME_QMP_LITE_IRQ_OUT_REG_ADDR,
				  MEM_AREA_IO_SEC,
				  TME_QMP_LITE_IRQ_OUT_REG_SIZE);
	if (!irq_reg) {
		EMSG("mbox_plat: failed to map IRQ-out reg at PA %#" PRIxPA,
		     TME_QMP_LITE_IRQ_OUT_REG_ADDR);
		return TEE_ERROR_GENERIC;
	}

	tme_qmp_lite_cfg.local_desc_base = tx_base;
	tme_qmp_lite_cfg.remote_desc_base = rx_base;
	tme_qmp_lite_cfg.local_mbox_size = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_mbox_size = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_signal.reg = irq_reg;
	tme_qmp_lite_cfg.remote_signal.value = TME_QMP_LITE_IRQ_OUT_BIT_MASK;

	tme_qmp_lite_priv.cfg = &tme_qmp_lite_cfg;

	DMSG("mbox_plat: TX VA %#" PRIxVA " RX VA %#" PRIxVA
	     " IRQ-out VA %#" PRIxVA, tx_base, rx_base, irq_reg);

	return mbox_controller_register(&tme_qmp_lite_controller,
					&tme_qmp_lite_desc);
}

struct mbox_controller *qcom_mbox_get_controller(void)
{
	return tme_qmp_lite_controller;
}

early_init(plat_qcom_mbox_init);
