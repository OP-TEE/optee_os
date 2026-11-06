// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Mailbox platform data: a single QMP-Lite channel, "tme-qmp-lite", to the
 * TME.  The addresses come from the per-variant target_config.h.
 *
 * TME_QMP_LITE_{INBOUND,OUTBOUND}_MBOX_ADDR are named from the TME's point of
 * view: INBOUND is what the TME reads (our TX mailbox) and OUTBOUND is what
 * the TME writes (our RX mailbox).  Each region starts with the 4-byte
 * QMP-Lite descriptor register, followed by the message payload.
 * TME_QMP_LITE_IRQ_OUT_REG_ADDR is the doorbell register written to signal
 * the TME after a send.
 *
 * The channel is polling-only by design: the framework supports IRQ-assisted
 * wakeup, but this platform does not use it, so itr_chip is NULL and
 * TME_QMP_LITE_IRQ_IN is left unused.
 */

#include <initcall.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include "qcom_mbox_private.h"
#include "qcom_mbox_qmp_lite.h"

/* The mailboxes and the doorbell register are secure device memory. */
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_INBOUND_MBOX_ADDR,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_IRQ_OUT_REG_ADDR,
			CORE_MMU_PGDIR_SIZE);

static bool mbox_initialized;

static struct qcom_mbox_qmp_lite_config tme_qmp_lite_cfg;
static struct qcom_mbox_qmp_lite_priv   tme_qmp_lite_priv;

/*
 * transport_cfg is filled in by plat_qcom_mbox_init() once the physical
 * regions have been mapped.
 */
static struct qcom_mbox_chan_config mbox_configs[] = {
	{
		.name           = "tme-qmp-lite",
		.ops            = &qcom_mbox_qmp_lite_ops,
		.transport_cfg  = NULL,
		.transport_priv = &tme_qmp_lite_priv,
		.itr_chip       = NULL,
		.itr_num        = 0,
	},
};

static struct qcom_mbox_chan_slot mbox_slots[ARRAY_SIZE(mbox_configs)];

static const struct qcom_mbox_plat_data mbox_plat_data = {
	.configs      = mbox_configs,
	.slots        = mbox_slots,
	.num_channels = ARRAY_SIZE(mbox_configs),
};

/*
 * Map the mailbox regions and fill in the transport config.  Registered with
 * driver_init() so it runs once the MMU is up.
 */
static TEE_Result plat_qcom_mbox_init(void)
{
	vaddr_t tx_base = 0;
	vaddr_t rx_base = 0;
	vaddr_t irq_reg = 0;

	if (mbox_initialized)
		return TEE_SUCCESS;

	/* TX mailbox (OP-TEE -> TME), INBOUND from the TME's side */
	tx_base = (vaddr_t)phys_to_virt(TME_QMP_LITE_INBOUND_MBOX_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!tx_base) {
		EMSG("mbox_plat: failed to map TX mbox at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_INBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	/* RX mailbox (TME -> OP-TEE), OUTBOUND from the TME's side */
	rx_base = (vaddr_t)phys_to_virt(TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!rx_base) {
		EMSG("mbox_plat: failed to map RX mbox at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_OUTBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	/* Doorbell register (OP-TEE -> TME) */
	irq_reg = (vaddr_t)phys_to_virt(TME_QMP_LITE_IRQ_OUT_REG_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!irq_reg) {
		EMSG("mbox_plat: failed to map IRQ-out reg at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_IRQ_OUT_REG_ADDR);
		return TEE_ERROR_GENERIC;
	}

	tme_qmp_lite_cfg.local_desc_base     = tx_base;
	tme_qmp_lite_cfg.remote_desc_base    = rx_base;
	tme_qmp_lite_cfg.local_mbox_size     = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_mbox_size    = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_signal.reg   = irq_reg;
	tme_qmp_lite_cfg.remote_signal.value = TME_QMP_LITE_IRQ_OUT_BIT_MASK;

	mbox_configs[0].transport_cfg = &tme_qmp_lite_cfg;
	mbox_initialized = true;

	IMSG("mbox_plat: TX va=0x%08lx RX va=0x%08lx IRQ-out va=0x%08lx",
	     (unsigned long)tx_base, (unsigned long)rx_base,
	     (unsigned long)irq_reg);

	return TEE_SUCCESS;
}

driver_init(plat_qcom_mbox_init);

const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void)
{
	/*
	 * A caller may get here before the driver-init phase has run, so
	 * initialise on demand; plat_qcom_mbox_init() is idempotent.
	 */
	if (!mbox_initialized) {
		TEE_Result res = plat_qcom_mbox_init();

		if (res != TEE_SUCCESS) {
			EMSG("mbox_plat: lazy init failed: %#x", res);
			return NULL;
		}
	}

	return &mbox_plat_data;
}
