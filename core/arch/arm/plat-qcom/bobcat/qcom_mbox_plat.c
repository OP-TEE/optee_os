// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2025, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Bobcat (IPQ52xx / IPQ96xx) mailbox platform integration.
 *
 * This file implements plat_qcom_mbox_get_data() for the Bobcat platform
 * family.  It defines one mailbox channel:
 *
 *   "tme-qmp-lite" — QMP-Lite channel to the TME (Trusted Memory Engine).
 *                    Used for OP-TEE ↔ TME communication.
 *
 * Hardware layout (per-variant addresses in target_config.h):
 *
 * TME_QMP_LITE_INBOUND/OUTBOUND_MBOX_ADDR are named from TME's point of
 * view, matching the downstream xport_qmp_config.c convention:
 *
 *   TME_QMP_LITE_INBOUND_MBOX_ADDR  — TX mailbox (OP-TEE → TME): OP-TEE
 *                                      writes here to send messages to TME.
 *                                      The QMP-Lite descriptor register is
 *                                      at offset 0; the message payload
 *                                      follows at offset 4.
 *
 *   TME_QMP_LITE_OUTBOUND_MBOX_ADDR — RX mailbox (TME → OP-TEE): OP-TEE
 *                                      reads here to receive messages from
 *                                      TME.  Same layout.
 *
 *   TME_QMP_LITE_IRQ_OUT_REG_ADDR   — APCS TZ IPC interrupt register.
 *                                      OP-TEE writes
 *                                      TME_QMP_LITE_IRQ_OUT_BIT_MASK here
 *                                      to signal TME after sending a message.
 *
 * IRQ-assisted wakeup
 * -------------------
 * itr_chip/itr_num are filled in at runtime by plat_qcom_mbox_init(), same
 * as transport_cfg, since interrupt_get_main_chip() is not a compile-time
 * constant.  This lets qcom_mbox_enable_irq() register TME_QMP_LITE_IRQ_IN
 * and wake callers instead of being polled at full rate.
 */

#include <initcall.h>
#include <kernel/interrupt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <trace.h>
#include <util.h>

#include <drivers/qcom/mbox/qcom_mbox_plat.h>
#include <drivers/qcom/mbox/qcom_mbox_qmp_lite.h>

/*
 * Register physical memory regions.
 *
 * TX and RX mailboxes are in the TME secure address space → IO_SEC.
 * The APCS TZ IPC interrupt register is also in the secure address space.
 *
 * Each register_phys_mem_pgdir() call maps a CORE_MMU_PGDIR_SIZE (2 MB)
 * region aligned to the page-directory boundary that contains the given
 * physical address.
 */
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_INBOUND_MBOX_ADDR,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, TME_QMP_LITE_IRQ_OUT_REG_ADDR,
			CORE_MMU_PGDIR_SIZE);

/* Set to true after plat_qcom_mbox_init() completes successfully. */
static bool bobcat_mbox_initialized;

/* QMP-Lite transport configuration — virtual addresses filled by init. */
static struct qcom_mbox_qmp_lite_config tme_qmp_lite_cfg;
static struct qcom_mbox_qmp_lite_priv   tme_qmp_lite_priv;

/*
 * Channel configuration table.
 *
 * transport_cfg is NULL here and set by bobcat_mbox_init() after the
 * physical regions have been mapped to virtual addresses.
 */
static struct qcom_mbox_chan_config bobcat_mbox_configs[] = {
	{
		/*
		 * TME QMP-Lite channel.
		 *
		 * Used for communication with the TME (Trusted Memory Engine).
		 */
		.name           = "tme-qmp-lite",
		.ops            = &qcom_mbox_qmp_lite_ops,
		/* transport_cfg and itr_chip: set in plat_qcom_mbox_init() */
		.transport_cfg  = NULL,
		.transport_priv = &tme_qmp_lite_priv,
		.itr_chip       = NULL,
		.itr_num        = TME_QMP_LITE_IRQ_IN,
	},
};

/* One slot per channel — allocated statically. */
static struct qcom_mbox_chan_slot
	bobcat_mbox_slots[ARRAY_SIZE(bobcat_mbox_configs)];

/* Platform data descriptor returned by plat_qcom_mbox_get_data(). */
static const struct qcom_mbox_plat_data bobcat_mbox_plat_data = {
	.configs      = bobcat_mbox_configs,
	.slots        = bobcat_mbox_slots,
	.num_channels = ARRAY_SIZE(bobcat_mbox_configs),
};

/*
 * plat_qcom_mbox_init() — map physical regions and populate transport config.
 *
 * Registered with driver_init() so that OP-TEE calls it automatically
 * during the driver-initialization phase of boot, after the MMU is active.
 * Converts the physical addresses from target_config.h to virtual addresses
 * and stores them in the transport configuration structure.
 *
 * local_desc_base  = TX mailbox (OP-TEE → TME): OP-TEE writes here.
 * remote_desc_base = RX mailbox (TME → OP-TEE): OP-TEE reads here.
 * remote_signal    = APCS TZ IPC register: OP-TEE writes to signal TME.
 */
static TEE_Result plat_qcom_mbox_init(void)
{
	vaddr_t tx_base = 0;
	vaddr_t rx_base = 0;
	vaddr_t irq_reg = 0;

	/* Idempotent: skip if already initialised. */
	if (bobcat_mbox_initialized)
		return TEE_SUCCESS;

	/*
	 * TME_QMP_LITE_INBOUND/OUTBOUND_MBOX_ADDR are named from TME's point
	 * of view (matches the downstream xport_qmp_config.c convention):
	 * INBOUND is what TME reads (i.e. what OP-TEE writes as TX), and
	 * OUTBOUND is what TME writes (i.e. what OP-TEE reads as RX).
	 */

	/* TX mailbox (OP-TEE → TME) */
	tx_base = (vaddr_t)phys_to_virt(TME_QMP_LITE_INBOUND_MBOX_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!tx_base) {
		EMSG("mbox_plat: failed to map TX mbox at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_INBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	/* RX mailbox (TME → OP-TEE) */
	rx_base = (vaddr_t)phys_to_virt(TME_QMP_LITE_OUTBOUND_MBOX_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!rx_base) {
		EMSG("mbox_plat: failed to map RX mbox at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_OUTBOUND_MBOX_ADDR);
		return TEE_ERROR_GENERIC;
	}

	/* APCS TZ IPC interrupt register (OP-TEE → TME doorbell) */
	irq_reg = (vaddr_t)phys_to_virt(TME_QMP_LITE_IRQ_OUT_REG_ADDR,
					MEM_AREA_IO_SEC,
					CORE_MMU_PGDIR_SIZE);
	if (!irq_reg) {
		EMSG("mbox_plat: failed to map IRQ-out reg at phys 0x%08lx",
		     (unsigned long)TME_QMP_LITE_IRQ_OUT_REG_ADDR);
		return TEE_ERROR_GENERIC;
	}

	/*
	 * local_desc_base  = TX descriptor (OP-TEE writes to send).
	 * remote_desc_base = RX descriptor (OP-TEE reads to receive).
	 * The message payload immediately follows the 4-byte descriptor
	 * register in each mailbox region.
	 */
	tme_qmp_lite_cfg.local_desc_base     = tx_base;
	tme_qmp_lite_cfg.remote_desc_base    = rx_base;
	tme_qmp_lite_cfg.local_mbox_size     = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_mbox_size    = TME_QMP_LITE_MBOX_SIZE;
	tme_qmp_lite_cfg.remote_signal.reg   = irq_reg;
	tme_qmp_lite_cfg.remote_signal.value = TME_QMP_LITE_IRQ_OUT_BIT_MASK;

	bobcat_mbox_configs[0].transport_cfg = &tme_qmp_lite_cfg;
	bobcat_mbox_configs[0].itr_chip = interrupt_get_main_chip();
	bobcat_mbox_initialized = true;

	IMSG("mbox_plat: TX va=0x%08lx RX va=0x%08lx IRQ-out va=0x%08lx",
	     (unsigned long)tx_base, (unsigned long)rx_base,
	     (unsigned long)irq_reg);

	return TEE_SUCCESS;
}

driver_init(plat_qcom_mbox_init);

const struct qcom_mbox_plat_data *plat_qcom_mbox_get_data(void)
{
	/*
	 * Lazy initialisation: if driver_init() has not yet fired (e.g. the
	 * caller invokes plat_qcom_mbox_get_data() before the driver-init
	 * phase), trigger the mapping here.  The idempotency guard inside
	 * plat_qcom_mbox_init() prevents double-initialisation.
	 */
	if (!bobcat_mbox_initialized) {
		TEE_Result res = plat_qcom_mbox_init();

		if (res != TEE_SUCCESS) {
			EMSG("mbox_plat: lazy init failed: %#x", res);
			return NULL;
		}
	}

	return &bobcat_mbox_plat_data;
}
