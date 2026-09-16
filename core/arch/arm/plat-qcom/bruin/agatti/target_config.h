/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * SM4125 Agatti (QCM2290 / QRB2210, Arduino Uno-Q) target config for OP-TEE.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

/* GENI UART (QUPV3_0 SE4) - ttyMSM0 debug console. */
#define GENI_UART_REG_BASE		UL(0x04A90000)
#define GENI_UART_REG_SIZE		UL(0x4000)

/*
 * DDR at 0x40000000 (EBI1). DRAM0_SIZE is the non-secure window OP-TEE
 * validates normal-world buffers against (register_ddr() in plat-qcom/main.c).
 * The Uno-Q ships in 2 GiB and 4 GiB variants and the DT leaves the size to
 * the bootloader, so use the 2 GiB floor: under-reporting only rejects real
 * DDR, whereas over-reporting would accept unpopulated addresses. 4 GiB boards
 * need runtime DT/SMEM-derived sizing for high-memory buffers.
 */
#define DRAM0_BASE			UL(0x40000000)
#define DRAM0_SIZE			UL(0x80000000)

/* Boot IMEM window (used by the diag-log region). */
#define IMEM_BASE			UL(0x0C100000)
#define IMEM_SIZE			UL(0x19000)

#endif /* TARGET_CONFIG_H */
