/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef TARGET_CONFIG_H
#define TARGET_CONFIG_H

#define GENI_UART_REG_BASE		UL(0x884000)

#define GICD_BASE			UL(0x17000000)
#define GICR_BASE			UL(0x17080000)

#define AOP_CMD_DB_BASE                 UL(0x87148000)
#define AOP_CMD_DB_SIZE                 UL(0x2000)

#define MSG_RAM_SECTION_SIZE            UL(0x00001000)

#define RPMH_BASE_ADDR                  UL(0x18900000)
#define RPMH_RSC_SIZE                   UL(0x10000)

#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x880000000)
#define DRAM1_SIZE			ULL(0x780000000)
#define DRAM2_BASE			ULL(0x8800000000)
#define DRAM2_SIZE			ULL(0x3800000000)

#ifdef CFG_QCOM_QFPROM_FUSEPROV
/*
 * Window holding the fuse provisioning data. The address and size have not
 * been confirmed for this target, check them against the producer of the
 * data before enabling the feature. The window must be secure memory that is
 * authenticated before this image runs.
 */
#define CFG_SEC_ELF_DDR_ADDR		UL(0x87452000)
#define CFG_SEC_ELF_DDR_SIZE		UL(0x1000)
#define PROVISION_WINDOW_MEM_AREA	MEM_AREA_RAM_SEC

/* Register reporting the download mode */
#define TCSR_BOOT_MISC_DETECT		UL(0x1FD9000)

/*
 * Still to be provided for this target, their values are not known:
 * - PROVISION_WRITE_PERM_ADDR and PROVISION_WRITE_PERM_MASK, to refuse
 *   programming once the write permission fuses are set (optional)
 */
#endif /* CFG_QCOM_QFPROM_FUSEPROV */

#endif /* TARGET_CONFIG_H */
