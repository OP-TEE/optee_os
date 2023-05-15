/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2017-2018, STMicroelectronics
 */

#ifndef __BOOT_API_H__
#define __BOOT_API_H__

/*
 * Backup registers mapping
 */

/* Backup register #4: magic to request core1 boot up */
#define BCKR_CORE1_MAGIC_NUMBER			4

/* Value for BCKR_CORE1_MAGIC_NUMBER entry */
#define BOOT_API_A7_CORE1_MAGIC_NUMBER		0xca7face1

/* Backup register #5: physical address of core1 entry at boot up */
#define BCKR_CORE1_BRANCH_ADDRESS		5

#endif /* __BOOT_API_H__*/
