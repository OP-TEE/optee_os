/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 Microsoft
 *
 * Definitions for the NXP LX2160A-series Security Monitor (SecMon) driver.
 */

#ifndef __DRIVERS_LS_SEC_MON_H
#define __DRIVERS_LS_SEC_MON_H

#include <stdlib.h>
#include <tee_api_types.h>

/**
 * struct ls_sec_mon_data - Compact data struct of all SecMon registers.
 * @hplr:	HP Lock Register.
 * @hpcomr:	HP Command Register.
 * @hpsicr:	HP Security Interrupt Control Register.
 * @hpsvcr:	HP Security Violation Control Register.
 * @hpsr:	HP Status Register.
 * @hpsvsr:	HP Security Violation Status Register.
 * @hphacivr:	HP High Assurance Counter IV Register.
 * @hphacr:	HP High Assurance Counter Register.
 * @lplr:	LP Lock Register.
 * @lpcr:	LP Control Register.
 * @lpmkcr:	LP Master Key Control Register.
 * @lpsvcr:	LP Security Violation Control Register.
 * @lptdcr:	LP Tamper Detectors Configuration Register.
 * @lpsr:	LP Status Register.
 * @lpsmcmr:	LP Secure Monotonic Counter MSB Register.
 * @lpsmclr:	LP Secure Monotonic Counter LSB Register.
 * @lppgdr:	LP Power Glitch Detector Register.
 * @lpzmkr[8]:	LP Zeroizable Master Key Registers.
 * @lpgpr[4]:	LP General Purpose Registers.
 * @hpvidr1:	HP Version ID Register 1.
 * @hpvidr2:	HP Version ID Register 2.
 */
struct ls_sec_mon_data {
	uint32_t hplr;
	uint32_t hpcomr;
	uint32_t hpsicr;
	uint32_t hpsvcr;
	uint32_t hpsr;
	uint32_t hpsvsr;
	uint32_t hphacivr;
	uint32_t hphacr;
	uint32_t lplr;
	uint32_t lpcr;
	uint32_t lpmkcr;
	uint32_t lpsvcr;
	uint32_t lptdcr;
	uint32_t lpsr;
	uint32_t lpsmcmr;
	uint32_t lpsmclr;
	uint32_t lppgdr;
	uint32_t lpzmkr[8];
	uint32_t lpgpr[4];
	uint32_t hpvidr1;
	uint32_t hpvidr2;
};

/**
 * ls_sec_mon_read() - Read a copy of the SecMon register data if the SecMon
 *		       driver was successfully initialized.
 * @data:	Location to save SecMon data.
 *
 * Return:	0 if successful or > 0 on error.
 */
TEE_Result ls_sec_mon_read(struct ls_sec_mon_data *data);

/**
 * ls_sec_mon_status() - Check if the SecMon driver was initialized
 *			 successfully.
 *
 * Return:	0 if init was successful or TEE_ERROR_GENERIC on init failed.
 */
TEE_Result ls_sec_mon_status(void);

#endif /* __DRIVERS_LS_SEC_MON_H */
