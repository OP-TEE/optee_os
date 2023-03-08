/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 Microsoft
 *
 * Definitions for the NXP LX2160A-series Security Fuse Processor (SFP) driver.
 */

#ifndef __DRIVERS_LS_SFP_H
#define __DRIVERS_LS_SFP_H

#include <drivers/ls_gpio.h>
#include <stdlib.h>
#include <tee_api_types.h>

/* SFP instruction register */
/* SFP is big endian */
#define SFP_INGR_PROGFB_CMD 0x2
#define SFP_INGR_ERROR_MASK 0x100
#define SFP_INGR_FUSE_TIMEOUT_US 150000

/* SFP configuration register */
#define SFP_SFPCR_SB_MASK 0x20000000
#define SFP_SFPCR_SB_OFFSET 29

/* SFP OEM security policy register 0 */
#define SFP_OSPR0_WP_MASK 0x1
#define SFP_OSPR0_ITS_MASK 0x4
#define SFP_OSPR0_ITS_OFFSET 0x2

/* SFP OEM security policy register 1 */
#define SFP_OSPR1_DBLEV_MASK 0x7
#define SFP_OSPR1_DBLEV_OPEN 0x0
#define SFP_OSPR1_DBLEV_CLOSED_NOTIFY 0x1
#define SFP_OSPR1_DBLEV_CLOSED_SILENT 0x2
#define SFP_OSPR1_DBLEV_CLOSED 0x4

/**
 * struct ls_sfp_data - Compact data struct of all SFP registers.
 * @ingr:		Instruction Register.
 * @svhesr:		Secret Value Hamming Error Status Register.
 * @sfpcr:		SFP Configuration Register.
 * @version:		SFP Version Register.
 * @ospr0:		OEM Security Policy Register 0.
 * @ospr1:		OEM Security Policy Register 1.
 * @dcvr0:		Debug Challenge Value Register 0.
 * @dcvr1:		Debug Challenge Value Register 1.
 * @drvr0:		Debug Response Value Register 0.
 * @drvr1:		Debug Response Value Register 1.
 * @fswpr:		Factory Section Write Protect Register.
 * @fuidr0:		Factory Unique ID Register 0.
 * @fuidr1:		Factory Unique ID Register 1.
 * @isbccr:		ISBC Configuration Register.
 * @fspfr[0x3]:		Factory Scratch Pad Fuse Registers.
 * @otpmkr[0x8]:	One Time Programmable Master Key.
 * @srkhr[0x8]:		Super Root Key Hash Register.
 * @ouidr[0x5]:		OEM Unique ID/Scratch Pad Fuse Registers.
 */
struct ls_sfp_data {
	uint32_t ingr;
	uint32_t svhesr;
	uint32_t sfpcr;
	uint32_t version;
	uint32_t ospr0;
	uint32_t ospr1;
	uint32_t dcvr0;
	uint32_t dcvr1;
	uint32_t drvr0;
	uint32_t drvr1;
	uint32_t fswpr;
	uint32_t fuidr0;
	uint32_t fuidr1;
	uint32_t isbccr;
	uint32_t fspfr[0x3];
	uint32_t otpmkr[0x8];
	uint32_t srkhr[0x8];
	uint32_t ouidr[0x5];
};

/**
 * ls_sfp_read() - Read a copy of the SFP register data if the SFP driver was
 *		   successfully initialized.
 * @data:	Location to save SFP data.
 *
 * Return:	TEE_SUCCESS or > 0 on error
 */
TEE_Result ls_sfp_read(struct ls_sfp_data *data);

/**
 * ls_sfp_get_debug_level() - Read the last 3 bits of the SFP OSPR1 register
 *			      which denotes the debug level.
 * @dblev:	Pointer location to store the read debug level.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_get_debug_level(uint32_t *dblev);

/**
 * ls_sfp_get_its() - Read bit 29 of the SFP OSPR0 register which denotes the
 *		      ITS flag.
 * @its:	Pointer location to store the ITS flag.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_get_its(uint32_t *its);

/**
 * ls_sfp_get_ouid() - Read the SFP OUID register at the given index.
 * @index:	Index of the OUID register to read.
 * @ouid:	Pointer location to store the OIUD register value.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_get_ouid(uint32_t index, uint32_t *ouid);

/**
 * ls_sfp_get_sb() - Read bit 2 of the SFP SFPCR register which denotes the
 *		     secure boot flag.
 * @sb:		Pointer location to store the secure boot flag.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_get_sb(uint32_t *sb);

/**
 * ls_sfp_get_srkh() - Read the SFP SRKH register at the given index.
 * @index:	Index of the SRKH register to read.
 * @srkh:	Pointer location to store the SRKH register value.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_get_srkh(uint32_t index, uint32_t *srkh);

/**
 * ls_sfp_set_debug_level() - Set the last 3 bits of the SFP OSPR1 register
 *			      which denotes the debug level.
 * @dblev:	Value to write into the SFP OSPR1 register.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_set_debug_level(uint32_t dblev);

/**
 * ls_sfp_set_its_wp() - Set bits 29 and 31 of the SFP OSPR0 register which
 *			 denote the ITS and write protect flags respectively.
 *
 * WARNING - Setting the ITS and write protect flags will lock the mirror
 * registers and permanently prevent any further programming of the fuse block.
 * The system will also be forced to always attempt to secure boot which
 * requires signature validation and the absence of any hardware security
 * violations when booting.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_set_its_wp(void);

/**
 * ls_sfp_set_ouid() - Write to the SFP OUID register at the given index.
 * @index:	Index of the OUID register to write.
 * @ouid:	Value to write into the SFP OUID register.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_set_ouid(uint32_t index, uint32_t ouid);

/**
 * ls_sfp_status() - Check if the SFP driver was initialized successfully.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
TEE_Result ls_sfp_status(void);

#endif /* __DRIVERS_LS_SFP_H */
