// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microsoft
 *
 * Driver for the NXP LX2160A-series Security Fuse Processor (SFP).
 */

#include <assert.h>
#include <drivers/ls_sfp.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <kernel/tee_time.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <util.h>

/**
 * struct ls_sfp_registers - Memory map of the SFP registers.
 * @rsvd0[0x8]:		Reserved.
 * @ingr:		Instruction Register.
 * @svhesr:		Secret Value Hamming Error Status Registers.
 * @sfpcr:		SFP Configuration Register.
 * @rsvd1[0x3]:		Reserved.
 * @version:		SFP Version Register.
 * @rsvd2[0x71]:	Reserved.
 * @ospr0:		OEM Security Policy Register 0.
 * @ospr1:		OEM Security Policy Register 1.
 * @dcvr0:		Debug Challenge Value Register 0.
 * @dcvr1:		Debug Challenge Value Register 1.
 * @drvr0:		Debug Response Value Register 0.
 * @drvr1:		Debug Response Value Register 1
 * @fswpr:		Factory Section Write Protect Register.
 * @fuidr0:		Factory Unique ID Register 0.
 * @fuidr1:		Factory Unique ID Register 1.
 * @isbccr:		ISBC Configuration Register.
 * @fspfr[0x3]:		Factory Scratch Pad Fuse Registers.
 * @otpmkr[0x8]:	One Time Programmable Master Key.
 * @srkhr[0x8]:		Super Root Key Hash.
 * @ouidr[0x5]:		OEM Unique ID Scratch Pad Fuse Registers.
 */
static struct ls_sfp_registers {
	uint32_t rsvd0[0x8];	/* 0x000 */
	uint32_t ingr;		/* 0x020 */
	uint32_t svhesr;	/* 0x024 */
	uint32_t sfpcr;		/* 0x028 */
	uint32_t rsvd1[0x3];	/* 0x02C */
	uint32_t version;	/* 0x038 */
	uint32_t rsvd2[0x71];	/* 0x03C */
	uint32_t ospr0;		/* 0x200 */
	uint32_t ospr1;		/* 0x204 */
	uint32_t dcvr0;		/* 0x208 */
	uint32_t dcvr1;		/* 0x20C */
	uint32_t drvr0;		/* 0x210 */
	uint32_t drvr1;		/* 0x214 */
	uint32_t fswpr;		/* 0x218 */
	uint32_t fuidr0;	/* 0x21C */
	uint32_t fuidr1;	/* 0x220 */
	uint32_t isbccr;	/* 0x224 */
	uint32_t fspfr[0x3];	/* 0x228 */
	uint32_t otpmkr[0x8];	/* 0x234 */
	uint32_t srkhr[0x8];	/* 0x254 */
	uint32_t ouidr[0x5];	/* 0x274 */
} *sfp_regs;

/**
 * struct ls_gpio_info - Data struct containing GPIO specific information.
 * @gpio_pin:		GPIO pin number.
 * @gpio_chip:	GPIO controller instance data.
 */
static struct ls_gpio_info {
	uint32_t gpio_pin;
	struct ls_gpio_chip_data gpio_chip;
} gpio_info;

/**
 * ls_sfp_init() - Get SFP info from the embedded device tree and initialize
 *		   sfp_regs and gpio_info.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
static TEE_Result ls_sfp_init(void)
{
	size_t size = 0;
	int node = 0;
	int rc = 0;
	int povdd_node = 0;
	int prop_len = 0;
	vaddr_t ctrl_base = 0;
	struct ls_gpio_chip_data *gc = NULL;
	const char *fdt_prop_gpio = "povdd-gpio-controller";
	const char *fdt_prop_pin = "povdd-gpio-pin";
	const fdt32_t *gpio_val = NULL;
	const fdt32_t *pin_val = NULL;
	void *fdt = get_embedded_dt();

	if (!fdt) {
		EMSG("Unable to get the Embedded DTB, SFP init failed");
		return TEE_ERROR_GENERIC;
	}

	node = fdt_node_offset_by_compatible(fdt, node, "fsl,lx2160a-sfp");
	if (node <= 0) {
		EMSG("Unable to find SFP FDT node - rc = 0x%#"PRIx32, rc);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	rc = dt_map_dev(fdt, node, &ctrl_base, &size, DT_MAP_AUTO);
	if (rc < 0) {
		EMSG("Unable to get SFP virtual address - rc = 0x%#"PRIx32, rc);
		return TEE_ERROR_GENERIC;
	}

	povdd_node = fdt_path_offset(fdt, "/povdd");
	if (povdd_node <= 0) {
		EMSG("Unable to find POVDD FDT node - rc = 0x%#"PRIx32,
		     povdd_node);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	sfp_regs = (struct ls_sfp_registers *)ctrl_base;

	gpio_val = fdt_getprop(fdt, povdd_node, fdt_prop_gpio, &prop_len);
	if (!gpio_val) {
		EMSG("Missing %s from POVDD FDT node", fdt_prop_gpio);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	pin_val = fdt_getprop(fdt, povdd_node, fdt_prop_pin, &prop_len);
	if (!pin_val) {
		EMSG("Missing %s from POVDD FDT node", fdt_prop_pin);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	gc = &gpio_info.gpio_chip;
	gc->gpio_controller = (uint8_t)fdt32_to_cpu(*gpio_val);
	gpio_info.gpio_pin = fdt32_to_cpu(*pin_val);

	return ls_gpio_init(gc);
}

/**
 * ls_sfp_program_fuses() - Write to fuses and verify that the correct value was
 *			    written.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
static TEE_Result ls_sfp_program_fuses(void)
{
	TEE_Result ret = TEE_SUCCESS;
	struct gpio_chip *gc = NULL;
	uint32_t pin = gpio_info.gpio_pin;
	vaddr_t sfp_ingr_va = (vaddr_t)&sfp_regs->ingr;
	uint64_t timeout = 0;

	/* Enable POVDD */
	gc = &gpio_info.gpio_chip.chip;

	DMSG("Set GPIO %"PRIu32" pin %"PRIu32" to HIGH",
	     (uint32_t)gpio_info.gpio_chip.gpio_controller, pin);
	gc->ops->set_direction(gc, pin, GPIO_DIR_OUT);
	gc->ops->set_value(gc, pin, GPIO_LEVEL_HIGH);

	if (gc->ops->get_value(gc, pin) != GPIO_LEVEL_HIGH) {
		EMSG("Error setting POVDD to HIGH");
		return TEE_ERROR_GENERIC;
	}

	/* TA_PROG_SFP ramp rate requires up to 5ms for stability */
	mdelay(5);

	/* Send SFP write command */
	io_write32(sfp_ingr_va, SFP_INGR_PROGFB_CMD);

	/* Wait until fuse programming is successful */
	timeout = timeout_init_us(SFP_INGR_FUSE_TIMEOUT_US);
	while (io_read32(sfp_ingr_va) & SFP_INGR_PROGFB_CMD) {
		if (timeout_elapsed(timeout)) {
			EMSG("SFP fusing timed out");
			ret = TEE_ERROR_GENERIC;
			break;
		}
	}

	/* Disable POVDD */
	DMSG("Set GPIO %"PRIu8" pin %"PRIu32" to LOW",
	     gpio_info.gpio_chip.gpio_controller, pin);
	gc->ops->set_value(gc, pin, GPIO_LEVEL_LOW);
	gc->ops->set_direction(gc, pin, GPIO_DIR_IN);

	if (ret)
		return ret;

	/* Check for SFP fuse programming error */
	if (io_read32(sfp_ingr_va) & SFP_INGR_ERROR_MASK) {
		EMSG("Error writing SFP fuses");
		return TEE_ERROR_GENERIC;
	}

	DMSG("Programmed fuse successfully");

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_read(struct ls_sfp_data *data)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!data)
		return TEE_ERROR_BAD_PARAMETERS;

	data->ingr = io_read32((vaddr_t)&sfp_regs->ingr);
	data->svhesr = io_read32((vaddr_t)&sfp_regs->svhesr);
	data->sfpcr = io_read32((vaddr_t)&sfp_regs->sfpcr);
	data->version = io_read32((vaddr_t)&sfp_regs->version);
	data->ospr0 = io_read32((vaddr_t)&sfp_regs->ospr0);
	data->ospr1 = io_read32((vaddr_t)&sfp_regs->ospr1);
	data->dcvr0 = io_read32((vaddr_t)&sfp_regs->dcvr0);
	data->dcvr1 = io_read32((vaddr_t)&sfp_regs->dcvr1);
	data->drvr0 = io_read32((vaddr_t)&sfp_regs->drvr0);
	data->drvr1 = io_read32((vaddr_t)&sfp_regs->drvr1);
	data->fswpr = io_read32((vaddr_t)&sfp_regs->fswpr);
	data->fuidr0 = io_read32((vaddr_t)&sfp_regs->fuidr0);
	data->fuidr1 = io_read32((vaddr_t)&sfp_regs->fuidr1);
	data->isbccr = io_read32((vaddr_t)&sfp_regs->isbccr);

	for (uint32_t i = 0; i < ARRAY_SIZE(sfp_regs->fspfr); ++i)
		data->fspfr[i] = io_read32((vaddr_t)&sfp_regs->fspfr[i]);

	for (uint32_t i = 0; i < ARRAY_SIZE(sfp_regs->otpmkr); ++i)
		data->otpmkr[i] = io_read32((vaddr_t)&sfp_regs->otpmkr[i]);

	for (uint32_t i = 0; i < ARRAY_SIZE(sfp_regs->srkhr); ++i)
		data->srkhr[i] = io_read32((vaddr_t)&sfp_regs->srkhr[i]);

	for (uint32_t i = 0; i < ARRAY_SIZE(sfp_regs->ouidr); ++i)
		data->ouidr[i] = io_read32((vaddr_t)&sfp_regs->ouidr[i]);

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_get_debug_level(uint32_t *dblev)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!dblev)
		return TEE_ERROR_BAD_PARAMETERS;

	*dblev = io_read32((vaddr_t)&sfp_regs->ospr1) & SFP_OSPR1_DBLEV_MASK;

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_get_its(uint32_t *its)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!its)
		return TEE_ERROR_BAD_PARAMETERS;

	*its = (io_read32((vaddr_t)&sfp_regs->ospr0) & SFP_OSPR0_ITS_MASK) >>
	       SFP_OSPR0_ITS_OFFSET;

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_get_ouid(uint32_t index, uint32_t *ouid)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!ouid)
		return TEE_ERROR_BAD_PARAMETERS;

	if (index >= ARRAY_SIZE(sfp_regs->ouidr)) {
		DMSG("Index greater or equal to ouid: %"PRIu32" >= %zu",
		     index, ARRAY_SIZE(sfp_regs->ouidr));
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*ouid = io_read32((vaddr_t)&sfp_regs->ouidr[index]);

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_get_sb(uint32_t *sb)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!sb)
		return TEE_ERROR_BAD_PARAMETERS;

	*sb = (io_read32((vaddr_t)&sfp_regs->sfpcr) & SFP_SFPCR_SB_MASK) >>
	      SFP_SFPCR_SB_OFFSET;

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_get_srkh(uint32_t index, uint32_t *srkh)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!srkh)
		return TEE_ERROR_BAD_PARAMETERS;

	if (index >= ARRAY_SIZE(sfp_regs->srkhr)) {
		DMSG("Index greater or equal to srkhr: %"PRIu32" >= %zu",
		     index, ARRAY_SIZE(sfp_regs->srkhr));
		return TEE_ERROR_BAD_PARAMETERS;
	}

	*srkh = io_read32((vaddr_t)&sfp_regs->srkhr[index]);

	return TEE_SUCCESS;
}

TEE_Result ls_sfp_set_debug_level(uint32_t dblev)
{
	uint32_t ospr1 = 0;

	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (!dblev)
		return TEE_SUCCESS;

	ospr1 = io_read32((vaddr_t)&sfp_regs->ospr1);
	if (ospr1 & SFP_OSPR1_DBLEV_MASK) {
		DMSG("Debug level has already been fused");
		return TEE_ERROR_SECURITY;
	}

	io_write32((vaddr_t)&sfp_regs->ospr1, ospr1 | dblev);

	return ls_sfp_program_fuses();
}

TEE_Result ls_sfp_set_its_wp(void)
{
	uint32_t ospr0 = 0;

	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	ospr0 = io_read32((vaddr_t)&sfp_regs->ospr0);
	if (ospr0 & (SFP_OSPR0_WP_MASK | SFP_OSPR0_ITS_MASK)) {
		DMSG("SFP is already fused");
		return TEE_ERROR_SECURITY;
	}

	ospr0 |= SFP_OSPR0_WP_MASK | SFP_OSPR0_ITS_MASK;
	io_write32((vaddr_t)&sfp_regs->ospr0, ospr0);

	return ls_sfp_program_fuses();
}

TEE_Result ls_sfp_set_ouid(uint32_t index, uint32_t ouid)
{
	if (!sfp_regs) {
		EMSG("SFP driver not initialized");
		return TEE_ERROR_GENERIC;
	}

	if (index >= ARRAY_SIZE(sfp_regs->ouidr)) {
		DMSG("Index greater or equal to ouid: %"PRIu32" >= %"PRIu32,
		     index, ARRAY_SIZE(sfp_regs->ouidr));
		return TEE_ERROR_BAD_PARAMETERS;
	}

	io_write32((vaddr_t)&sfp_regs->ouidr[index], ouid);

	return ls_sfp_program_fuses();
}

TEE_Result ls_sfp_status(void)
{
	if (!sfp_regs)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

driver_init(ls_sfp_init);
