// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <drivers/pl022_spi.h>
#include <drivers/pl061_gpio.h>
#include <hikey_peripherals.h>
#include <io.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <trace.h>
#include <util.h>

#define PL022_STAT	0x00C
#define PL022_STAT_BSY	SHIFT_U32(1, 4)

static void spi_cs_callback(enum gpio_level value)
{
	static bool inited;
	static struct pl061_data pd;
	vaddr_t gpio6_base = core_mmu_get_va(GPIO6_BASE, MEM_AREA_IO_NSEC,
					     PL061_REG_SIZE);
	vaddr_t spi_base = core_mmu_get_va(SPI_BASE, MEM_AREA_IO_NSEC,
					   PL022_REG_SIZE);

	if (!inited) {
		pl061_init(&pd);
		pl061_register(gpio6_base, 6);
		pl061_set_mode_control(GPIO6_2, PL061_MC_SW);
		pd.chip.ops->set_interrupt(NULL, GPIO6_2,
					   GPIO_INTERRUPT_DISABLE);
		pd.chip.ops->set_direction(NULL, GPIO6_2, GPIO_DIR_OUT);
		inited = true;
	}

	if (io_read8(spi_base + PL022_STAT) & PL022_STAT_BSY)
		DMSG("pl022 busy - do NOT set CS!");
	while (io_read8(spi_base + PL022_STAT) & PL022_STAT_BSY)
		;
	DMSG("pl022 done - set CS!");

	pd.chip.ops->set_value(NULL, GPIO6_2, value);
}

static void spi_set_cs_mux(uint32_t val)
{
	uint32_t data;
	vaddr_t pmx0_base = core_mmu_get_va(PMX0_BASE, MEM_AREA_IO_NSEC,
					    PMX0_REG_SIZE);

	if (val == PINMUX_SPI) {
		DMSG("Configure gpio6 pin2 as SPI");
		io_write32(pmx0_base + PMX0_IOMG106, PINMUX_SPI);
	} else {
		DMSG("Configure gpio6 pin2 as GPIO");
		io_write32(pmx0_base + PMX0_IOMG106, PINMUX_GPIO);
	}

	data = io_read32(pmx0_base + PMX0_IOMG106);
	if (data)
		DMSG("gpio6 pin2 is SPI");
	else
		DMSG("gpio6 pin2 is GPIO");
}

static void spi_test_with_manual_cs_control(void)
{
	struct pl022_data pd;
	vaddr_t spi_base = core_mmu_get_va(SPI_BASE, MEM_AREA_IO_NSEC,
					   PL022_REG_SIZE);
	uint8_t tx[3] = {0x01, 0x80, 0x00};
	uint8_t rx[3] = {0};
	size_t i, j, len = 3;
	enum spi_result res;

	spi_set_cs_mux(PINMUX_GPIO);

	DMSG("Set CS callback");
	pd.cs_control = PL022_CS_CTRL_MANUAL;

	DMSG("spi_base: 0x%" PRIxVA "\n", spi_base);
	DMSG("Configure SPI");
	pd.base = spi_base;
	pd.clk_hz = SPI_CLK_HZ;
	pd.speed_hz = SPI_10_KHZ;
	pd.mode = SPI_MODE0;
	pd.data_size_bits = 8;
	pd.loopback = true;

	pl022_init(&pd);
	pd.chip.ops->configure(&pd.chip);
	pd.chip.ops->start(&pd.chip);

	/*
	 * Pulse CS only once for the whole transmission.
	 * This is the scheme used by the pl022 driver.
	 */
	spi_cs_callback(GPIO_LEVEL_HIGH);
	tee_time_busy_wait(2);
	spi_cs_callback(GPIO_LEVEL_LOW);
	for (j = 0; j < 10; j++) {
		DMSG("SPI test loop: %zu", j);
		res = pd.chip.ops->txrx8(&pd.chip, tx, rx, len);
		if (res) {
			EMSG("SPI transceive error %d", res);
			break;
		}

		for (i = 0; i < len; i++)
			DMSG("rx[%zu] = 0x%x", i, rx[i]);

		tee_time_busy_wait(20);
	}
	spi_cs_callback(GPIO_LEVEL_HIGH);

	/* Pulse CS once per transfer */
	spi_cs_callback(GPIO_LEVEL_HIGH);
	tee_time_busy_wait(2);
	for (j = 10; j < 20; j++) {
		DMSG("SPI test loop: %zu", j);
		spi_cs_callback(GPIO_LEVEL_LOW);
		res = pd.chip.ops->txrx8(&pd.chip, tx, rx, len);
		if (res) {
			EMSG("SPI transceive error %d", res);
			break;
		}

		for (i = 0; i < len; i++)
			DMSG("rx[%zu] = 0x%x", i, rx[i]);

		tee_time_busy_wait(20);
		spi_cs_callback(GPIO_LEVEL_HIGH);
	}

	/* Pulse CS once per word/byte */
	spi_set_cs_mux(PINMUX_SPI);
	tee_time_busy_wait(2);
	for (j = 20; j < 30; j++) {
		DMSG("SPI test loop: %zu", j);
		res = pd.chip.ops->txrx8(&pd.chip, tx, rx, len);
		if (res) {
			EMSG("SPI transceive error %d", res);
			break;
		}

		for (i = 0; i < len; i++)
			DMSG("rx[%zu] = 0x%x", i, rx[i]);

		tee_time_busy_wait(20);
	}

	pd.chip.ops->end(&pd.chip);
}

static void spi_test_with_registered_cs_cb(void)
{
	struct pl022_data pd;
	vaddr_t spi_base = core_mmu_get_va(SPI_BASE, MEM_AREA_IO_NSEC,
					   PL022_REG_SIZE);
	uint8_t tx[3] = {0x01, 0x80, 0x00};
	uint8_t rx[3] = {0};
	size_t i, j, len = 3;
	enum spi_result res;

	spi_set_cs_mux(PINMUX_GPIO);

	DMSG("Set CS callback");
	pd.cs_data.cs_cb = spi_cs_callback;
	pd.cs_control = PL022_CS_CTRL_CB;

	DMSG("spi_base: 0x%" PRIxVA "\n", spi_base);
	DMSG("Configure SPI");
	pd.base = spi_base;
	pd.clk_hz = SPI_CLK_HZ;
	pd.speed_hz = SPI_10_KHZ;
	pd.mode = SPI_MODE0;
	pd.data_size_bits = 8;
	pd.loopback = true;

	pl022_init(&pd);
	pd.chip.ops->configure(&pd.chip);
	pd.chip.ops->start(&pd.chip);

	for (j = 0; j < 20; j++) {
		DMSG("SPI test loop: %zu", j);
		res = pd.chip.ops->txrx8(&pd.chip, tx, rx, len);
		if (res) {
			EMSG("SPI transceive error %d", res);
			break;
		}

		for (i = 0; i < len; i++)
			DMSG("rx[%zu] = 0x%x", i, rx[i]);

		tee_time_busy_wait(20);
	}

	pd.chip.ops->end(&pd.chip);
}

static void spi_test_with_builtin_cs_control(void)
{
	struct pl061_data pd061;
	struct pl022_data pd022;
	vaddr_t gpio6_base = core_mmu_get_va(GPIO6_BASE, MEM_AREA_IO_NSEC,
					     PL061_REG_SIZE);
	vaddr_t spi_base = core_mmu_get_va(SPI_BASE, MEM_AREA_IO_NSEC,
					   PL022_REG_SIZE);
	uint8_t tx[3] = {0x01, 0x80, 0x00};
	uint8_t rx[3] = {0};
	size_t i, j, len = 3;
	enum spi_result res;

	spi_set_cs_mux(PINMUX_GPIO);

	DMSG("gpio6_base: 0x%" PRIxVA "\n", gpio6_base);
	DMSG("Configure GPIO");
	pl061_init(&pd061);
	pl061_register(gpio6_base, 6);
	DMSG("Enable software mode control for chip select");
	pl061_set_mode_control(GPIO6_2, PL061_MC_SW);

	pd022.cs_data.gpio_data.chip = &pd061.chip;
	pd022.cs_data.gpio_data.pin_num = GPIO6_2;
	pd022.cs_control = PL022_CS_CTRL_AUTO_GPIO;

	DMSG("spi_base: 0x%" PRIxVA "\n", spi_base);
	DMSG("Configure SPI");
	pd022.base = spi_base;
	pd022.clk_hz = SPI_CLK_HZ;
	pd022.speed_hz = SPI_10_KHZ;
	pd022.mode = SPI_MODE0;
	pd022.data_size_bits = 8;
	pd022.loopback = true;

	pl022_init(&pd022);
	pd022.chip.ops->configure(&pd022.chip);
	pd022.chip.ops->start(&pd022.chip);

	for (j = 0; j < 20; j++) {
		DMSG("SPI test loop: %zu", j);
		res = pd022.chip.ops->txrx8(&pd022.chip, tx, rx, len);
		if (res) {
			EMSG("SPI transceive error %d", res);
			break;
		}

		for (i = 0; i < len; i++)
			DMSG("rx[%zu] = 0x%x", i, rx[i]);

		tee_time_busy_wait(20);
	}

	pd022.chip.ops->end(&pd022.chip);
}

/*
 * spi_init() MUST be run before calling this function!
 *
 * spi_test runs some loopback tests, so the SPI module will just receive
 * what is transmitted, i.e. 0x01, 0x80, 0x00.
 *
 * In non-loopback mode, the transmitted value will elicit a readback of
 * the measured value from the ADC chip on the Linksprite 96Boards
 * Mezzanine card [1], which can be connected to either a sliding
 * rheostat [2] or photoresistor [3].
 *
 * [1] http://linksprite.com/wiki/index.php5?title=Linker_Mezzanine_card_for_96board
 * [2] http://learn.linksprite.com/96-board/sliding-rheostat
 * [3] http://learn.linksprite.com/96-board/photoresistor
 */
void spi_test(void)
{
	spi_test_with_builtin_cs_control();
	spi_test_with_registered_cs_cb();
	spi_test_with_manual_cs_control();
}
