/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <drivers/pl022_spi.h>
#include <drivers/pl061_gpio.h>
#include <hikey_peripherals.h>
#include <stdint.h>
#include <trace.h>

/*
 * spi_init() must be run before calling this function.
 *
 * This runs a loopback test by default, so the SPI module will just
 * receive what is transmitted, i.e. 0x01, 0x80, 0x00.
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
	struct pl061_data platform_pl061_data;
	struct pl022_data platform_pl022_data;
	vaddr_t gpio6_base = nsec_periph_base(GPIO6_BASE);
	vaddr_t spi_base = nsec_periph_base(SPI_BASE);
	uint8_t tx[3] = {0x01, 0x80, 0x00};
	uint8_t rx[3] = {0};
	size_t i, j, num_rxpkts, len = 3;

	DMSG("gpio6_base: 0x%" PRIxVA "\n", gpio6_base);
	DMSG("spi_base: 0x%" PRIxVA "\n", spi_base);

	DMSG("configure GPIO\n");
	pl061_init(&platform_pl061_data);
	pl061_register(gpio6_base, 6);

	DMSG("enable software mode control for chip select\n");
	pl061_set_mode_control(GPIO6_2, PL061_MC_SW);

	DMSG("mask/disable interrupt for chip select\n");
	platform_pl061_data.chip.ops->set_interrupt(GPIO6_2,
						GPIO_INTERRUPT_DISABLE);

	DMSG("configure SPI\n");
	platform_pl022_data.gpio = &platform_pl061_data.chip;
	platform_pl022_data.base = spi_base;
	platform_pl022_data.cs_gpio_base = gpio6_base;
	platform_pl022_data.clk_hz = SPI_CLK_HZ;
	platform_pl022_data.speed_hz = SPI_500_KHZ;
	platform_pl022_data.cs_gpio_pin = GPIO6_2;
	platform_pl022_data.mode = SPI_MODE0;
	platform_pl022_data.data_size_bits = 8;
	platform_pl022_data.loopback = true;

	pl022_configure(&platform_pl022_data);
	pl022_start(&platform_pl022_data);

	for (j = 0; j < 20; j++) {
		DMSG("SPI test loop: %zu\n", j);
		platform_pl022_data.chip.ops->txrx8(&platform_pl022_data.chip,
						tx, rx, len, &num_rxpkts);
		for (i = 0; i < num_rxpkts; i++)
			DMSG("rx[%zu] = 0x%x\n", i, rx[i]);

		/* wait a bit */
		for (i = 0; i < 100000000; i++)
			;
	}

	pl022_end(&platform_pl022_data);
}
