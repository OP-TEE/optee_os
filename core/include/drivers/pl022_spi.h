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
 *
 */

#ifndef __PL022_SPI_H__
#define __PL022_SPI_H__

#include <gpio.h>
#include <spi.h>

#define PL022_REG_SIZE	0x1000

enum pl022_cs_control {
	PL022_CS_CTRL_AUTO_GPIO,
	PL022_CS_CTRL_CB,
	PL022_CS_CTRL_MANUAL
};

struct pl022_cs_gpio_data {
	struct gpio_chip	*chip;
	unsigned int		pin_num;
};

union pl022_cs_data {
	struct pl022_cs_gpio_data	gpio_data;
	void				(*cs_cb)(enum gpio_level value);
};

struct pl022_data {
	union pl022_cs_data	cs_data;
	struct spi_chip		chip;
	vaddr_t			base;
	enum spi_mode		mode;
	enum pl022_cs_control	cs_control;
	unsigned int		clk_hz;
	unsigned int		speed_hz;
	unsigned int		data_size_bits;
	bool			loopback;
};

void pl022_init(struct pl022_data *pd);

#endif	/* __PL022_SPI_H__ */

