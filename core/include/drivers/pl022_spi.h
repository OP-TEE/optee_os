/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 *
 */

#ifndef __DRIVERS_PL022_SPI_H
#define __DRIVERS_PL022_SPI_H

#include <drivers/gpio.h>
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

#endif	/* __DRIVERS_PL022_SPI_H */

