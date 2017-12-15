/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016, Linaro Ltd and Contributors. All rights reserved.
 * Copyright (c) 2016, Hisilicon Ltd and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
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

#ifndef __HIKEY_PERIPHERALS_H__
#define __HIKEY_PERIPHERALS_H__

#include <types_ext.h>

#define PMUSSI_BASE	0xF8000000
#define PERI_BASE	0xF7030000
#define PMX0_BASE	0xF7010000
#define PMX1_BASE	0xF7010800
#define GPIO6_BASE	0xF7022000
#define SPI_BASE	0xF7106000

#define PMUSSI_REG_SIZE		0x1000
#define PERI_BASE_REG_SIZE	0x2000
#define PMX0_REG_SIZE		0x27c
#define PMX1_REG_SIZE		0x28c

/* register offsets */
#define PMUSSI_LDO21_REG_ADJ	SHIFT_U32(0x86, 2)
#define PMUSSI_ENA_LDO17_22	SHIFT_U32(0x2F, 2)

#define PERI_SC_PERIPH_RSTDIS3	0x334
#define PERI_SC_PERIPH_RSTSTAT3	0x338
#define PERI_SC_PERIPH_CLKEN3	0x230
#define PERI_SC_PERIPH_CLKSTAT3	0x238

#define PMX0_IOMG104	0x1a0
#define PMX0_IOMG105	0x1a4
#define PMX0_IOMG106	0x1a8
#define PMX0_IOMG107	0x1ac

#define PMX1_IOCG104	0x1b0
#define PMX1_IOCG105	0x1b4
#define PMX1_IOCG106	0x1b8
#define PMX1_IOCG107	0x1bc
/* end register offsets */

#define PMUSSI_LDO21_REG_VL_MASK	0x7
#define PMUSSI_LDO21_REG_VL_1V8		0x3
#define PMUSSI_ENA_LDO21		BIT(4)

#define PERI_RST3_SSP	BIT(9)
#define PERI_CLK3_SSP	BIT(9)

#define PINMUX_GPIO	0
#define PINMUX_SPI	1

#define PINCFG_NOPULL	0
#define PINCFG_PULLUP	1
#define PINCFG_PULLDN	2

#define GPIO6_2		50
#define SPI_CLK_HZ	150000000 /* 150mhz */
#define SPI_500_KHZ	500000
#define SPI_10_KHZ	10000

#ifdef CFG_SPI
void spi_init(void);
#ifdef CFG_SPI_TEST
void spi_test(void);
#endif /* CFG_SPI_TEST */
#endif /* CFG_SPI */

#endif /* __HIKEY_PERIPHERALS_H__ */
