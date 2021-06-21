// SPDX-License-Identifier: BSD-Source-Code
/*
 * Copyright (c) 2013, Atmel Corporation
 * Copyright (c) 2017, Timesys Corporation
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer below.
 *
 * Atmel's name may not be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * DISCLAIMER: THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <arm32.h>
#include <io.h>
#include <sama5d2.h>
#include <platform_config.h>
#include <stdint.h>
#include <matrix.h>
#include <tz_matrix.h>
#include <trace.h>

#define MATRIX_AXIMX	1
#define MATRIX_H64MX	2
#define MATRIX_H32MX	3

#define SECURITY_TYPE_AS	1
#define SECURITY_TYPE_NS	2
#define SECURITY_TYPE_PS	3

#define WORLD_NON_SECURE	0
#define WORLD_SECURE		1

struct peri_security {
	unsigned int peri_id;
	unsigned int matrix;
	unsigned int security_type;
};

static const struct peri_security peri_security_array[] = {
	{
		.peri_id = AT91C_ID_PMC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_ARM,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PIT,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_WDT,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_GMAC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_XDMAC0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_XDMAC1,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_ICM,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_AES,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_AESB,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_TDES,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SHA,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_MPDDRC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_MATRIX1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_MATRIX0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_SECUMOD,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_HSMC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PIOA,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM2,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM3,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_FLEXCOM4,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UART0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UART1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UART2,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UART3,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UART4,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_TWI0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_TWI1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SDMMC0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SDMMC1,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SPI0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SPI1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_TC0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_TC1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PWM,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_ADC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UHPHS,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_UDPHS,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SSC0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SSC1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_LCDC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_ISI,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_TRNG,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PDMIC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_IRQ,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_NS,
	},
	{
		.peri_id = AT91C_ID_SFC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SECURAM,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_QSPI0,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_QSPI1,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_I2SC0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_I2SC1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CAN0_INT0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CAN1_INT0,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CLASSD,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SFR,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SAIC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_AIC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_NS,
	},
	{
		.peri_id = AT91C_ID_L2CC,
		.matrix = MATRIX_H64MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CAN0_INT1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CAN1_INT1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_GMAC_Q1,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_GMAC_Q2,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_PIOB,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_PIOC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_PIOD,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_AS,
	},
	{
		.peri_id = AT91C_ID_SDMMC0_TIMER,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SDMMC1_TIMER,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SYS,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_ACC,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_RXLP,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_SFRBU,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
	{
		.peri_id = AT91C_ID_CHIPID,
		.matrix = MATRIX_H32MX,
		.security_type = SECURITY_TYPE_PS,
	},
};

static void matrix_write(unsigned int base,
			 unsigned int offset,
			 const unsigned int value)
{
	io_write32(offset + base, value);
}

static unsigned int matrix_read(int base, unsigned int offset)
{
	return io_read32(offset + base);
}

void matrix_write_protect_enable(unsigned int matrix_base)
{
	matrix_write(matrix_base, MATRIX_WPMR,
		    (MATRIX_WPMR_WPKEY_PASSWD | MATRIX_WPMR_WPEN_ENABLE));
}

void matrix_write_protect_disable(unsigned int matrix_base)
{
	matrix_write(matrix_base, MATRIX_WPMR, MATRIX_WPMR_WPKEY_PASSWD);
}

void matrix_configure_slave_security(unsigned int matrix_base,
				     unsigned int slave,
				     unsigned int srtop_setting,
				     unsigned int srsplit_setting,
				     unsigned int ssr_setting)
{
	matrix_write(matrix_base, MATRIX_SSR(slave), ssr_setting);
	matrix_write(matrix_base, MATRIX_SRTSR(slave), srtop_setting);
	matrix_write(matrix_base, MATRIX_SASSR(slave), srsplit_setting);
}

static const struct peri_security *get_peri_security(unsigned int peri_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(peri_security_array); i++) {
		if (peri_id == peri_security_array[i].peri_id)
			return &peri_security_array[i];
	}

	return NULL;
}

static int matrix_set_periph_world(unsigned int matrix, unsigned int peri_id,
				   unsigned int world)
{
	unsigned int base;
	unsigned int spselr;
	unsigned int idx;
	unsigned int bit;

	idx = peri_id / 32;
	if (idx > 3)
		return -1;

	bit = (0x01 << (peri_id % 32));

	if (matrix == MATRIX_H32MX)
		base = matrix32_base();
	else if (matrix == MATRIX_H64MX)
		base = matrix64_base();
	else
		return -1;

	spselr = matrix_read(base, MATRIX_SPSELR(idx));
	if (world == WORLD_SECURE)
		spselr &= ~bit;
	else
		spselr |= bit;
	matrix_write(base, MATRIX_SPSELR(idx), spselr);

	return 0;
}

int matrix_configure_periph_secure(unsigned int peri_id)
{
	const struct peri_security *psec = NULL;

	psec = get_peri_security(peri_id);
	if (!psec)
		return -1;

	return matrix_set_periph_world(psec->matrix, peri_id, WORLD_SECURE);
}

int matrix_configure_periph_non_secure(unsigned int *peri_id_array,
				       unsigned int size)
{
	unsigned int i;
	unsigned int *peri_id_p;
	unsigned int matrix;
	unsigned int peri_id;
	const struct peri_security *peripheral_sec;
	int ret;

	if (!peri_id_array || !size)
		return -1;

	peri_id_p = peri_id_array;
	for (i = 0; i < size; i++) {
		peripheral_sec = get_peri_security(*peri_id_p);
		if (!peripheral_sec)
			return -1;

		if (peripheral_sec->security_type != SECURITY_TYPE_PS)
			return -1;

		matrix = peripheral_sec->matrix;
		peri_id = *peri_id_p;
		ret = matrix_set_periph_world(matrix, peri_id,
					      WORLD_NON_SECURE);
		if (ret)
			return -1;

		peri_id_p++;
	}

	return 0;
}
