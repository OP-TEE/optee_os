/* SPDX-License-Identifier: BSD-Source-Code */
/*
 * Copyright (c) 2013, Atmel Corporation
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
#ifndef TZ_MATRIX_H
#define TZ_MATRIX_H

#define MATRIX_MCFG(n)	(0x0000 + (n) * 4) /* Master Configuration Register */
#define MATRIX_SCFG(n)	(0x0040 + (n) * 4) /* Slave Configuration Register */
#define MATRIX_PRAS(n)	(0x0080 + (n) * 8) /* Priority Register A for Slave */
#define MATRIX_PRBS(n)	(0x0084 + (n) * 8) /* Priority Register B for Slave */

#define MATRIX_MRCR	0x0100	/* Master Remap Control Register */
#define MATRIX_MEIER	0x0150	/* Master Error Interrupt Enable Register */
#define MATRIX_MEIDR	0x0154	/* Master Error Interrupt Disable Register */
#define MATRIX_MEIMR	0x0158	/* Master Error Interrupt Mask Register */
#define MATRIX_MESR	0x015c	/* Master Error Status Register */

/* Master n Error Address Register */
#define MATRIX_MEAR(n)	(0x0160 + (n) * 4)

#define MATRIX_WPMR	0x01E4		/* Write Protect Mode Register */
#define MATRIX_WPSR	0x01E8		/* Write Protect Status Register */

/* Security Slave n Register */
#define MATRIX_SSR(n)	(0x0200 + (n) * 4)
/* Security Area Split Slave n Register */
#define MATRIX_SASSR(n)	(0x0240 + (n) * 4)
/* Security Region Top Slave n Register */
#define MATRIX_SRTSR(n)	(0x0280 + (n) * 4)

/* Security Peripheral Select n Register */
#define MATRIX_SPSELR(n)	(0x02c0	+ (n) * 4)

/**************************************************************************/
/* Write Protect Mode Register (MATRIX_WPMR) */
#define MATRIX_WPMR_WPEN	(1 << 0)	/* Write Protect Enable */
#define		MATRIX_WPMR_WPEN_DISABLE	(0 << 0)
#define		MATRIX_WPMR_WPEN_ENABLE		(1 << 0)
#define	MATRIX_WPMR_WPKEY	(PASSWD << 8) /* Write Protect KEY */
#define		MATRIX_WPMR_WPKEY_PASSWD	(0x4D4154 << 8)

/* Security Slave Registers (MATRIX_SSRx) */
#define MATRIX_LANSECH(n, bit)	((bit) << n)
#define		MATRIX_LANSECH_S(n)	(0x00 << n)
#define		MATRIX_LANSECH_NS(n)	(0x01 << n)
#define MATRIX_RDNSECH(n, bit)	((bit) << (n + 8))
#define		MATRIX_RDNSECH_S(n)	(0x00 << (n + 8))
#define		MATRIX_RDNSECH_NS(n)	(0x01 << (n + 8))
#define MATRIX_WRNSECH(n, bit)	((bit) << (n + 16))
#define		MATRIX_WRNSECH_S(n)	(0x00 << (n + 16))
#define		MATRIX_WRNSECH_NS(n)	(0x01 << (n + 16))

/* Security Areas Split Slave Registers (MATRIX_SASSRx) */
#define MATRIX_SASPLIT(n, value)	((value) << (4 * n))
#define		MATRIX_SASPLIT_VALUE_4K		0x00
#define		MATRIX_SASPLIT_VALUE_8K		0x01
#define		MATRIX_SASPLIT_VALUE_16K	0x02
#define		MATRIX_SASPLIT_VALUE_32K	0x03
#define		MATRIX_SASPLIT_VALUE_64K	0x04
#define		MATRIX_SASPLIT_VALUE_128K	0x05
#define		MATRIX_SASPLIT_VALUE_256K	0x06
#define		MATRIX_SASPLIT_VALUE_512K	0x07
#define		MATRIX_SASPLIT_VALUE_1M		0x08
#define		MATRIX_SASPLIT_VALUE_2M		0x09
#define		MATRIX_SASPLIT_VALUE_4M		0x0a
#define		MATRIX_SASPLIT_VALUE_8M		0x0b
#define		MATRIX_SASPLIT_VALUE_16M	0x0c
#define		MATRIX_SASPLIT_VALUE_32M	0x0d
#define		MATRIX_SASPLIT_VALUE_64M	0x0e
#define		MATRIX_SASPLIT_VALUE_128M	0x0f

/* Security Region Top Slave Registers (MATRIX_SRTSRx) */
#define MATRIX_SRTOP(n, value)		((value) << (4 * n))
#define		MATRIX_SRTOP_VALUE_4K		0x00
#define		MATRIX_SRTOP_VALUE_8K		0x01
#define		MATRIX_SRTOP_VALUE_16K		0x02
#define		MATRIX_SRTOP_VALUE_32K		0x03
#define		MATRIX_SRTOP_VALUE_64K		0x04
#define		MATRIX_SRTOP_VALUE_128K		0x05
#define		MATRIX_SRTOP_VALUE_256K		0x06
#define		MATRIX_SRTOP_VALUE_512K		0x07
#define		MATRIX_SRTOP_VALUE_1M		0x08
#define		MATRIX_SRTOP_VALUE_2M		0x09
#define		MATRIX_SRTOP_VALUE_4M		0x0a
#define		MATRIX_SRTOP_VALUE_8M		0x0b
#define		MATRIX_SRTOP_VALUE_16M		0x0c
#define		MATRIX_SRTOP_VALUE_32M		0x0d
#define		MATRIX_SRTOP_VALUE_64M		0x0e
#define		MATRIX_SRTOP_VALUE_128M		0x0f

#endif /* #ifndef TZ_MATRIX_H */
