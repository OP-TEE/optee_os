/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 */

#ifndef __IMX_MMDC_H
#define __IMX_MMDC_H

#define IMX_DDR_TYPE_DDR3		0
#define IMX_DDR_TYPE_LPDDR2		1
#define IMX_DDR_TYPE_LPDDR3		2
/* For i.MX6SLL */
#define IMX_MMDC_DDR_TYPE_LPDDR3	3

/* i.MX6 */
#define MMDC_MDMISC		0x18
#define MDMISC_DDR_TYPE_MASK	GENMASK_32(4, 3)
#define MDMISC_DDR_TYPE_SHIFT	0x3

/* i.MX7 */
#define DDRC_MSTR		0x0
#define MSTR_DDR3		BIT(0)
#define MSTR_LPDDR2		BIT(2)
#define MSTR_LPDDR3		BIT(3)

int imx_get_ddr_type(void);

#endif
