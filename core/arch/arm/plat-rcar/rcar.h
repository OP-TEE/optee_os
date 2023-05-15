/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021, EPAM Systems. All rights reserved. */

#ifndef PLAT_RCAR_RCAR_H
#define PLAT_RCAR_RCAR_H

#define PRR_OFFSET		0x44
#define PRR_PRODUCT_H3		0x4F00
#define PRR_PRODUCT_M3W		0x5200
#define PRR_PRODUCT_MASK	0xFF00
#define PRR_CUT_MASK		0xFF
#define PRR_CUT_10		0x00	/* Ver 1.0 */
#define PRR_CUT_11		0x01	/* Ver 1.1 */
#define PRR_CUT_20		0x10	/* Ver 2.0 */
#define PRR_CUT_30		0x20	/* Ver.3.0 */

#ifndef __ASSEMBLER__
extern uint32_t rcar_prr_value;
#endif

#endif	/* PLAT_RCAR_RCAR_H */
