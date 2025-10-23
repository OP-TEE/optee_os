/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Copyright (C) STMicroelectronics 2026 - All Rights Reserved
 */

#ifndef __DT_BINDINGS_STPMIC2_H__
#define __DT_BINDINGS_STPMIC2_H__

/* IRQ definitions */
#define IT_PKEY_FA		0
#define IT_PKEY_RI		1
#define IT_WKP_FA		2
#define IT_WKP_RI		3
#define IT_VINLOW_FA		4
#define IT_VINLOW_RI		5
#define IT_VBUS_FA		6
#define IT_VBUS_RI		7

#define IT_THW_FA		8
#define IT_THW_RI		9

#define IT_BUCK1_OCP		16
#define IT_BUCK2_OCP		17
#define IT_BUCK3_OCP		18
#define IT_BUCK4_OCP		19
#define IT_BUCK5_OCP		20
#define IT_BUCK6_OCP		21
#define IT_BUCK7_OCP		22
#define IT_REFDDR_OCP		23

#define IT_LDO1_OCP		24
#define IT_LDO2_OCP		25
#define IT_LDO3_OCP		26
#define IT_LDO4_OCP		27
#define IT_LDO5_OCP		28
#define IT_LDO6_OCP		29
#define IT_LDO7_OCP		30
#define IT_LDO8_OCP		31

#endif /* __DT_BINDINGS_STPMIC2_H__ */
