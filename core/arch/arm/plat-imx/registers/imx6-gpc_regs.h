/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */
#ifndef __IMX6_GPC_REGS_H__
#define __IMX6_GPC_REGS_H__

#define GPC_REGISTER_OFFSET_MASK	0xFFF

/*
 * GPC registers - GPC
 */
#define	GPC_IMR_NUM		(4)

#define GPC_CNTR            0x0000
#define GPC_IMR1            0x0008
#define GPC_IMR2            0x000C
#define GPC_IMR3            0x0010
#define GPC_IMR4            0x0014

#define BM_GPC_CNTR_GPU_VPU_PDN_REG 0x1


/*
 * GPC registers - PGC
 */
#define GPC_PGC_MF_PDN      0x0220
#define GPC_PGC_GPU_CTRL    0x0260
#define GPC_PGC_GPU_PDNSCR  0x0268
#define GPC_PGC_CPU_CTRL    0x02A0

#endif /* __IMX6_GPC_REGS_H__ */
