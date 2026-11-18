/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _CLOCK_GROUP_H_
#define _CLOCK_GROUP_H_

#include <platform_config.h>

#ifdef CFG_QCOM_CLK_CFG

/* WRAP0 SE CBCRs and CMD_RCGRs */
#define GCC_QUPV3_WRAP0_S0_CBCR                            (GCC_BASE + 0x1E004)
#define GCC_QUPV3_WRAP0_S0_CMD_RCGR                        (GCC_BASE + 0x1E014)
#define GCC_QUPV3_WRAP0_S1_CBCR                            (GCC_BASE + 0x1E140)
#define GCC_QUPV3_WRAP0_S1_CMD_RCGR                        (GCC_BASE + 0x1E150)
#define GCC_QUPV3_WRAP0_S2_CBCR                            (GCC_BASE + 0x1E27C)
#define GCC_QUPV3_WRAP0_S2_CMD_RCGR                        (GCC_BASE + 0x1E28C)
#define GCC_QUPV3_WRAP0_S3_CBCR                            (GCC_BASE + 0x1E3B8)
#define GCC_QUPV3_WRAP0_S3_CMD_RCGR                        (GCC_BASE + 0x1E3C8)
#define GCC_QUPV3_WRAP0_S4_CBCR                            (GCC_BASE + 0x1E4F4)
#define GCC_QUPV3_WRAP0_S4_CMD_RCGR                        (GCC_BASE + 0x1E504)
#define GCC_QUPV3_WRAP0_S5_CBCR                            (GCC_BASE + 0x1E630)
#define GCC_QUPV3_WRAP0_S5_CMD_RCGR                        (GCC_BASE + 0x1E640)

/* WRAP1 SE CBCRs and CMD_RCGRs */
#define GCC_QUPV3_WRAP1_S0_CBCR                            (GCC_BASE + 0x18004)
#define GCC_QUPV3_WRAP1_S0_CMD_RCGR                        (GCC_BASE + 0x18014)
#define GCC_QUPV3_WRAP1_S1_CBCR                            (GCC_BASE + 0x18140)
#define GCC_QUPV3_WRAP1_S1_CMD_RCGR                        (GCC_BASE + 0x18150)
#define GCC_QUPV3_WRAP1_S2_CBCR                            (GCC_BASE + 0x1827C)
#define GCC_QUPV3_WRAP1_S2_CMD_RCGR                        (GCC_BASE + 0x1828C)
#define GCC_QUPV3_WRAP1_S3_CBCR                            (GCC_BASE + 0x183B8)
#define GCC_QUPV3_WRAP1_S3_CMD_RCGR                        (GCC_BASE + 0x183C8)
#define GCC_QUPV3_WRAP1_S4_CBCR                            (GCC_BASE + 0x184F4)
#define GCC_QUPV3_WRAP1_S4_CMD_RCGR                        (GCC_BASE + 0x18504)
#define GCC_QUPV3_WRAP1_S5_CBCR                            (GCC_BASE + 0x18630)
#define GCC_QUPV3_WRAP1_S5_CMD_RCGR                        (GCC_BASE + 0x18640)
#define GCC_QUPV3_WRAP1_S6_CBCR                            (GCC_BASE + 0x1876C)
#define GCC_QUPV3_WRAP1_S6_CMD_RCGR                        (GCC_BASE + 0x1877C)

/* Wrapper infrastructure clocks (core/core_2x/m_ahb/s_ahb)*/
#define GCC_QUPV3_WRAP_0_M_AHB_CBCR                        (GCC_BASE + 0x23294)
#define GCC_QUPV3_WRAP_0_S_AHB_CBCR                        (GCC_BASE + 0x23298)
#define GCC_QUPV3_WRAP0_CORE_CBCR                          (GCC_BASE + 0x2329C)
#define GCC_QUPV3_WRAP0_CORE_2X_CBCR                       (GCC_BASE + 0x232B0)
#define GCC_QUPV3_WRAP_1_M_AHB_CBCR                        (GCC_BASE + 0x2313C)
#define GCC_QUPV3_WRAP_1_S_AHB_CBCR                        (GCC_BASE + 0x23140)
#define GCC_QUPV3_WRAP1_CORE_CBCR                          (GCC_BASE + 0x23144)
#define GCC_QUPV3_WRAP1_CORE_2X_CBCR                       (GCC_BASE + 0x23158)

/*
 * Shared branch-enable vote registers; branches gate through one of these,
 * not their own CBCR CLK_ENABLE bit.
 */
#define GCC_CLOCK_BRANCH_ENA_VOTE                                  (GCC_BASE + 0x53010)
#define GCC_CLOCK_BRANCH_ENA_VOTE_1                                (GCC_BASE + 0x53018)
#define GCC_CLOCK_BRANCH_ENA_VOTE_2                                (GCC_BASE + 0x53020)
#define GCC_CLOCK_BRANCH_ENA_VOTE_3                                (GCC_BASE + 0x53028)

/* Bits within GCC_CLOCK_BRANCH_ENA_VOTE_1. */
#define QUPV3_WRAP1_CORE_2X_SHFT                           18
#define QUPV3_WRAP1_CORE_SHFT                              19
#define QUPV3_WRAP_1_M_AHB_SHFT                            20
#define QUPV3_WRAP_1_S_AHB_SHFT                            21
#define QUPV3_WRAP1_S0_SHFT                                22
#define QUPV3_WRAP1_S1_SHFT                                23
#define QUPV3_WRAP1_S2_SHFT                                24
#define QUPV3_WRAP1_S3_SHFT                                25
#define QUPV3_WRAP1_S4_SHFT                                26
#define QUPV3_WRAP1_S5_SHFT                                27
#define QUPV3_WRAP1_S6_SHFT                                28

/* Bits within GCC_CLOCK_BRANCH_ENA_VOTE_2. */
#define QUPV3_WRAP0_CORE_SHFT                              0
#define QUPV3_WRAP_0_S_AHB_SHFT                            1
#define QUPV3_WRAP_0_M_AHB_SHFT                            2
#define QUPV3_WRAP0_CORE_2X_SHFT                           3
#define QUPV3_WRAP0_S0_SHFT                                4
#define QUPV3_WRAP0_S1_SHFT                                5
#define QUPV3_WRAP0_S2_SHFT                                6
#define QUPV3_WRAP0_S3_SHFT                                7
#define QUPV3_WRAP0_S4_SHFT                                8
#define QUPV3_WRAP0_S5_SHFT                                9

/*
 * PLL branch-enable vote register and bits for the PLLs QUP SE RCGs source
 * from; direct GCC write, not RPMh.
 */
#define GCC_PLL_BRANCH_ENA_VOTE                                    (GCC_BASE + 0x53030)
#define GCC_PLL_VOTE_BIT_GPLL0                             0
#define GCC_PLL_VOTE_BIT_GPLL2                             2

/* RCG register layout; offsets relative to clk_rcg_desc.cmd_rcgr_addr. */
#define QCOM_RCG_CFG_REG_OFFSET                            0x4
#define QCOM_RCG_M_REG_OFFSET                              0x8
#define QCOM_RCG_N_REG_OFFSET                              0xC
#define QCOM_RCG_D_REG_OFFSET                              0x10
#define QCOM_RCG_CMD_DFSR_REG_OFFSET                       0x14
#define QCOM_RCG_PERF_DFSR_REG_OFFSET                      0x1C
#define QCOM_RCG_PERF_M_DFSR_REG_OFFSET                    0x5C
#define QCOM_RCG_PERF_N_DFSR_REG_OFFSET                    0x9C
#define QCOM_RCG_PERF_D_DFSR_REG_OFFSET                    0xDC

/* CMD_RCGR fields. */
#define QCOM_RCG_CMD_CFG_UPDATE_FMSK                       0x00000001

/* CFG_RCGR fields. */
#define QCOM_RCG_CFG_HW_CLK_CONTROL_FMSK                   0x00100000
#define QCOM_RCG_CFG_MODE_FMSK                             0x00003000
#define QCOM_RCG_CFG_MODE_SHFT                             0x0000000C
#define QCOM_RCG_CFG_SRC_SEL_FMSK                          0x00000700
#define QCOM_RCG_CFG_SRC_SEL_SHFT                          0x00000008
#define QCOM_RCG_CFG_SRC_DIV_FMSK                          0x0000001F
#define QCOM_RCG_CFG_SRC_DIV_SHFT                          0x00000000
#define QCOM_RCG_CFG_DUAL_EDGE_MODE_VAL                    0x00000002

/* CMD_DFSR fields. */
#define QCOM_RCG_CMD_DFSR_HW_CLK_CONTROL_FMSK              0x00000020
#define QCOM_RCG_CMD_DFSR_DFS_EN_FMSK                      0x00000001
#define QCOM_RCG_CMD_DFSR_SW_PERF_STATE_FMSK               0x00007800
#define QCOM_RCG_CMD_DFSR_SW_PERF_STATE_SHFT               11
#endif /* CFG_QCOM_CLK_CFG */
#endif /* _CLOCK_GROUP_H_ */
