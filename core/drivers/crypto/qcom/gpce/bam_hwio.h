/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * BAM v1 controller register offsets and field definitions.
 */
#ifndef __QCOM_GPCE_BAM_HWIO_H
#define __QCOM_GPCE_BAM_HWIO_H

#include <util.h>

/* BAM controller registers */
#define BAM_CTRL                            U(0x0)
#define BAM_DESC_CNT_TRSHLD                 U(0x8)
#define BAM_CNFG_BITS                       U(0x7c)
#define BAM_NUM_PIPES                       U(0x1008)

/* BAM_PIPE_ATTR_EEn */
#define BAM_PIPE_ATTR_EE(ee)                (U(0x300c) + U(0x1000) * (ee))

/* BAM pipe registers */
#define BAM_P_CTRL(pipe)                    (U(0x13000) + U(0x1000) * (pipe))
#define BAM_P_RST(pipe)                     (U(0x13004) + U(0x1000) * (pipe))
#define BAM_P_CNSMR_SDBND(pipe)             (U(0x13028) + U(0x1000) * (pipe))
#define BAM_P_SW_OFSTS(pipe)                (U(0x13800) + U(0x1000) * (pipe))
#define BAM_P_EVNT_REG(pipe)                (U(0x13818) + U(0x1000) * (pipe))
#define BAM_P_DESC_FIFO_ADDR(pipe)          (U(0x1381c) + U(0x1000) * (pipe))
#define BAM_P_FIFO_SIZES(pipe)              (U(0x13820) + U(0x1000) * (pipe))
#define BAM_P_EVNT_GEN_TRSHLD(pipe)         (U(0x13828) + U(0x1000) * (pipe))
#define BAM_P_DESC_FIFO_ADDR_MSB(pipe)      (U(0x13914) + U(0x1000) * (pipe))

/* BAM controller and pipe fields */
#define BAM_P_SW_OFSTS_DESC_OFFSET_MASK      U(0xffff)
#define BAM_P_SW_OFSTS_DESC_OFFSET_SHIFT     U(0)
#define BAM_P_EVNT_REG_DESC_OFFSET_MASK      U(0xffff)
#define BAM_P_EVNT_REG_DESC_OFFSET_SHIFT     U(0)
#define BAM_P_FIFO_SIZES_DESC_SIZE_MASK      U(0xffff)
#define BAM_P_FIFO_SIZES_DESC_SIZE_SHIFT     U(0)
#define BAM_CTRL_LOCAL_CLK_GATING_MASK       SHIFT_U32(0x3, 17)
#define BAM_CTRL_LOCAL_CLK_GATING_SHIFT      U(17)
#define BAM_NUM_PIPES_ADDR_WIDTH_MASK        SHIFT_U32(0x3, 14)
#define BAM_NUM_PIPES_ADDR_WIDTH_SHIFT       U(14)
#define BAM_NUM_PIPES_ADDR_WIDTH_36_BIT      U(1)
#define BAM_NUM_PIPES_ADDR_WIDTH_40_BIT      U(2)
#define BAM_P_CNSMR_SDBND_CTRL_MASK          SHIFT_U32(0xf, 16)
#define BAM_P_CNSMR_SDBND_CTRL_SHIFT         U(16)
#define BAM_P_CNSMR_SDBND_CTRL_NWD_MASK      BIT(1)
#define BAM_PIPE_ATTR_ENABLED_MASK           BIT(31)
#define BAM_PIPE_ATTR_ENABLED_SHIFT          U(31)
#define BAM_P_CTRL_LOCK_GROUP_MASK           SHIFT_U32(0x1f, 16)
#define BAM_P_CTRL_LOCK_GROUP_SHIFT          U(16)
#define BAM_P_CTRL_LOCK_GROUP_NONE           U(0)
#define BAM_P_CTRL_DIRECTION_MASK            BIT(3)
#define BAM_P_CTRL_DIRECTION_SHIFT           U(3)
#define BAM_NUM_PIPES_COUNT_MASK             U(0xff)
#define BAM_NUM_PIPES_COUNT_SHIFT            U(0)
#define BAM_P_CTRL_SYS_MODE_MASK             BIT(5)
#define BAM_P_CTRL_SYS_MODE_SHIFT            U(5)
#define BAM_P_CTRL_SYS_STRM_MASK             BIT(4)
#define BAM_P_CTRL_SYS_STRM_SHIFT            U(4)
#define BAM_CTRL_SW_RST_MASK                 BIT(0)
#define BAM_CTRL_SW_RST_SHIFT                U(0)
#define BAM_P_CTRL_EN_MASK                   BIT(1)
#define BAM_P_CTRL_EN_SHIFT                  U(1)
#define BAM_CTRL_EN_MASK                     BIT(1)
#define BAM_CTRL_EN_SHIFT                    U(1)

/* BAM pipe-reset register values. */
#define BAM_P_RST_ASSERT                     U(1)
#define BAM_P_RST_DEASSERT                   U(0)

/* Default threshold for generating a BAM pipe event. */
#define BAM_P_EVNT_GEN_TRSHLD_DEFAULT        U(1)

/* Bits [39:32] of an LPAE physical address. */
#define BAM_LPAE_ADDR_MSB_MASK               U(0xff)

/*
 * BAM_CNFG_BITS initialization: enable BAM_PIPE_CNFG (bit 2) and the
 * controller configuration bits in BAM_CNFG_BITS[31:12].
 */
#define BAM_RESET_CNFG_BITS                  U(0xfffff004)
#define BAM_RESET_DESC_CNT_TRSHLD            U(4)

#endif /* __QCOM_GPCE_BAM_HWIO_H */
