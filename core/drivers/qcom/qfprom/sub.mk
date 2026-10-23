# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-$(CFG_QCOM_FUSE_BLOW) += qfprom_core.c
srcs-$(CFG_QCOM_FUSE_BLOW) += qfprom_hal.c
srcs-$(CFG_QCOM_FUSE_BLOW) += qfprom_target.c
srcs-$(CFG_QCOM_FUSE_BLOW) += $(PLATFORM_FLAVOR)/qfprom_fuse_region.c
srcs-$(CFG_QCOM_FUSE_PTA) += qfprom_secboot.c

global-incdirs-y += .
global-incdirs-y += $(PLATFORM_FLAVOR)
