# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-$(CFG_QCOM_QFPROM_FUSE_CORE) += qfprom_core.c
srcs-$(CFG_QCOM_QFPROM_FUSE_CORE) += qfprom_hal.c
srcs-$(CFG_QCOM_QFPROM_FUSE_CORE) += qfprom_target.c
srcs-$(CFG_QCOM_QFPROM_FUSE_CORE) += $(PLATFORM_FLAVOR)/qfprom_fuse_region.c
srcs-$(CFG_QCOM_FUSE_PTA) += qfprom_secboot.c

global-incdirs-$(CFG_QCOM_QFPROM_FUSE_CORE) += .
global-incdirs-y += $(PLATFORM_FLAVOR)
