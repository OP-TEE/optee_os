# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-y += qfprom_core.c
srcs-y += qfprom_hal.c
srcs-y += qfprom_target.c
srcs-y += $(PLATFORM_FLAVOR)/qfprom_fuse_region.c
srcs-$(CFG_QCOM_QFPROM_SECBOOT) += qfprom_secboot.c
srcs-$(CFG_QCOM_QFPROM_SECBOOT) += $(PLATFORM_FLAVOR)/qfprom_pil_arb.c

global-incdirs-y += .
global-incdirs-y += $(PLATFORM_FLAVOR)
