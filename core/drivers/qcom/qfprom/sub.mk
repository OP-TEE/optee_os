# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-$(GTH) += qfprom_core.c
srcs-$(GTH) += qfprom_fec.c
srcs-$(GTH) += qfprom_hal.c
srcs-$(GTH) += qfprom_target.c
srcs-$(CFG_QCOM_QFPROM_RPMH_CLIENT) += qfprom_rpmh.c
srcs-y += $(PLATFORM_FLAVOR)/qfprom_fuse_region.c
srcs-$(CFG_QCOM_FUSE_PTA) += qfprom_secboot.c

global-incdirs-$(GTH) += .
global-incdirs-y += $(PLATFORM_FLAVOR)
