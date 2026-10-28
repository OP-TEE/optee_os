# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

# The fuse-blow driver is built unless a target opts out, for instance because
# it only needs to read the security fuses.
CFG_QCOM_FUSE_BLOW ?= y

srcs-$(CFG_QCOM_FUSE_BLOW) += qfprom_core.c
srcs-$(CFG_QCOM_FUSE_BLOW) += qfprom_hal.c
srcs-$(CFG_QCOM_FUSE_BLOW) += qfprom_target.c
srcs-$(CFG_QCOM_QFPROM_RPMH_CLIENT) += qfprom_rpmh.c
srcs-$(CFG_QCOM_FUSE_BLOW) += $(PLATFORM_FLAVOR)/qfprom_fuse_region.c
srcs-$(CFG_QCOM_FUSE_PTA) += qfprom_secboot.c

global-incdirs-$(CFG_QCOM_FUSE_BLOW) += .
global-incdirs-y += $(PLATFORM_FLAVOR)
