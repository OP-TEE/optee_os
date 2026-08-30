# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-y += qfprom_core.c
srcs-y += qfprom_hal.c
srcs-y += qfprom_target.c
srcs-$(CFG_QCOM_QFPROM_RPMH_CLIENT) += qfprom_rpmh.c
srcs-y += $(PLATFORM_FLAVOR)/qfprom_fuse_region.c
# The ARB/MRC policy reads the secure boot state from qfprom_secboot.c.
ifneq ($(filter y,$(CFG_QCOM_FUSE_PTA) $(CFG_QCOM_QFPROM_ARB_MRC)),)
srcs-y += qfprom_secboot.c
endif
srcs-$(CFG_QCOM_QFPROM_ARB_MRC) += qfprom_arb_mrc.c
srcs-$(CFG_QCOM_QFPROM_ARB_MRC) += $(PLATFORM_FLAVOR)/qfprom_pil_arb.c

global-incdirs-y += .
global-incdirs-y += $(PLATFORM_FLAVOR)
