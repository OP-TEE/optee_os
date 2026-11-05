# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
#

qcom_icb_enabled := $(if $(filter y,$(CFG_QCOM_ICB)),y)

global-incdirs-y += include
global-incdirs-y += $(PLATFORM_FLAVOR)

srcs-$(CFG_QCOM_ICB) += icbuarb.c

srcs-$(qcom_icb_enabled) += $(PLATFORM_FLAVOR)/u_data.c
