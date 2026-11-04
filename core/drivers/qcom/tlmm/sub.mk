# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

srcs-$(CFG_QCOM_TLMM) += gpio.c
srcs-$(CFG_QCOM_TLMM) += pinctrl.c
srcs-$(CFG_QCOM_TLMM) += $(PLATFORM_FLAVOR)/tlmm_soc_data.c
