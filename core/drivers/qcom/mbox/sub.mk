# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

global-incdirs-y += .

srcs-$(CFG_QCOM_MBOX) += qcom_mbox.c
srcs-$(CFG_QCOM_MBOX_QMP_LITE) += qcom_mbox_qmp_lite.c
srcs-$(CFG_QCOM_MBOX) += $(QCOM_ARCH_FAMILY)/qcom_mbox_plat.c
