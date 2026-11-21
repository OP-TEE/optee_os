# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

global-incdirs-y += .

srcs-y += qcom_mbox.c
srcs-y += qcom_mbox_qmp_lite.c
srcs-y += $(QCOM_ARCH_FAMILY)/qcom_mbox_plat.c
