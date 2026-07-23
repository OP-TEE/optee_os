# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Qualcomm Technologies, Inc.

incdirs-y += ../include ../ce/include
srcs-y += authenc.c
srcs-$(CFG_QCOM_CE_AES_GCM) += gcm.c
