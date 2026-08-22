# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Qualcomm Technologies, Inc.

incdirs-y += ../include ../ce/include
srcs-y += cipher.c
srcs-$(CFG_QCOM_CE_AES_ECB) += ecb.c
srcs-$(CFG_QCOM_CE_AES_CBC) += cbc.c
