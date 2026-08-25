# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Qualcomm Technologies, Inc.

incdirs-y += ../hwkm/include
incdirs-y += include

srcs-y += ce.c

subdirs-$(CFG_QCOM_CE_CIPHER) += cipher
