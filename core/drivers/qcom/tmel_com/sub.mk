# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

global-incdirs-y += .
srcs-y += tmel_com_client.c

subdirs-$(CFG_QCOM_TMEL_RNG) += tmel_rng
