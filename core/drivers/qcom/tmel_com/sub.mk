# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

global-incdirs-y += .
srcs-y += tmecom_client.c

# TME-Lite feature clients
subdirs-$(CFG_QCOM_TMEL_RNG) += tmel_rng
subdirs-$(CFG_QCOM_TMEL_KM) += tmel_km
