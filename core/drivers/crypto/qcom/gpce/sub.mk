# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026, Qualcomm Technologies, Inc.

# Qualcomm GPCE SHA-1 driver using direct HWIO transfers.
srcs-$(CFG_QCOM_GPCE_HASH) += qce_hash.c
srcs-$(CFG_QCOM_GPCE_HASH) += sha1_hwio.c
srcs-$(CFG_QCOM_GPCE_HASH) += sha_hw_cmn.c
srcs-$(CFG_QCOM_GPCE_HASH) += sha_hwio_cmn.c
srcs-$(CFG_QCOM_GPCE_HASH) += ce_hal.c
srcs-$(CFG_QCOM_GPCE_HASH) += ce_hwio.c
srcs-$(CFG_QCOM_GPCE_HASH) += util_blkbuf.c
