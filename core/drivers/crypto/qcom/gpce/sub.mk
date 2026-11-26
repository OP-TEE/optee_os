# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

# Qualcomm GPCE SHA-256 driver using BAM transfers.
srcs-$(CFG_QCOM_GPCE_HASH) += qce_hash.c
srcs-$(CFG_QCOM_GPCE_HASH) += sha_hw_cmn.c
srcs-$(CFG_QCOM_GPCE_HASH) += ce_hal.c
srcs-$(CFG_QCOM_GPCE_HASH) += bam.c
srcs-$(CFG_QCOM_GPCE_HASH) += ce_bam.c
srcs-$(CFG_QCOM_GPCE_HASH) += util_blkbuf.c

global-incdirs-$(CFG_QCOM_GPCE_HASH) += $(PLATFORM_FLAVOR)
