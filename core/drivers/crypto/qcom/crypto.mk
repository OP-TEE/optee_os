# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Qualcomm Technologies, Inc.

# Enable the OP-TEE hash framework required by the Qualcomm GPCE driver.
ifeq ($(CFG_QCOM_GPCE),y)
$(call force,CFG_CRYPTO_DRIVER,y,Mandated by CFG_QCOM_GPCE)
CFG_CRYPTO_DRIVER_DEBUG ?= 0
endif

ifeq ($(CFG_QCOM_GPCE_HASH),y)
$(call force,CFG_CRYPTO_DRV_HASH,y,Mandated by CFG_QCOM_GPCE_HASH)
endif
