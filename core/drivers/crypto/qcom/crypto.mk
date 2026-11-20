# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

# Enable the OP-TEE hash framework required by the Qualcomm GPCE driver.
ifeq ($(CFG_QCOM_GPCE),y)
$(call force,CFG_CRYPTO_DRIVER,y,Mandated by CFG_QCOM_GPCE)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

ifeq ($(CFG_QCOM_GPCE_HASH),y)
$(call force,CFG_CRYPTO_DRV_HASH,y,Mandated by CFG_QCOM_GPCE_HASH)
endif
else
$(call force,CFG_QCOM_GPCE_HASH,n,CFG_QCOM_GPCE is disabled)
endif
