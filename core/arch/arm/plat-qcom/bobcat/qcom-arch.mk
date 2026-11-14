# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

CFG_QCOM_SEC_WDOG ?= y

# XPU protection for TZDRAM and the OP-TEE DIAG log buffer
CFG_QCOM_XPU_PROTECT ?= y
ifeq ($(CFG_QCOM_XPU_PROTECT),y)
$(call force,CFG_QCOM_XPUV4,y)
endif

CFG_PAS_MD_SLOTS ?= 1
CFG_PAS_TA_HEAP_SIZE ?= (4 * 1024)

# Each client forces on what it needs (HUK -> KM -> COM -> MBOX), so disabling
# a layer means disabling the clients above it too.
CFG_QCOM_TMEL_HUK ?= y
ifeq ($(CFG_QCOM_TMEL_HUK),y)
$(call force,CFG_QCOM_TMEL_KM,y,required by CFG_QCOM_TMEL_HUK)
endif

ifeq ($(CFG_QCOM_TMEL_KM),y)
$(call force,CFG_QCOM_TMEL_COM,y,required by CFG_QCOM_TMEL_KM)
endif

CFG_QCOM_TMEL_COM ?= y
ifeq ($(CFG_QCOM_TMEL_COM),y)
$(call force,CFG_QCOM_MBOX,y,required by CFG_QCOM_TMEL_COM)
endif

CFG_TMEL_COM_IPCBUF_CARVEOUT_SIZE ?= 0x3000
