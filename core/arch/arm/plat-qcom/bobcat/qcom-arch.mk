# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.

# BOBCAT architecture configuration

# TME-Lite communication stack: the tmel_com client is layered on the
# G-Link Lite protocol driver over the QMP mailbox transport, so enable
# all three together.
CFG_QCOM_TMEL_COM ?= y
ifeq ($(CFG_QCOM_TMEL_COM),y)
$(call force,CFG_QCOM_GLINK_LITE,y,required by CFG_QCOM_TMEL_COM)
$(call force,CFG_QCOM_XPORT_QMP,y,required by CFG_QCOM_TMEL_COM)
endif

# Reserve carveout at the end of TZDRAM for the TMEL IPC coherent buffers.
CFG_TMECOM_IPCBUF_CARVEOUT_SIZE ?= 0x3000

# Hardware Unique Key provider (derives the HUK via TME-Lite KM).
# Enabling HUK forces the KM client on, since the HUK is its consumer.
CFG_QCOM_TMEL_HUK ?= y
ifeq ($(CFG_QCOM_TMEL_HUK),y)
$(call force,CFG_QCOM_TMEL_KM,y,required by CFG_QCOM_TMEL_HUK)
endif

# TME-Lite Key Management client (depends on the COM stack)
$(eval $(call cfg-depends-all,CFG_QCOM_TMEL_KM,CFG_QCOM_TMEL_COM))

# TME-Lite RNG client (depends on the COM stack)
$(eval $(call cfg-depends-all,CFG_QCOM_TMEL_RNG,CFG_QCOM_TMEL_COM))
