# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
#

srcs-$(CFG_QCOM_RAMBLUR_PIMEM_V3) += ramblur/ramblur_pimem_v3.c
srcs-$(CFG_QCOM_PRNG) += prng/prng.c

subdirs-$(CFG_QCOM_CMD_DB) += cmd_db
subdirs-$(CFG_QCOM_RPMH_CLIENT) += rpmh
subdirs-$(CFG_QCOM_QFPROM) += qfprom

# G-Link Lite protocol driver
subdirs-$(CFG_QCOM_GLINK_LITE) += glink_lite

# QMP mailbox transport for G-Link Lite
subdirs-$(CFG_QCOM_XPORT_QMP) += xport_qmp
