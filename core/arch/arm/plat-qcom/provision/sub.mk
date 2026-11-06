# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

global-incdirs-$(CFG_QCOM_TMEL_FUSEPROV) += .

srcs-$(CFG_QCOM_QFPROM_FUSEPROV) += sec_elf_v2.c
srcs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision_core.c
srcs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision_regions.c
srcs-$(CFG_QCOM_QFPROM_FUSEPROV) += provision_boot.c

srcs-$(CFG_QCOM_TMEL_FUSEPROV) += sec_elf_v3.c
srcs-$(CFG_QCOM_TMEL_FUSEPROV) += fuseprov_v3.c
