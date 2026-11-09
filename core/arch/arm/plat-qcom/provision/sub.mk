# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-y += provision_core.c
srcs-y += provision_boot.c
ifneq ($(CFG_QCOM_PROVISION_SEC_ELF_V3),y)
srcs-y += provision_backend_qfprom.c
srcs-y += sec_elf_v2.c
srcs-y += provision_v2.c
srcs-y += provision_regions.c
endif
srcs-$(CFG_QCOM_PROVISION_SEC_ELF_V3) += sec_elf_v3.c
srcs-$(CFG_QCOM_PROVISION_SEC_ELF_V3) += provision_v3.c
srcs-$(CFG_QCOM_PROVISION_BACKEND_TME) += provision_backend_tme.c
srcs-$(CFG_QCOM_TME_ARB) += provision_arb.c
