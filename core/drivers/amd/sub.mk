# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
#
#

subdirs-$(CFG_AMD_ASU_SUPPORT) += asu

srcs-$(CFG_AMD_PS_GPIO) += gpio_common.c ps_gpio_driver.c
