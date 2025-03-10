# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.
#
#

incdirs-y += include

ifeq ($(CFG_AMD_PS_GPIO),y)
srcs-y += gpio_common.c
endif

srcs-$(CFG_AMD_PS_GPIO) += ps_gpio_driver.c
