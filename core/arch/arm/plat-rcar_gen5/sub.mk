# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025-2026, Renesas Electronics Corporation.
#

global-incdirs-y += .
srcs-y += main.c
cppflags-main.c-y += -DTEE_IMPL_GIT_SHA1=$(TEE_IMPL_GIT_SHA1)
