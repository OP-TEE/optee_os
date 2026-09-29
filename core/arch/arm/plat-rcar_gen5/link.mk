# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025-2026, Renesas Electronics Corporation.
#

include core/arch/arm/kernel/link.mk

SRECFLAGS ?= --srec-forceS3 --adjust-vma=$(CFG_TZDRAM_START)

all: $(link-out-dir)/tee.srec
