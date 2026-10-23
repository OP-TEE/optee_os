# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#

srcs-y += pas_auth.c pas_fuse.c pas_mbn.c pas_mbn_v6.c pas_meta.c \
	  pas_meta_v6.c pas_policy.c pas_sig.c pas_sig_auth.c

global-incdirs-y += $(PLATFORM_FLAVOR)
