/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once

#if ((!defined(__KERNEL__) && !defined(__LDELF__)) && defined(CFG_TA_SANITIZE_KADDRESS)) || \
    ((defined(__KERNEL__) || defined(__LDELF__)) && defined(CFG_CORE_SANITIZE_KADDRESS))
#define CFG_ASAN_ENABLED 1
#else
#define CFG_ASAN_ENABLED 0
#endif
