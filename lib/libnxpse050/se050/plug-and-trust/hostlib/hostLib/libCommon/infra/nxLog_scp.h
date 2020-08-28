/*
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NX_LOG_SCP_H
#define NX_LOG_SCP_H

#include <nxLog.h>

/* ############################################################ */
/* ## AUTO Generated ########################################## */
/* ############################################################ */

/* Default configuration file */
#include <nxLog_DefaultConfig.h>

/* clang-format off */

/* Check if we are double defining these macros */
#if defined(LOG_D) || defined(LOG_I) || defined(LOG_W) || defined(LOG_E)
/* This should not happen.  The only reason this could happn is double inclusion of different log files. */
#   error "LOG_ macro already defined"
#endif /* LOG_E */

/* Enable/Set log levels for 'scp' - start */
/* If source file, or nxLog_Config.h has not set it, set these defines
 *
 * Do not #undef these values, rather set to 0/1. This way we can
 * jump to definition and avoid plain-old-text-search to jump to
 * undef. */

#ifndef NX_LOG_ENABLE_SCP_DEBUG
#   define NX_LOG_ENABLE_SCP_DEBUG (NX_LOG_ENABLE_DEFAULT_DEBUG)
#endif
#ifndef NX_LOG_ENABLE_SCP_INFO
#   define NX_LOG_ENABLE_SCP_INFO (NX_LOG_ENABLE_SCP_DEBUG + NX_LOG_ENABLE_DEFAULT_INFO)
#endif
#ifndef NX_LOG_ENABLE_SCP_WARN
#   define NX_LOG_ENABLE_SCP_WARN (NX_LOG_ENABLE_SCP_INFO + NX_LOG_ENABLE_DEFAULT_WARN)
#endif
#ifndef NX_LOG_ENABLE_SCP_ERROR
#   define NX_LOG_ENABLE_SCP_ERROR (NX_LOG_ENABLE_SCP_WARN + NX_LOG_ENABLE_DEFAULT_ERROR)
#endif

/* Enable/Set log levels for 'scp' - end */

#if NX_LOG_ENABLE_SCP_DEBUG
#   define LOG_DEBUG_ENABLED 1
#   define LOG_D(format, ...) \
        nLog("scp", NX_LEVEL_DEBUG, format, ##__VA_ARGS__)
#   define LOG_X8_D(VALUE) \
        nLog("scp", NX_LEVEL_DEBUG, "%s=0x%02X",#VALUE, VALUE)
#   define LOG_U8_D(VALUE) \
        nLog("scp", NX_LEVEL_DEBUG, "%s=%u",#VALUE, VALUE)
#   define LOG_X16_D(VALUE) \
        nLog("scp", NX_LEVEL_DEBUG, "%s=0x%04X",#VALUE, VALUE)
#   define LOG_U16_D(VALUE) \
        nLog("scp", NX_LEVEL_DEBUG, "%s=%u",#VALUE, VALUE)
#   define LOG_X32_D(VALUE) \
        nLog("scp", NX_LEVEL_DEBUG, "%s=0x%08X",#VALUE, VALUE)
#   define LOG_U32_D(VALUE) \
        nLog("scp", NX_LEVEL_DEBUG, "%s=%u",#VALUE, VALUE)
#   define LOG_AU8_D(ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_DEBUG, #ARRAY, ARRAY, LEN)
#   define LOG_MAU8_D(MESSAGE, ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_DEBUG, MESSAGE, ARRAY, LEN)
#else
#   define LOG_DEBUG_ENABLED 0
#   define LOG_D(...)
#   define LOG_X8_D(VALUE)
#   define LOG_U8_D(VALUE)
#   define LOG_X16_D(VALUE)
#   define LOG_U16_D(VALUE)
#   define LOG_X32_D(VALUE)
#   define LOG_U32_D(VALUE)
#   define LOG_AU8_D(ARRAY, LEN)
#   define LOG_MAU8_D(MESSAGE, ARRAY, LEN)
#endif

#if NX_LOG_ENABLE_SCP_INFO
#   define LOG_INFO_ENABLED 1
#   define LOG_I(format, ...) \
        nLog("scp", NX_LEVEL_INFO, format, ##__VA_ARGS__)
#   define LOG_X8_I(VALUE) \
        nLog("scp", NX_LEVEL_INFO, "%s=0x%02X",#VALUE, VALUE)
#   define LOG_U8_I(VALUE) \
        nLog("scp", NX_LEVEL_INFO, "%s=%u",#VALUE, VALUE)
#   define LOG_X16_I(VALUE) \
        nLog("scp", NX_LEVEL_INFO, "%s=0x%04X",#VALUE, VALUE)
#   define LOG_U16_I(VALUE) \
        nLog("scp", NX_LEVEL_INFO, "%s=%u",#VALUE, VALUE)
#   define LOG_X32_I(VALUE) \
        nLog("scp", NX_LEVEL_INFO, "%s=0x%08X",#VALUE, VALUE)
#   define LOG_U32_I(VALUE) \
        nLog("scp", NX_LEVEL_INFO, "%s=%u",#VALUE, VALUE)
#   define LOG_AU8_I(ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_INFO, #ARRAY, ARRAY, LEN)
#   define LOG_MAU8_I(MESSAGE, ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_INFO, MESSAGE, ARRAY, LEN)
#else
#   define LOG_INFO_ENABLED 0
#   define LOG_I(...)
#   define LOG_X8_I(VALUE)
#   define LOG_U8_I(VALUE)
#   define LOG_X16_I(VALUE)
#   define LOG_U16_I(VALUE)
#   define LOG_X32_I(VALUE)
#   define LOG_U32_I(VALUE)
#   define LOG_AU8_I(ARRAY, LEN)
#   define LOG_MAU8_I(MESSAGE, ARRAY, LEN)
#endif

#if NX_LOG_ENABLE_SCP_WARN
#   define LOG_WARN_ENABLED 1
#   define LOG_W(format, ...) \
        nLog("scp", NX_LEVEL_WARN, format, ##__VA_ARGS__)
#   define LOG_X8_W(VALUE) \
        nLog("scp", NX_LEVEL_WARN, "%s=0x%02X",#VALUE, VALUE)
#   define LOG_U8_W(VALUE) \
        nLog("scp", NX_LEVEL_WARN, "%s=%u",#VALUE, VALUE)
#   define LOG_X16_W(VALUE) \
        nLog("scp", NX_LEVEL_WARN, "%s=0x%04X",#VALUE, VALUE)
#   define LOG_U16_W(VALUE) \
        nLog("scp", NX_LEVEL_WARN, "%s=%u",#VALUE, VALUE)
#   define LOG_X32_W(VALUE) \
        nLog("scp", NX_LEVEL_WARN, "%s=0x%08X",#VALUE, VALUE)
#   define LOG_U32_W(VALUE) \
        nLog("scp", NX_LEVEL_WARN, "%s=%u",#VALUE, VALUE)
#   define LOG_AU8_W(ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_WARN, #ARRAY, ARRAY, LEN)
#   define LOG_MAU8_W(MESSAGE, ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_WARN, MESSAGE, ARRAY, LEN)
#else
#   define LOG_WARN_ENABLED 0
#   define LOG_W(...)
#   define LOG_X8_W(VALUE)
#   define LOG_U8_W(VALUE)
#   define LOG_X16_W(VALUE)
#   define LOG_U16_W(VALUE)
#   define LOG_X32_W(VALUE)
#   define LOG_U32_W(VALUE)
#   define LOG_AU8_W(ARRAY, LEN)
#   define LOG_MAU8_W(MESSAGE, ARRAY, LEN)
#endif

#if NX_LOG_ENABLE_SCP_ERROR
#   define LOG_ERROR_ENABLED 1
#   define LOG_E(format, ...) \
        nLog("scp", NX_LEVEL_ERROR, format, ##__VA_ARGS__)
#   define LOG_X8_E(VALUE) \
        nLog("scp", NX_LEVEL_ERROR, "%s=0x%02X",#VALUE, VALUE)
#   define LOG_U8_E(VALUE) \
        nLog("scp", NX_LEVEL_ERROR, "%s=%u",#VALUE, VALUE)
#   define LOG_X16_E(VALUE) \
        nLog("scp", NX_LEVEL_ERROR, "%s=0x%04X",#VALUE, VALUE)
#   define LOG_U16_E(VALUE) \
        nLog("scp", NX_LEVEL_ERROR, "%s=%u",#VALUE, VALUE)
#   define LOG_X32_E(VALUE) \
        nLog("scp", NX_LEVEL_ERROR, "%s=0x%08X",#VALUE, VALUE)
#   define LOG_U32_E(VALUE) \
        nLog("scp", NX_LEVEL_ERROR, "%s=%u",#VALUE, VALUE)
#   define LOG_AU8_E(ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_ERROR, #ARRAY, ARRAY, LEN)
#   define LOG_MAU8_E(MESSAGE, ARRAY,LEN) \
        nLog_au8("scp", NX_LEVEL_ERROR, MESSAGE, ARRAY, LEN)
#else
#   define LOG_ERROR_ENABLED 0
#   define LOG_E(...)
#   define LOG_X8_E(VALUE)
#   define LOG_U8_E(VALUE)
#   define LOG_X16_E(VALUE)
#   define LOG_U16_E(VALUE)
#   define LOG_X32_E(VALUE)
#   define LOG_U32_E(VALUE)
#   define LOG_AU8_E(ARRAY, LEN)
#   define LOG_MAU8_E(MESSAGE, ARRAY, LEN)
#endif

/* clang-format on */

#endif /* NX_LOG_SCP_H */
