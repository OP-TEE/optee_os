/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019-2020 NXP
 *
 * Brief   CAAM driver trace include file.
 *         Definition of the internal driver trace macros.
 */

#ifndef __CAAM_TRACE_H__
#define __CAAM_TRACE_H__

#include <trace.h>
#include <util.h>

#define CAAM_DBG_TRACE(var) (CFG_DBG_CAAM_TRACE & DBG_TRACE_##var)
#define CAAM_DBG_DESC(var)  (CFG_DBG_CAAM_DESC & DBG_TRACE_##var)
#define CAAM_DBG_BUF(var)   (CFG_DBG_CAAM_BUF & DBG_TRACE_##var)

/*
 * Debug Macros function of CAAM Debug Level setting
 * CFG_DBG_CAAM_TRACE  Module print trace
 * CFG_DBG_CAAM_DESC   Module descriptor dump
 * CFG_DBG_CAAM_BUF    Module buffer dump
 *
 * A module is represented with the same bit in each configuration value.
 * Module Bit definition is as follow:
 */
#define DBG_TRACE_HAL	 BIT32(0)  /* HAL trace */
#define DBG_TRACE_CTRL	 BIT32(1)  /* Controller trace */
#define DBG_TRACE_MEM	 BIT32(2)  /* Memory utility trace */
#define DBG_TRACE_SGT	 BIT32(3)  /* Scatter Gather trace */
#define DBG_TRACE_PWR	 BIT32(4)  /* Power trace */
#define DBG_TRACE_JR	 BIT32(5)  /* Job Ring trace */
#define DBG_TRACE_RNG	 BIT32(6)  /* RNG trace */
#define DBG_TRACE_HASH	 BIT32(7)  /* Hash trace */
#define DBG_TRACE_RSA	 BIT32(8)  /* RSA trace */

/* HAL */
#if CAAM_DBG_TRACE(HAL)
#define HAL_TRACE DRV_TRACE
#else
#define HAL_TRACE(...)
#endif

/* Controller */
#if CAAM_DBG_TRACE(CTRL)
#define CTRL_TRACE DRV_TRACE
#else
#define CTRL_TRACE(...)
#endif

/* Memory Utility */
#if CAAM_DBG_TRACE(MEM)
#define MEM_TRACE DRV_TRACE
#else
#define MEM_TRACE(...)
#endif

/* Scatter Gether Table */
#if CAAM_DBG_TRACE(SGT)
#define SGT_TRACE DRV_TRACE
#else
#define SGT_TRACE(...)
#endif

/* Power */
#if CAAM_DBG_TRACE(PWR)
#define PWR_TRACE DRV_TRACE
#else
#define PWR_TRACE(...)
#endif

/* Job Ring */
#if CAAM_DBG_TRACE(JR)
#define JR_TRACE DRV_TRACE
#if CAAM_DBG_DESC(JR)
#define JR_DUMPDESC(desc)                                                      \
	do {                                                                   \
		JR_TRACE("Descriptor");                                        \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define JR_DUMPDESC(desc)
#endif
#else
#define JR_TRACE(...)
#define JR_DUMPDESC(desc)
#endif

/* RNG */
#if CAAM_DBG_TRACE(RNG)
#define RNG_TRACE DRV_TRACE
#if CAAM_DBG_DESC(RNG)
#define RNG_DUMPDESC(desc)                                                     \
	do {                                                                   \
		RNG_TRACE("RNG Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define RNG_DUMPDESC(desc)
#endif
#else
#define RNG_TRACE(...)
#define RNG_DUMPDESC(desc)
#endif

/* Hash */
#if CAAM_DBG_TRACE(HASH)
#define HASH_TRACE DRV_TRACE
#if CAAM_DBG_DESC(HASH)
#define HASH_DUMPDESC(desc)                                                    \
	do {                                                                   \
		HASH_TRACE("HASH Descriptor");                                 \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define HASH_DUMPDESC(desc)
#endif
#if CAAM_DBG_BUF(HASH)
#define HASH_DUMPBUF DRV_DUMPBUF
#else
#define HASH_DUMPBUF(...)
#endif
#else
#define HASH_TRACE(...)
#define HASH_DUMPDESC(desc)
#define HASH_DUMPBUF(...)
#endif

/* RSA */
#if CAAM_DBG_TRACE(RSA)
#define RSA_TRACE DRV_TRACE
#if CAAM_DBG_DESC(RSA)
#define RSA_DUMPDESC(desc)                                                     \
	do {                                                                   \
		RSA_TRACE("RSA Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define RSA_DUMPDESC(desc)
#endif
#if CAAM_DBG_BUF(RSA)
#define RSA_DUMPBUF DRV_DUMPBUF
#else
#define RSA_DUMPBUF(...)
#endif
#else
#define RSA_TRACE(...)
#define RSA_DUMPDESC(desc)
#define RSA_DUMPBUF(...)
#endif

#if (TRACE_LEVEL >= TRACE_DEBUG)
#define DRV_TRACE(...)                                                         \
	trace_printf(__func__, __LINE__, TRACE_DEBUG, true, __VA_ARGS__)
#define DRV_DUMPDESC(desc) dump_desc(desc)

#define DRV_DUMPBUF(title, buf, len)                                           \
	do {                                                                   \
		__typeof__(buf) _buf = (buf);                                  \
		__typeof__(len) _len = (len);                                  \
									       \
		DRV_TRACE("%s @%p : %zu", title, _buf, _len);                  \
		dhex_dump(NULL, 0, 0, _buf, _len);                             \
	} while (0)

#else
#define DRV_TRACE(...)
#define DRV_DUMPDESC(...)
#define DRV_DUMPBUF(...)
#endif

#endif /* CAAM_TRACE_H__ */
