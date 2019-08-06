/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM driver trace include file.
 *         Definition of the internal driver trace macros.
 */

#ifndef __CAAM_TRACE_H__
#define __CAAM_TRACE_H__

#include <trace.h>
#include <util.h>

/*
 * Debug Macros function of CAAM Debug Level setting
 * The CFG_CAAM_DBG is a bit mask 32 bits value defined
 * as followed:
 */
#define DBG_TRACE_HAL    BIT32(0)  /* HAL trace */
#define DBG_TRACE_CTRL   BIT32(1)  /* Controller trace */
#define DBG_TRACE_MEM    BIT32(2)  /* Memory utility trace */
#define DBG_TRACE_PWR    BIT32(3)  /* Power trace */
#define DBG_TRACE_JR     BIT32(4)  /* Job Ring trace */
#define DBG_DESC_JR      BIT32(5)  /* Job Ring dump descriptor */
#define DBG_TRACE_RNG    BIT32(6)  /* RNG trace */
#define DBG_DESC_RNG     BIT32(7)  /* RNG dump descriptor */
#define DBG_TRACE_HASH   BIT32(8)  /* Hash trace */
#define DBG_DESC_HASH    BIT32(9)  /* Hash dump descriptor */
#define DBG_BUF_HASH     BIT32(10) /* Hash dump Buffer */

/* HAL */
#if (CFG_CAAM_DBG & DBG_TRACE_HAL)
#define HAL_TRACE DRV_TRACE
#else
#define HAL_TRACE(...)
#endif

/* Controller */
#if (CFG_CAAM_DBG & DBG_TRACE_CTRL)
#define CTRL_TRACE DRV_TRACE
#else
#define CTRL_TRACE(...)
#endif

/* Memory Utility */
#if (CFG_CAAM_DBG & DBG_TRACE_MEM)
#define MEM_TRACE DRV_TRACE
#else
#define MEM_TRACE(...)
#endif

/* Power */
#if (CFG_CAAM_DBG & DBG_TRACE_PWR)
#define PWR_TRACE DRV_TRACE
#else
#define PWR_TRACE(...)
#endif

/* Job Ring */
#if (CFG_CAAM_DBG & DBG_TRACE_JR)
#define JR_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_JR)
#define JR_DUMPDESC(desc)                                                      \
	{                                                                      \
		JR_TRACE("Descriptor");                                        \
		DRV_DUMPDESC(desc);                                            \
	}
#else
#define JR_DUMPDESC(desc)
#endif
#else
#define JR_TRACE(...)
#define JR_DUMPDESC(desc)
#endif

/* RNG */
#if (CFG_CAAM_DBG & DBG_TRACE_RNG)
#define RNG_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_RNG)
#define RNG_DUMPDESC(desc)                                                     \
	{                                                                      \
		RNG_TRACE("RNG Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	}
#else
#define RNG_DUMPDESC(desc)
#endif
#else
#define RNG_TRACE(...)
#define RNG_DUMPDESC(desc)
#endif

/* Hash */
#if (CFG_CAAM_DBG & DBG_TRACE_HASH)
#define HASH_TRACE DRV_TRACE
#if (CFG_CAAM_DBG & DBG_DESC_HASH)
#define HASH_DUMPDESC(desc)                                                    \
	{                                                                      \
		HASH_TRACE("HASH Descriptor");                                 \
		DRV_DUMPDESC(desc);                                            \
	}
#else
#define HASH_DUMPDESC(desc)
#endif
#if (CFG_CAAM_DBG & DBG_BUF_HASH)
#define HASH_DUMPBUF DRV_DUMPBUF
#else
#define HASH_DUMPBUF(...)
#endif
#else
#define HASH_TRACE(...)
#define HASH_DUMPDESC(desc)
#define HASH_DUMPBUF(...)
#endif

#if (TRACE_LEVEL >= TRACE_DEBUG)
#define DRV_TRACE(...)                                                         \
	trace_printf(__func__, __LINE__, TRACE_DEBUG, true, __VA_ARGS__)
#define DRV_DUMPDESC(desc) dump_desc(desc)

#define DRV_DUMPBUF(title, buf, len)                                           \
	({                                                                     \
		__typeof__(buf) _buf = (buf);                                  \
		__typeof__(len) _len = (len);                                  \
		DRV_TRACE("%s @0x%" PRIxPTR ": %zu", title, (uintptr_t)_buf,   \
			  _len);                                               \
		dhex_dump(NULL, 0, 0, _buf, _len);                             \
	})

#else
#define DRV_TRACE(...)
#define DRV_DUMPDESC(...)
#define DRV_DUMPBUF(...)
#endif

#endif /* CAAM_TRACE_H__ */
