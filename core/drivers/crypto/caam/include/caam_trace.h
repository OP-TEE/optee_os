/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019-2021 NXP
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
#define DBG_TRACE_CIPHER BIT32(9)  /* Cipher dump Buffer */
#define DBG_TRACE_BLOB   BIT32(10) /* BLOB trace */
#define DBG_TRACE_DMAOBJ BIT32(11) /* DMA Object trace */
#define DBG_TRACE_ECC    BIT32(12) /* ECC trace */
#define DBG_TRACE_DH	 BIT32(13) /* DH trace */
#define DBG_TRACE_DSA	 BIT32(14) /* DSA trace */

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

/* Cipher */
#if CAAM_DBG_TRACE(CIPHER)
#define CIPHER_TRACE DRV_TRACE
#if CAAM_DBG_DESC(CIPHER)
#define CIPHER_DUMPDESC(desc)                                                  \
	do {                                                                   \
		CIPHER_TRACE("CIPHER Descriptor");                             \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define CIPHER_DUMPDESC(desc)
#endif
#if CAAM_DBG_BUF(CIPHER)
#define CIPHER_DUMPBUF DRV_DUMPBUF
#else
#define CIPHER_DUMPBUF(...)
#endif
#else
#define CIPHER_TRACE(...)
#define CIPHER_DUMPDESC(desc)
#define CIPHER_DUMPBUF(...)
#endif

/* DMA Object */
#if CAAM_DBG_TRACE(DMAOBJ)
#define DMAOBJ_TRACE DRV_TRACE
#else
#define DMAOBJ_TRACE(...)
#endif

/* ECC */
#if CAAM_DBG_TRACE(ECC)
#define ECC_TRACE DRV_TRACE
#if CAAM_DBG_DESC(ECC)
#define ECC_DUMPDESC(desc)                                                     \
	do {                                                                   \
		ECC_TRACE("ECC Descriptor");                                   \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define ECC_DUMPDESC(desc) do { } while (0)
#endif
#if CAAM_DBG_BUF(ECC)
#define ECC_DUMPBUF DRV_DUMPBUF
#else
#define ECC_DUMPBUF(...) do { } while (0)
#endif
#else
#define ECC_TRACE(...) do { } while (0)
#define ECC_DUMPDESC(desc) do { } while (0)
#define ECC_DUMPBUF(...) do { } while (0)
#endif

/* DH */
#if CAAM_DBG_TRACE(DH)
#define DH_TRACE DRV_TRACE
#if CAAM_DBG_DESC(DH)
#define DH_DUMPDESC(desc)                                                      \
	{                                                                      \
		DH_TRACE("DH Descriptor");                                     \
		DRV_DUMPDESC(desc);                                            \
	}
#else
#define DH_DUMPDESC(desc)
#endif
#if CAAM_DBG_BUF(DH)
#define DH_DUMPBUF DRV_DUMPBUF
#else
#define DH_DUMPBUF(...)
#endif
#else
#define DH_TRACE(...)
#define DH_DUMPDESC(desc)
#define DH_DUMPBUF(...)
#endif

/* DSA */
#if CAAM_DBG_TRACE(DSA)
#define DSA_TRACE DRV_TRACE
#if CAAM_DBG_DESC(DSA)
#define DSA_DUMPDESC(desc)                                                     \
	do {                                                                   \
		MP_TRACE("DSA Descriptor");                                    \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define DSA_DUMPDESC(desc)
#endif
#if CAAM_DBG_BUF(DSA)
#define DSA_DUMPBUF DRV_DUMPBUF
#else
#define DSA_DUMPBUF(...)
#endif
#else
#define DSA_TRACE(...)
#define DSA_DUMPDESC(desc)
#define DSA_DUMPBUF(...)
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

/* BLOB */
#if CAAM_DBG_TRACE(BLOB)
#define BLOB_TRACE DRV_TRACE
#if CAAM_DBG_DESC(BLOB)
#define BLOB_DUMPDESC(desc)                                                    \
	do {                                                                   \
		BLOB_TRACE("BLOB Descriptor");                                 \
		DRV_DUMPDESC(desc);                                            \
	} while (0)
#else
#define BLOB_DUMPDESC(desc)
#endif
#if CAAM_DBG_BUF(BLOB)
#define BLOB_DUMPBUF DRV_DUMPBUF
#else
#define BLOB_DUMPBUF(...)
#endif
#else
#define BLOB_TRACE(...)
#define BLOB_DUMPDESC(desc)
#define BLOB_DUMPBUF(...)
#endif

#endif /* CAAM_TRACE_H__ */
