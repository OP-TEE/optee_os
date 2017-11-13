/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#ifndef __CAAM_H
#define __CAAM_H

#include <stdint.h>

struct rng4tst {
	uint32_t rtmctl;		/* misc. control register */
	uint32_t rtscmisc;		/* statistical check misc. register */
	uint32_t rtpkrrng;		/* poker range register */
	union {
		uint32_t rtpkrmax;	/* PRGM=1: poker max.
					 *	limit register
					 */
		uint32_t rtpkrsq;	/* PRGM=0: poker square calc.
					 *	result register
					 */
	} rtpk;
	uint32_t rtsdctl;		/* seed control register */
	union {
		uint32_t rtsblim;	/* PRGM=1: sparse bit limit register */
		uint32_t rttotsam;	/* PRGM=0: total samples register */
	} rtsb;
	uint32_t rtfreqmin;		/* frequency count min.
					 *	limit register
					 */
	union {
		uint32_t rtfreqmax;	/* PRGM=1: freq. count max.
					 *	limit register
					 */
		uint32_t rtfreqcnt;	/* PRGM=0: freq. count register */
	} rtfreq;
	uint32_t rsvd1[40];
	uint32_t rdsta;		/*RNG DRNG Status Register*/
	uint32_t rsvd2[15];
};

struct ccsr_sec {
	uint32_t	res0;
	uint32_t	mcfgr;		/* Master CFG Register */
	uint8_t	res1[0x4];
	uint32_t	scfgr;
	struct {
		uint32_t	ms;	/* Job Ring LIODN Register, MS */
		uint32_t	ls;	/* Job Ring LIODN Register, LS */
	} jrliodnr[4];
	uint8_t	res2[0x2c];
	uint32_t	jrstartr;	/* Job Ring Start Register */
	struct {
		uint32_t	ms;	/* RTIC LIODN Register, MS */
		uint32_t	ls;	/* RTIC LIODN Register, LS */
	} rticliodnr[4];
	uint8_t	res3[0x1c];
	uint32_t	decorr;		/* DECO Request Register */
	struct {
		uint32_t	ms;	/* DECO LIODN Register, MS */
		uint32_t	ls;	/* DECO LIODN Register, LS */
	} decoliodnr[8];
	uint8_t	res4[0x40];
	uint32_t	dar;		/* DECO Avail Register */
	uint32_t	drr;		/* DECO Reset Register */
	uint8_t	res5[0x4d8];
	struct rng4tst rng;	/* RNG Registers */
	uint8_t	res6[0x8a0];
	uint32_t	crnr_ms; /* CHA Revision Number Register, MS */
	uint32_t	crnr_ls; /* CHA Revision Number Register, LS */
	uint32_t	ctpr_ms; /* Compile Time Parameters Register, MS */
	uint32_t	ctpr_ls; /* Compile Time Parameters Register, LS */
	uint8_t	res7[0x10];
	uint32_t	far_ms;	/* Fault Address Register, MS */
	uint32_t	far_ls;	/* Fault Address Register, LS */
	uint32_t	falr;	/* Fault Address LIODN Register */
	uint32_t	fadr;	/* Fault Address Detail Register */
	uint8_t	res8[0x4];
	uint32_t	csta;	/* CAAM Status Register */
	uint32_t	smpart;	/* Secure Memory Partition Parameters */
	uint32_t	smvid;	/* Secure Memory Version ID */
	uint32_t	rvid;	/* RTIC Version ID Reg.*/
	uint32_t	ccbvid;	/* CHA Cluster Block Version ID Register */
	uint32_t	chavid_ms; /* CHA Version ID Register, MS */
	uint32_t	chavid_ls; /* CHA Version ID Register, LS */
	uint32_t	chanum_ms; /* CHA Number Register, MS */
	uint32_t	chanum_ls; /* CHA Number Register, LS */
	uint32_t	secvid_ms; /* SEC Version ID Register, MS */
	uint32_t	secvid_ls; /* SEC Version ID Register, LS */
	uint8_t	res9[0x6020];
	uint32_t	qilcr_ms; /* Queue Interface LIODN CFG Register, MS */
	uint32_t	qilcr_ls; /* Queue Interface LIODN CFG Register, LS */
	uint8_t	res10[0x8fd8];
};

struct jr_regs {
	uint32_t irba_h;
	uint32_t irba_l;
	uint32_t rsvd1;
	uint32_t irs;
	uint32_t rsvd2;
	uint32_t irsa;
	uint32_t rsvd3;
	uint32_t irja;
	uint32_t orba_h;
	uint32_t orba_l;
	uint32_t rsvd4;
	uint32_t ors;
	uint32_t rsvd5;
	uint32_t orjr;
	uint32_t rsvd6;
	uint32_t orsf;
	uint32_t rsvd7;
	uint32_t jrsta;
	uint32_t rsvd8;
	uint32_t jrint;
	uint32_t jrcfg0;
	uint32_t jrcfg1;
	uint32_t rsvd9;
	uint32_t irri;
	uint32_t rsvd10;
	uint32_t orwi;
	uint32_t rsvd11;
	uint32_t jrcr;
};

#define MCFGR_AWCACHE_SHIFT	8
#define MCFGR_AWCACHE_MASK	(0xf << MCFGR_AWCACHE_SHIFT)
#define MCFGR_ARCACHE_SHIFT	12
#define MCFGR_ARCACHE_MASK	(0xf << MCFGR_ARCACHE_SHIFT)

#endif
