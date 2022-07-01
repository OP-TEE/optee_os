/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef RISCV_H
#define RISCV_H

#include <compiler.h>
#include <encoding.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <util.h>

#define RISCV_XLEN_BITS		(__riscv_xlen)
#define RISCV_XLEN_BYTES	(__riscv_xlen / 8)

#define REGOFF(x)			((x) * RISCV_XLEN_BYTES)

#if __riscv_xlen == 32
#define STR       sw
#define LDR       lw
#else
#define STR       sd
#define LDR       ld
#endif

#ifndef __ASSEMBLER__

static inline __noprof void mb(void)
{
	asm volatile ("fence" : : : "memory");
}

static inline __noprof unsigned long read_tp(void)
{
	unsigned long tp;

	asm volatile("mv %0, tp" : "=&r"(tp));
	return tp;
}

static inline __noprof void wfi(void)
{
	asm volatile ("wfi");
}

static inline __noprof void flush_tlb(void)
{
	asm volatile("sfence.vma zero, zero");
}

static inline __noprof void flush_tlb_entry(unsigned long va)
{
	asm volatile ("sfence.vma %0" : : "r" (va) : "memory");
}

/* supervisor address translation and protection */
static inline __noprof unsigned long read_satp(void)
{
	unsigned long satp;

	asm volatile("csrr %0, satp" : "=r" (satp));

	return satp;
}

static inline __noprof void write_satp(unsigned long satp)
{
	asm volatile("csrw satp, %0" : : "r" (satp));
}

/* machine trap-vector base-address register */
static inline __noprof unsigned long read_mtvec(void)
{
	unsigned long mtvec;

	asm volatile("csrr %0, mtvec" : "=r" (mtvec));

	return mtvec;
}

static inline __noprof void write_mtvec(unsigned long mtvec)
{
	asm volatile("csrw mtvec, %0" : : "r" (mtvec));
}

/* supervisor trap-vector base-address register */
static inline __noprof unsigned long read_stvec(void)
{
	unsigned long stvec;

	asm volatile("csrr %0, stvec" : "=r" (stvec));

	return stvec;
}

static inline __noprof void write_stvec(unsigned long stvec)
{
	asm volatile("csrw stvec, %0" : : "r" (stvec));
}

/* machine status register */
static inline __noprof unsigned long read_mstatus(void)
{
	unsigned long mstatus;

	asm volatile("csrr %0, mstatus" : "=r" (mstatus));

	return mstatus;
}

static inline __noprof void write_mstatus(unsigned long mstatus)
{
	asm volatile("csrw mstatus, %0" : : "r" (mstatus));
}

/* supervisor status register */
static inline __noprof unsigned long read_sstatus(void)
{
	unsigned long sstatus;

	asm volatile("csrr %0, sstatus" : "=r" (sstatus));

	return sstatus;
}

static inline __noprof void write_sstatus(unsigned long sstatus)
{
	asm volatile("csrw sstatus, %0" : : "r" (sstatus));
}

static inline __noprof void set_sstatus(unsigned long sstatus)
{
	unsigned long x;

	asm volatile ("csrrs %0, sstatus, %1" : "=r"(x) : "rK"(sstatus));
}

/* machine exception delegation */
static inline __noprof unsigned long read_medeleg(void)
{
	unsigned long medeleg;

	asm volatile("csrr %0, medeleg" : "=r" (medeleg));

	return medeleg;
}

static inline __noprof void write_medeleg(unsigned long medeleg)
{
	asm volatile("csrw medeleg, %0" : : "r" (medeleg));
}

/* machine interrupt delegation */
static inline __noprof unsigned long read_mideleg(void)
{
	unsigned long mideleg;

	asm volatile("csrr %0, mideleg" : "=r" (mideleg));

	return mideleg;
}

static inline __noprof void write_mideleg(unsigned long mideleg)
{
	asm volatile("csrw mideleg, %0" : : "r" (mideleg));
}

/* machine interrupt-enable register */
static inline __noprof unsigned long read_mie(void)
{
	unsigned long mie;

	asm volatile("csrr %0, mie" : "=r" (mie));

	return mie;
}

static inline __noprof void write_mie(unsigned long mie)
{
	asm volatile("csrw mie, %0" : : "r" (mie));
}

/* supervisor interrupt-enable register */
static inline __noprof unsigned long read_sie(void)
{
	unsigned long sie;

	asm volatile("csrr %0, sie" : "=r" (sie));

	return sie;
}

static inline __noprof void write_sie(unsigned long sie)
{
	asm volatile("csrw sie, %0" : : "r" (sie));
}

/* machine exception program counter */
static inline __noprof unsigned long read_mepc(void)
{
	unsigned long mepc;

	asm volatile("csrr %0, mepc" : "=r" (mepc));

	return mepc;
}

static inline __noprof void write_mepc(unsigned long mepc)
{
	asm volatile("csrw mepc, %0" : : "r" (mepc));
}

/* supervisor exception program counter */
static inline __noprof unsigned long read_sepc(void)
{
	unsigned long sepc;

	asm volatile("csrr %0, sepc" : "=r" (sepc));

	return sepc;
}

static inline __noprof void write_sepc(unsigned long sepc)
{
	asm volatile("csrw sepc, %0" : : "r" (sepc));
}

/* machine scratch register */
static inline __noprof unsigned long read_mscratch(void)
{
	unsigned long mscratch;

	asm volatile("csrr %0, mscratch" : "=r" (mscratch));

	return mscratch;
}

static inline __noprof void write_mscratch(unsigned long mscratch)
{
	asm volatile("csrw mscratch, %0" : : "r" (mscratch));
}

/* supervisor scratch register */
static inline __noprof unsigned long read_sscratch(void)
{
	unsigned long sscratch;

	asm volatile("csrr %0, sscratch" : "=r" (sscratch));

	return sscratch;
}

static inline __noprof void write_sscratch(unsigned long sscratch)
{
	asm volatile("csrw sscratch, %0" : : "r" (sscratch));
}

/* trap-return instructions */
static inline __noprof void mret(void)
{
	asm volatile("mret");
}

static inline __noprof void sret(void)
{
	asm volatile("sret");
}

static inline __noprof void uret(void)
{
	asm volatile("uret");
}

#endif /*__ASSEMBLER__*/

#endif /*RISCV_H*/
