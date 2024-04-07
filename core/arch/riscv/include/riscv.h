/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __RISCV_H
#define __RISCV_H

#include <compiler.h>
#include <encoding.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <util.h>

#define RISCV_XLEN_BITS		(__riscv_xlen)
#define RISCV_XLEN_BYTES	(__riscv_xlen / 8)

/* Bind registers to their ABI names */
#define REG_RA	1
#define REG_SP	2
#define REG_GP	3
#define REG_TP	4
#define REG_T0	5
#define REG_T2	7
#define REG_S0	8
#define REG_S1	9
#define REG_A0	10
#define REG_A1	11
#define REG_A2	12
#define REG_A3	13
#define REG_A5	15
#define REG_A7	17
#define REG_S2	18
#define REG_S11	27
#define REG_T3	28
#define REG_T6	31

#if defined(CFG_RISCV_M_MODE)
#define CSR_MODE_OFFSET	PRV_M
#define XRET			mret
#elif defined(CFG_RISCV_S_MODE)
#define CSR_MODE_OFFSET	PRV_S
#define XRET			sret
#endif

#define CSR_MODE_BITS		SHIFT_U64(CSR_MODE_OFFSET, 8)

#define CSR_XSTATUS		(CSR_MODE_BITS | 0x000)
#define CSR_XIE			(CSR_MODE_BITS | 0x004)
#define CSR_XTVEC		(CSR_MODE_BITS | 0x005)
#define CSR_XSCRATCH		(CSR_MODE_BITS | 0x040)
#define CSR_XEPC		(CSR_MODE_BITS | 0x041)
#define CSR_XCAUSE		(CSR_MODE_BITS | 0x042)
#define CSR_XTVAL		(CSR_MODE_BITS | 0x043)
#define CSR_XIP			(CSR_MODE_BITS | 0x044)

#define IRQ_XSOFT		(CSR_MODE_OFFSET + 0)
#define IRQ_XTIMER		(CSR_MODE_OFFSET + 4)
#define IRQ_XEXT		(CSR_MODE_OFFSET + 8)

#define CSR_XIE_SIE		BIT64(IRQ_XSOFT)
#define CSR_XIE_TIE		BIT64(IRQ_XTIMER)
#define CSR_XIE_EIE		BIT64(IRQ_XEXT)

#define CSR_XSTATUS_IE		BIT(CSR_MODE_OFFSET + 0)
#define CSR_XSTATUS_PIE		BIT(CSR_MODE_OFFSET + 4)
#define CSR_XSTATUS_SPP		BIT(8)
#define CSR_XSTATUS_SUM		BIT(18)
#define CSR_XSTATUS_MXR		BIT(19)

#ifndef __ASSEMBLER__

#define read_csr(csr)							\
	({								\
		unsigned long __tmp;					\
		asm volatile ("csrr %0, %1" : "=r"(__tmp) : "i"(csr));	\
		__tmp;							\
	})

#define write_csr(csr, val)						\
	({								\
		asm volatile ("csrw %0, %1" : : "i"(csr), "rK"(val));	\
	})

#define swap_csr(csr, val)						\
	({								\
		unsigned long __tmp;					\
		asm volatile ("csrrw %0, %1, %2"			\
			      : "=r"(__tmp) : "i"(csr), "rK"(val));	\
		__tmp;							\
	})

#define set_csr(csr, bit)						\
	({								\
		unsigned long __tmp;					\
		asm volatile ("csrrs %0, %1, %2"			\
			      : "=r"(__tmp) : "i"(csr), "rK"(bit));	\
		__tmp;							\
	})

#define clear_csr(csr, bit)						\
	({								\
		unsigned long __tmp;					\
		asm volatile ("csrrc %0, %1, %2"			\
			      : "=r"(__tmp) : "i"(csr), "rK"(bit));	\
		__tmp;							\
	})

#define rdtime() read_csr(CSR_TIME)
#define rdcycle() read_csr(CSR_CYCLE)
#define rdinstret() read_csr(CSR_INSTRET)

static inline __noprof void mb(void)
{
	asm volatile ("fence" : : : "memory");
}

static inline __noprof unsigned long read_gp(void)
{
	unsigned long gp = 0;

	asm volatile("mv %0, gp" : "=&r"(gp));
	return gp;
}

static inline __noprof unsigned long read_tp(void)
{
	unsigned long tp = 0;

	asm volatile("mv %0, tp" : "=&r"(tp));
	return tp;
}

static inline __noprof unsigned long read_fp(void)
{
	unsigned long fp = 0;

	asm volatile ("mv %0, s0" : "=r" (fp));

	return fp;
}

static inline __noprof unsigned long read_pc(void)
{
	unsigned long pc = 0;

	asm volatile ("auipc %0, 0" : "=r" (pc));

	return pc;
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

__noprof uint64_t read_time(void);

static inline __noprof uint64_t barrier_read_counter_timer(void)
{
	mb();	/* Get timer value after pending operations have completed */
	return read_time();
}

static inline __noprof uint32_t read_cntfrq(void)
{
	return CFG_RISCV_MTIME_RATE;
}

__noprof bool riscv_detect_csr_seed(void);

#endif /*__ASSEMBLER__*/

#endif /*__RISCV_H*/
