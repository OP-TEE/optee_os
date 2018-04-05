/* SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause) */
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file is adapted from glibc' gmon/sys/gmon.h.
 *-
 * Copyright (c) 1982, 1986, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * See gmon_out.h for gmon.out format.
 */

#ifndef GMON_H
#define GMON_H

#include <stdint.h>
#include <util.h>

/* Exported by the TA linker script */
extern uint8_t __text_start[];
extern uint8_t __text_end[];

void __mcount_internal(unsigned long frompc, unsigned long selfpc);


/*
 * Histogram counters are unsigned shorts (according to the kernel).
 */
#define	HISTCOUNTER	unsigned short

/*
 * Fraction of text space to allocate for histogram counters here, 1/2
 */
#define	HISTFRACTION	2

/*
 * Fraction of text space to allocate for from hash buckets.
 * The value of HASHFRACTION is based on the minimum number of bytes
 * of separation between two subroutine call points in the object code.
 * Given MIN_SUBR_SEPARATION bytes of separation the value of
 * HASHFRACTION is calculated as:
 *
 *	HASHFRACTION = MIN_SUBR_SEPARATION / (2 * sizeof(short) - 1);
 *
 * For example, on the VAX, the shortest two call sequence is:
 *
 *	calls	$0,(r0)
 *	calls	$0,(r0)
 *
 * which is separated by only three bytes, thus HASHFRACTION is
 * calculated as:
 *
 *	HASHFRACTION = 3 / (2 * 2 - 1) = 1
 *
 * Note that the division above rounds down, thus if MIN_SUBR_FRACTION
 * is less than three, this algorithm will not work!
 *
 * In practice, however, call instructions are rarely at a minimal
 * distance.  Hence, we will define HASHFRACTION to be 2 across all
 * architectures.  This saves a reasonable amount of space for
 * profiling data structures without (in practice) sacrificing
 * any granularity.
 */
#define	HASHFRACTION	2

/*
 * Percent of text space to allocate for tostructs.
 * This is a heuristic; we will fail with a warning when profiling programs
 * with a very large number of very small functions, but that's
 * normally OK.
 * 2 is probably still a good value for normal programs.
 * Profiling a test case with 64000 small functions will work if
 * you raise this value to 3 and link statically (which bloats the
 * text size, thus raising the number of arcs expected by the heuristic).
 */
#define ARCDENSITY	3

/*
 * Always allocate at least this many tostructs.  This
 * hides the inadequacy of the ARCDENSITY heuristic, at least
 * for small programs.
 */
#define MINARCS		50

/*
 * The type used to represent indices into gmonparam.tos[].
 */
#define	ARCINDEX	unsigned long

/*
 * Maximum number of arcs we want to allow.
 * Used to be max representable value of ARCINDEX minus 2, but now
 * that ARCINDEX is a long, that's too large; we don't really want
 * to allow a 48 gigabyte table.
 * The old value of 1<<16 wasn't high enough in practice for large C++
 * programs; will 1<<20 be adequate for long?  FIXME
 */
#define MAXARCS		(1 << 20)

struct tostruct {
	unsigned long selfpc;
	long count;
	ARCINDEX link;
};

/*
 * A raw arc, with pointers to the calling site and the called site and a
 * count.
 */
struct rawarc {
	unsigned long	raw_frompc;
	unsigned long	raw_selfpc;
	long		raw_count;
};

/*
 * The profiling data structures are housed in this structure.
 */
struct gmonparam {
	long int	state;
	unsigned short	*kcount;
	unsigned long	kcountsize;
	ARCINDEX	*froms;
	unsigned long	fromssize;
	struct tostruct	*tos;
	unsigned long	tossize;
	unsigned long	tolimit;
	unsigned long	lowpc;
	unsigned long	highpc;
	unsigned long	textsize;
	unsigned long	hashfraction;
	long		log_hashfraction;
	/* */
	uint32_t	prof_rate; /* PC sampling frequency */
};

/*
 * Possible states of profiling.
 */
#define	GMON_PROF_ON		0
#define	GMON_PROF_BUSY		1
#define	GMON_PROF_ERROR		2
#define	GMON_PROF_OFF		3
#define	GMON_PROF_OFF_EXITING	4

#endif /* GMON_H */
