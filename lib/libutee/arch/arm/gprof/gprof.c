// SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause)
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
 * Portions of this file are adapted from glibc:
 *   gmon/gmon.c
 *   gmon/mcount.c
 *
 *-
 * Copyright (c) 1983, 1992, 1993, 2011
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

#include <assert.h>
#include <compiler.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_private.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#include <user_ta_header.h>
#include <utee_types.h>
#include "gmon.h"
#include "gmon_out.h"
#include "gprof_pta.h"

static void *gprof_buf;
static size_t gprof_buf_len;

#if defined(ARM32)
#define MCOUNT_SYM __gnu_mcount_nc
#elif defined(ARM64)
#define MCOUNT_SYM _mcount
#endif

static void dummy(void) {}
void (*MCOUNT_SYM)(void) __weak = dummy;

static bool ta_instrumented(void)
{
	/*
	 * Return true if the mcount function is called somewhere (and therefore
	 * profiling should be initialized).
	 * Since gprof is not supported with shared libraries, checking if
	 * mcount is called is the same as checking if it is present in the
	 * TA binary, because the function would be eliminated at link time if
	 * not used.
	 */
	return dummy != MCOUNT_SYM;
}

#undef MCOUNT_SYM

static void *gprof_alloc(size_t len)
{
	assert(!gprof_buf);
	gprof_buf = tee_map_zi(len, TEE_MEMORY_ACCESS_ANY_OWNER);
	gprof_buf_len = len;
	return gprof_buf;
}

static struct gmonparam _gmonparam = { GMON_PROF_OFF };

static uint32_t _gprof_file_id; /* File id returned by tee-supplicant */

static int _gprof_s_scale;
#define SCALE_1_TO_1 0x10000L

/* Adjust PC so that gprof can locate it in the TA ELF file */
static unsigned long __noprof adjust_pc(unsigned long pc)
{
	return pc - (unsigned long)__text_start + sizeof(struct ta_head);
}

void __utee_gprof_init(void)
{
	unsigned long lowpc;
	unsigned long highpc;
	struct gmonparam *p = &_gmonparam;
	size_t bufsize;
	TEE_Result res;
	char *cp;

	if (!ta_instrumented())
		return;

	lowpc = adjust_pc((unsigned long)__text_start);
	highpc = adjust_pc((unsigned long)__text_end);

	/*
	 * Round lowpc and highpc to multiples of the density we're using
	 * so the rest of the scaling (here and in gprof) stays in ints.
	 */
	p->lowpc = ROUNDDOWN(lowpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->highpc = ROUNDUP(highpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->textsize = p->highpc - p->lowpc;
	p->kcountsize = ROUNDUP(p->textsize / HISTFRACTION, sizeof(*p->froms));
	p->hashfraction = HASHFRACTION;
	p->log_hashfraction = -1;
	/*
	 * The following test must be kept in sync with the corresponding
	 * test in __mcount_internal
	 */
	if ((HASHFRACTION & (HASHFRACTION - 1)) == 0) {
		/*
		 * If HASHFRACTION is a power of two, mcount can use shifting
		 * instead of integer division. Precompute shift amount.
		 */
		p->log_hashfraction = __builtin_ffs(p->hashfraction *
						    sizeof(*p->froms)) - 1;
	}
	p->fromssize = p->textsize / HASHFRACTION;
	p->tolimit = p->textsize * ARCDENSITY / 100;
	if (p->tolimit < MINARCS)
		p->tolimit = MINARCS;
	else if (p->tolimit > MAXARCS)
		p->tolimit = MAXARCS;
	p->tossize = p->tolimit * sizeof(struct tostruct);

	bufsize = p->kcountsize + p->fromssize + p->tossize;

	IMSG("gprof: initializing");
	DMSG("TA text size: %zu, gprof buffer size: %zu",
	     __text_end - __text_start, bufsize);

	cp = gprof_alloc(bufsize);
	if (!cp) {
		EMSG("gprof: could not allocate profiling buffer");
		p->tos = NULL;
		p->state = GMON_PROF_ERROR;
		return;
	}

	p->tos = (struct tostruct *)cp;
	cp += p->tossize;
	p->kcount = (HISTCOUNTER *)cp;
	cp += p->kcountsize;
	p->froms = (ARCINDEX *)cp;

	p->tos[0].link = 0;

	if (p->kcountsize < p->textsize)
		_gprof_s_scale = ((float)p->kcountsize / p->textsize) *
				  SCALE_1_TO_1;
	else
		_gprof_s_scale = SCALE_1_TO_1;

	res = __pta_gprof_pc_sampling_start(p->kcount, p->kcountsize,
					    p->lowpc +
					    ((unsigned long)__text_start -
						sizeof(struct ta_head)),
					    _gprof_s_scale);
	if (res != TEE_SUCCESS)
		EMSG("gprof: could not start PC sampling (0x%08x)", res);

	p->state = GMON_PROF_ON;
}

static void _gprof_write_buf(void *buf, size_t size)
{
	TEE_Result res;

	res = __pta_gprof_send(buf, size, &_gprof_file_id);
	if (res != TEE_SUCCESS)
		EMSG("gprof: could not send gprof data (0x%08x)", res);
}

static void _gprof_write_header(void)
{
	struct gmon_hdr ghdr;
	size_t size = sizeof(struct gmon_hdr);

	memcpy(&ghdr.cookie[0], GMON_MAGIC, sizeof(ghdr.cookie));
	ghdr.version = GMON_VERSION;
	memset(ghdr.spare, '\0', sizeof(ghdr.spare));

	_gprof_write_buf(&ghdr, size);
}

static void _gprof_write_hist(void)
{
	struct out_record {
		uint8_t tag;
		struct gmon_hist_hdr hist_hdr;
	} __packed out = {
		.tag = GMON_TAG_TIME_HIST,
		.hist_hdr = {
			.low_pc = _gmonparam.lowpc,
			.high_pc = _gmonparam.highpc,
			.hist_size = _gmonparam.kcountsize/sizeof(HISTCOUNTER),
			.prof_rate = _gmonparam.prof_rate,
			.dimen = "seconds",
			.dimen_abbrev = 's',
		}
	};

	_gprof_write_buf(&out, sizeof(out));
	_gprof_write_buf(_gmonparam.kcount, _gmonparam.kcountsize);
}

static void _gprof_write_call_graph(void)
{
#define NARCS_PER_WRITE 16
	struct out_record {
		uint8_t tag;
		uint8_t data[sizeof(struct gmon_cg_arc_record)];
	} out[NARCS_PER_WRITE];
	struct gmon_cg_arc_record arc;
	ARCINDEX from_index, to_index;
	unsigned long from_len;
	unsigned long frompc;
	int nfilled = 0;

	from_len = _gmonparam.fromssize / sizeof(*_gmonparam.froms);

	for (from_index = 0; from_index < from_len; ++from_index) {

		if (_gmonparam.froms[from_index] == 0)
			continue;

		frompc = _gmonparam.lowpc;
		frompc += (from_index * _gmonparam.hashfraction
			   * sizeof(*_gmonparam.froms));
		for (to_index = _gmonparam.froms[from_index];
		     to_index != 0;
		     to_index = _gmonparam.tos[to_index].link) {

			arc.from_pc = frompc;
			arc.self_pc = _gmonparam.tos[to_index].selfpc;
			arc.count = _gmonparam.tos[to_index].count;

			out[nfilled].tag = GMON_TAG_CG_ARC;
			memcpy(out[nfilled].data, &arc, sizeof(arc));

			if (++nfilled == NARCS_PER_WRITE) {
				_gprof_write_buf(out, sizeof(out));
				nfilled = 0;
			}
		}
	}
	if (nfilled > 0)
		_gprof_write_buf(out, nfilled * sizeof(out[0]));
}

/* Stop profiling and send profile data in gmon.out format to Normal World */
void __utee_gprof_fini(void)
{
	TEE_Result res;

	if (_gmonparam.state != GMON_PROF_ON)
		return;

	/* Stop call graph tracing */
	_gmonparam.state = GMON_PROF_OFF_EXITING;

	/* Stop TA sampling */
	res = __pta_gprof_pc_sampling_stop(&_gmonparam.prof_rate);

	_gprof_write_header();
	if (res == TEE_SUCCESS)
		_gprof_write_hist();
	_gprof_write_call_graph();

	__pta_gprof_fini();

	if (gprof_buf) {
		res = tee_unmap(gprof_buf, gprof_buf_len);
		assert(!res);
		gprof_buf = NULL;
	}
}

/*
 * Called from the assembly stub (_mcount or __gnu_mcount_nc).
 *
 * __mcount_internal updates data structures that represent traversals of the
 * program's call graph edges.  frompc and selfpc are the return
 * address and function address that represents the given call graph edge.
 */
void __noprof __mcount_internal(unsigned long frompc, unsigned long selfpc)
{
	ARCINDEX *frompcindex;
	struct tostruct *top, *prevtop;
	struct gmonparam *p;
	ARCINDEX toindex;
	int i;

	p = &_gmonparam;

	/*
	 * Check that we are profiling and that we aren't recursively invoked.
	 */
	if (p->state != GMON_PROF_ON)
		return;
	p->state = GMON_PROF_BUSY;

	frompc = adjust_pc(frompc);
	selfpc = adjust_pc(selfpc);

	/* Check that frompcindex is a reasonable pc value. */
	frompc -= p->lowpc;
	if (frompc > p->textsize)
		goto done;

	/* Note: keep in sync. with the initialization function above */
	if ((HASHFRACTION & (HASHFRACTION - 1)) == 0) {
		/* Avoid integer divide if possible */
		i = frompc >> p->log_hashfraction;
	} else {
		i = frompc / (p->hashfraction * sizeof(*p->froms));
	}
	frompcindex = &p->froms[i];
	toindex = *frompcindex;
	if (toindex == 0) {
		/* First time traversing this arc */
		toindex = ++p->tos[0].link;
		if (toindex >= p->tolimit) {
			/* Halt further profiling */
			goto overflow;
		}

		*frompcindex = toindex;
		top = &p->tos[toindex];
		top->selfpc = selfpc;
		top->count = 1;
		top->link = 0;
		goto done;
	}
	top = &p->tos[toindex];
	if (top->selfpc == selfpc) {
		/* Arc at front of chain; usual case */
		top->count++;
		goto done;
	}
	/*
	 * Have to go looking down chain for it.
	 * top points to what we are looking at,
	 * prevtop points to previous top.
	 * we know it is not at the head of the chain.
	 */
	for (;;) {
		if (top->link == 0) {
			/*
			 * top is end of the chain and none of the chain
			 * had top->selfpc == selfpc.
			 * so we allocate a new tostruct
			 * and link it to the head of the chain.
			 */
			toindex = ++p->tos[0].link;
			if (toindex >= p->tolimit)
				goto overflow;

			top = &p->tos[toindex];
			top->selfpc = selfpc;
			top->count = 1;
			top->link = *frompcindex;
			*frompcindex = toindex;
			goto done;
		}
		/*
		 * Otherwise, check the next arc on the chain.
		 */
		prevtop = top;
		top = &p->tos[top->link];
		if (top->selfpc == selfpc) {
			/*
			 * There it is. Increment its count, move it to the
			 * head of the chain.
			 */
			top->count++;
			toindex = prevtop->link;
			prevtop->link = top->link;
			top->link = *frompcindex;
			*frompcindex = toindex;
			goto done;
		}
	}
done:
	p->state = GMON_PROF_ON;
	return;
overflow:
	p->state = GMON_PROF_ERROR;
}
