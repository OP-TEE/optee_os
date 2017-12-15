/* SPDX-License-Identifier: BSD-2-Clause */
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
 * gmon.out file format
 *
 * This file is adapted from glibc's gmon/sys/gmon_out.h
 * Although gmon/sys/gmon_out.h is covered by the LGPL v2.1 license or later
 * as stated below, please note the following:
 * (https://www.gnu.org/licenses/lgpl-3.0.en.html#section3)
 *
 * "3. Object Code Incorporating Material from Library Header Files.
 *  The object code form of an Application may incorporate material from a
 *  header file that is part of the Library. You may convey such object code
 *  under terms of your choice, provided that, if the incorporated material
 *  is not limited to numerical parameters, data structure layouts and
 *  accessors, or small macros, inline functions and templates (ten or fewer
 *  lines in length), you do both of the following: [...]"
 *
 * The code below is indeed limited to data structure layouts.
 */

/*
 * Copyright (C) 1996-2016 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 * Contributed by David Mosberger <davidm@cs.arizona.edu>.
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * This file specifies the format of gmon.out files.  It should have
 * as few external dependencies as possible as it is going to be included
 * in many different programs.  That is, minimize the number of #include's.
 *
 * A gmon.out file consists of a header (defined by gmon_hdr) followed by
 * a sequence of records.  Each record starts with a one-byte tag
 * identifying the type of records, followed by records specific data.
 */

#ifndef GMON_OUT_H
#define GMON_OUT_H

#define	GMON_MAGIC	"gmon"	/* magic cookie */
#define GMON_VERSION	1	/* version number */

/*
 * Raw header as it appears on file (without padding).  This header
 * always comes first in gmon.out and is then followed by a series
 * records defined below.
 * Virtual addresses are stored as uintptr_t, gprof knows which size to expect
 * because the executable file is provided.
 */
struct gmon_hdr {
	char cookie[4];
	int32_t version;
	char spare[3 * 4];
} __packed;

/* types of records in this file: */
enum gmon_record_tag {
	GMON_TAG_TIME_HIST = 0,
	GMON_TAG_CG_ARC = 1,
	GMON_TAG_BB_COUNT = 2
};

struct gmon_hist_hdr {
	uintptr_t low_pc;	/* base pc address of sample buffer */
	uintptr_t high_pc;	/* max pc address of sampled buffer */
	uint32_t hist_size;	/* size of sample buffer */
	uint32_t prof_rate;	/* profiling clock rate */
	char dimen[15];		/* phys. dim., usually "seconds" */
	char dimen_abbrev;	/* usually 's' for "seconds" */
} __packed;

struct gmon_cg_arc_record {
	uintptr_t from_pc;	/* address within caller's body */
	uintptr_t self_pc;	/* address within callee's body */
	int32_t count;		/* number of arc traversals */
} __packed;

#endif /* GMON_OUT_H */
