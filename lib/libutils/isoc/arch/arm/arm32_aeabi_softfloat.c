/*
 * Copyright (c) 2015, Linaro Limited
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

#include "platform.h"
#include <softfloat.h>

/*
 * Helpers to convert between float32 and float, and float64 and double
 * used by the AEABI functions below.
 */
static float f32_to_f(float32_t val)
{
	union {
		float32_t from;
		float to;
	} res = { .from = val };

	return res.to;
}

static float32_t f32_from_f(float val)
{
	union {
		float from;
		float32_t to;
	} res = { .from = val };

	return res.to;
}

static double f64_to_d(float64_t val)
{
	union {
		float64_t from;
		double to;
	} res = { .from = val };

	return res.to;
}

static float64_t f64_from_d(double val)
{
	union {
		double from;
		float64_t to;
	} res = { .from = val };

	return res.to;
}

/*
 * From ARM Run-time ABI for ARM Architecture
 * ARM IHI 0043D, current through ABI release 2.09
 *
 * 4.1.2 The floating-point helper functions
 */

/*
 * Table 2, Standard double precision floating-point arithmetic helper
 * functions
 */

double __aeabi_dadd(double a, double b)
{
	return f64_to_d(f64_add(f64_from_d(a), f64_from_d(b)));
}

double __aeabi_ddiv(double a, double b)
{
	return f64_to_d(f64_div(f64_from_d(a), f64_from_d(b)));
}

double __aeabi_dmul(double a, double b)
{
	return f64_to_d(f64_mul(f64_from_d(a), f64_from_d(b)));
}


double __aeabi_drsub(double a, double b)
{
	return f64_to_d(f64_sub(f64_from_d(b), f64_from_d(a)));
}

double __aeabi_dsub(double a, double b)
{
	return f64_to_d(f64_sub(f64_from_d(a), f64_from_d(b)));
}

/*
 * Table 3, double precision floating-point comparison helper functions
 */

int __aeabi_dcmpeq(double a, double b)
{
	return f64_eq(f64_from_d(a), f64_from_d(b));
}

int __aeabi_dcmplt(double a, double b)
{
	return f64_lt(f64_from_d(a), f64_from_d(b));
}

int __aeabi_dcmple(double a, double b)
{
	return f64_le(f64_from_d(a), f64_from_d(b));
}

int __aeabi_dcmpge(double a, double b)
{
	return f64_le(f64_from_d(b), f64_from_d(a));
}

int __aeabi_dcmpgt(double a, double b)
{
	return f64_lt(f64_from_d(b), f64_from_d(a));
}

/*
 * Table 4, Standard single precision floating-point arithmetic helper
 * functions
 */

float __aeabi_fadd(float a, float b)
{
	return f32_to_f(f32_add(f32_from_f(a), f32_from_f(b)));
}

float __aeabi_fdiv(float a, float b)
{
	return f32_to_f(f32_div(f32_from_f(a), f32_from_f(b)));
}

float __aeabi_fmul(float a, float b)
{
	return f32_to_f(f32_mul(f32_from_f(a), f32_from_f(b)));
}

float __aeabi_frsub(float a, float b)
{
	return f32_to_f(f32_sub(f32_from_f(b), f32_from_f(a)));
}

float __aeabi_fsub(float a, float b)
{
	return f32_to_f(f32_sub(f32_from_f(a), f32_from_f(b)));
}

/*
 * Table 5, Standard single precision floating-point comparison helper
 * functions
 */

int __aeabi_fcmpeq(float a, float b)
{
	return f32_eq(f32_from_f(a), f32_from_f(b));
}

int __aeabi_fcmplt(float a, float b)
{
	return f32_lt(f32_from_f(a), f32_from_f(b));
}

int __aeabi_fcmple(float a, float b)
{
	return f32_le(f32_from_f(a), f32_from_f(b));
}

int __aeabi_fcmpge(float a, float b)
{
	return f32_le(f32_from_f(b), f32_from_f(a));
}

int __aeabi_fcmpgt(float a, float b)
{
	return f32_lt(f32_from_f(b), f32_from_f(a));
}

/*
 * Table 6, Standard floating-point to integer conversions
 */

int __aeabi_d2iz(double a)
{
	return f64_to_i32_r_minMag(f64_from_d(a), false);
}

unsigned __aeabi_d2uiz(double a)
{
	return f64_to_ui32_r_minMag(f64_from_d(a), false);
}

long long __aeabi_d2lz(double a)
{
	return f64_to_i64_r_minMag(f64_from_d(a), false);
}

unsigned long long __aeabi_d2ulz(double a)
{
	return f64_to_ui64_r_minMag(f64_from_d(a), false);
}

int __aeabi_f2iz(float a)
{
	return f32_to_i32_r_minMag(f32_from_f(a), false);
}

unsigned __aeabi_f2uiz(float a)
{
	return f32_to_ui32_r_minMag(f32_from_f(a), false);
}

long long __aeabi_f2lz(float a)
{
	return f32_to_i64_r_minMag(f32_from_f(a), false);
}

unsigned long long __aeabi_f2ulz(float a)
{
	return f32_to_ui64_r_minMag(f32_from_f(a), false);
}

/*
 * Table 7, Standard conversions between floating types
 */

float __aeabi_d2f(double a)
{
	return f32_to_f(f64_to_f32(f64_from_d(a)));
}

double __aeabi_f2d(float a)
{
	return f64_to_d(f32_to_f64(f32_from_f(a)));
}

/*
 * Table 8, Standard integer to floating-point conversions
 */

double __aeabi_i2d(int a)
{
	return f64_to_d(i32_to_f64(a));
}

double __aeabi_ui2d(unsigned a)
{
	return f64_to_d(ui32_to_f64(a));
}

double __aeabi_l2d(long long a)
{
	return f64_to_d(i64_to_f64(a));
}

double __aeabi_ul2d(unsigned long long a)
{
	return f64_to_d(ui64_to_f64(a));
}

float __aeabi_i2f(int a)
{
	return f32_to_f(i32_to_f32(a));
}

float __aeabi_ui2f(unsigned a)
{
	return f32_to_f(ui32_to_f32(a));
}

float __aeabi_l2f(long long a)
{
	return f32_to_f(i64_to_f32(a));
}

float __aeabi_ul2f(unsigned long long a)
{
	return f32_to_f(ui64_to_f32(a));
}
