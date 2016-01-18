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

union dword {
	unsigned long long dw;
	unsigned long w[2];
};

long long __aeabi_llsl(long long a, int shift);
long long __aeabi_llsl(long long a, int shift)
{
	union dword dword = { .dw = a };
	unsigned long hi = dword.w[1];
	unsigned long lo = dword.w[0];

	if (shift >= 32) {
		hi = lo << (shift - 32);
		lo = 0;
	} else if (shift > 0) {
		hi = (hi << shift) | (lo >> (32 - shift));
		lo = lo << shift;
	}

	dword.w[1] = hi;
	dword.w[0] = lo;
	return dword.dw;
}

long long __aeabi_llsr(long long a, int shift);
long long __aeabi_llsr(long long a, int shift)
{
	union dword dword = { .dw = a };
	unsigned long hi = dword.w[1];
	unsigned long lo = dword.w[0];

	if (shift >= 32) {
		lo = hi >> (shift - 32);
		hi = 0;
	} else if (shift > 0) {
		lo = (lo >> shift) | (hi << (32 - shift));
		hi = hi >> shift;
	}

	dword.w[1] = hi;
	dword.w[0] = lo;
	return dword.dw;
}
