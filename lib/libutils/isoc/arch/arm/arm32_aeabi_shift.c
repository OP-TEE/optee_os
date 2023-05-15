// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
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
