/*
 * Copyright (c) 2014, Linaro Limited
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
 * Crude implementation (ASCII, C locale) of the standard character
 * classification routines
 */

#include <ctype.h>

int isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

int isspace(int c)
{
	return (c == ' '  || c == '\f' || c == '\n' || c == '\r' ||
		c == '\t' || c == '\v');
}

int isalpha(int c)
{
	return (islower(c) || isupper(c));
}

int isalnum(int c)
{
	return (isalpha(c) || isdigit(c));
}

int isxdigit(int c)
{
	return (isdigit(c) || (c >= 'a' && c <= 'f')
			   || (c >= 'A' && c <= 'F'));
}

int isupper(int c)
{
	return (c >= 'A' && c <= 'Z');
}

int islower(int c)
{
	return (c >= 'a' && c <= 'z');
}

int toupper(int c)
{
       if (c >= 'a' && c <= 'z')
               return 'A' + c - 'a';
       return c;
}

int tolower(int c)
{
       if (c >= 'A' && c <= 'Z')
               return 'a' + c - 'A';
       return c;
}

