// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 1994-2009  Red Hat, Inc.
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
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
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
FUNCTION
<<abs>>---integer absolute value (magnitude)

INDEX
	abs

ANSI_SYNOPSIS
	#include <stdlib.h>
	int abs(int <[i]>);

TRAD_SYNOPSIS
	#include <stdlib.h>
	int abs(<[i]>)
	int <[i]>;

DESCRIPTION
<<abs>> returns
@tex
$|x|$,
@end tex
the absolute value of <[i]> (also called the magnitude
of <[i]>).  That is, if <[i]> is negative, the result is the opposite
of <[i]>, but if <[i]> is nonnegative the result is <[i]>.

The similar function <<labs>> uses and returns <<long>> rather than <<int>> values.

RETURNS
The result is a nonnegative integer.

PORTABILITY
<<abs>> is ANSI.

No supporting OS subroutines are required.
*/

#include "_ansi.h"
#include <stdlib.h>

int
_DEFUN (abs, (i), int i)
{
  return (i < 0) ? -i : i;
}
