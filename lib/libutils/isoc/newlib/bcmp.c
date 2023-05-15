// SPDX-License-Identifier: BSD-2-Clause
/*
FUNCTION
	<<bcmp>>---compare two memory areas

INDEX
	bcmp

SYNOPSIS
	#include <strings.h>
	int bcmp(const void *<[s1]>, const void *<[s2]>, size_t <[n]>);

DESCRIPTION
	This function compares not more than <[n]> bytes of the
	object pointed to by <[s1]> with the object pointed to by <[s2]>.

	This function is identical to <<memcmp>>.

RETURNS
	The function returns an integer greater than, equal to or
	less than zero 	according to whether the object pointed to by
	<[s1]> is greater than, equal to or less than the object
	pointed to by <[s2]>.

PORTABILITY
<<bcmp>> requires no supporting OS subroutines.

QUICKREF
	bcmp ansi pure
*/

#include <string.h>
#include <strings.h>

int
bcmp (const void *m1,
	const void *m2,
	size_t n)

{
  return memcmp (m1, m2, n);
}
