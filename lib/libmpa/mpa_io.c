/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include "mpa.h"

/*
 * Big #ifdef to get rid of string conversion routines
 */
#if defined(MPA_INCLUDE_STRING_CONVERSION)

/*
 * Remove the #undef if you like debug print outs and assertions
 * for this file.
 */
/*#undef DEBUG_ME */
#include "mpa_debug.h"
#include "mpa_assert.h"

/*************************************************************
 *
 *   HELPERS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   __mpa_isspace
 *
 *  Returns 1 if c is a while space character
 */
static int __mpa_isspace(char c)
{
	return c == '_'  ||	/* allow underscore which makes long hex */
				/* numbers easier to read */
	       c == ' '  ||	/* space */
	       c == '\n' ||	/* new line */
	       c == '\r' ||	/* carriage return */
	       c == '\t';	/* tab */
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_is_char_in_base
 *
 *  Returns 1 if c is either a white space char or a char in the current base,
 *  and 0 otherwise.
 */
static int __mpa_is_char_in_base(int base, int c)
{
	if (__mpa_isspace(c))
		return 1;

	switch (base) {
	case 10:
		return (c >= '0') && (c <= '9');
	case 16:
		return ((c >= '0') && (c <= '9')) ||
		       ((c >= 'A') && (c <= 'F')) ||
		       ((c >= 'a') && (c <= 'f'));
	default:
		return 0;
	}
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_digit_value
 *
 *  Returns the integer value of the hexadecimal character c.
 */
static int __mpa_digit_value(int c)
{
	if ((c >= '0') && (c <= '9'))
		return c - '0';
	if ((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;
	if ((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10;

	/* defensive */
	return 0;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_digitstr_to_binary_wsize
 *
 *  Returns the maximum number of words needed to binary represent a number
 *  consisting of "digits" digits and each digits is in base "base".
 */
static mpa_word_t __mpa_digitstr_to_binary_wsize_base_16(int digits)
{
		return (digits + 7) >> 3;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_nibble_to_char
 *
 *  caseing =  1 is lower case, 0 is uppercase
 */
static char __mpa_nibble_to_char(mpa_word_t c, int caseing)
{
	c &= 0xf;
	if (c < 0xa)
		return '0' + (char)c;
	return caseing == 0 ? 'A' - 0xA + (char)c: 'a' - 0xa + (char)c;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_word_to_hexstr
 *
 *  caseing 8= 1 is lower case, 0 is uppercase
 */
static void __mpa_word_to_hexstr(char *str, mpa_word_t w, int caseing)
{
	int i;
	for (i = NIBBLES_PER_WORD; i > 0; i--) {
		str[i - 1] =
		    __mpa_nibble_to_char(NIBBLE_OF_WORD(i - 1, w), caseing);
	}
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_mpanum_to_hexstr
 *
 *   caseing = 1 is lower case, 0 is uppercase
 */
static int __mpa_mpanum_to_hexstr(char *str, int caseing, const mpanum n)
{
	int d_idx;
	char digits[NIBBLES_PER_WORD];
	int i;
	char *cptr;
	int hex_digits;

	/* get high word with data in, watch out for zero case */
	d_idx = __mpanum_size(n);
	if (d_idx == 0) {
		*str++ = '0';
		*str = '\0';
		return 1;
	}
	d_idx--;

	cptr = str;

	/* the msw is special, since if we should not print leading zeros.
	 */
	__mpa_word_to_hexstr(digits, n->d[d_idx], caseing);

	/* find the left-most non-zero digit */
	i = NIBBLES_PER_WORD;
	while (i-- > 0)
		if (digits[i] != '0')
			break;
	while (i >= 0)
		*str++ = digits[i--];

	/* convert each word to a hex string */
	d_idx--;
	while (d_idx >= 0) {
		__mpa_word_to_hexstr(digits, n->d[d_idx], caseing);
		i = NIBBLES_PER_WORD - 1;
		while (i >= 0)
			*str++ = digits[i--];
		d_idx--;
	}
	hex_digits = (int)(str - cptr);
	*str++ = '\0';
	return hex_digits;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_count_leading_zero_bits
 *
 *
 */
static mpa_word_t __mpa_count_leading_zero_bits(mpa_word_t w)
{
	mpa_word_t mask;
	mpa_word_t zeros;

	if (w == 0)
		return MPA_WORD_SIZE;
	mask = (1 << (MPA_WORD_SIZE - 1));
	zeros = 0;
	while (!(w & mask)) {
		zeros++;
		mask >>= 1;
	}
	return zeros;
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_SizeInBase
 *
 *  Returns the number of characters needed to print |n| in base 255.
 */
static mpa_word_t __mpa_size_in_base_255(const mpanum n)
{
	mpa_word_t totalbits;
	/* number of leading zero bits in the msw of n */
	mpa_word_t zerobits_msw;

	if (__mpanum_is_zero(n))
		return 1;

	zerobits_msw = __mpa_count_leading_zero_bits(
				n->d[__mpanum_size(n) - 1]);
	totalbits = WORD_SIZE * __mpanum_size(n) - zerobits_msw;

	return (totalbits + 7) / 8;
}

/*  --------------------------------------------------------------------
 *  Function:   __mpa_add_grouping
 *
 *  Adds grouping and pad left with zeros up to groupsize chars
 *  src_len is length of src without the terminating '\0'.
 *  It will add a terminating '\0' to dest.
 */
static void __mpa_add_grouping(char *dest,
			       const char *src, int src_len, int groupsize)
{
	int grppos;
	const char *endptr;

	if (!(groupsize > 0)) {
		DPRINT("Groupsize is zero or negative. Cannot do grouping.\n");
		return;
	}

	if (src_len <= 0) {
		while (groupsize--)
			*dest++ = '0';
		*dest++ = '\0';
		return;
	}
	endptr = src + src_len;
	if (src_len % groupsize != 0) {
		/*
		 * Digits cannot be evenly divided into groups of the right
		 * size.
		 */

		grppos = (groupsize - (src_len % groupsize)) % groupsize;
		while (grppos--)
			*dest++ = '0';
		grppos = (src_len % groupsize);
		while (grppos--)
			*dest++ = *src++;

		/* insert first space */
		if (src < endptr)
			*dest++ = ' ';
	}
	grppos = groupsize;
	while (src < endptr) {
		*dest++ = *src++;
		grppos--;
		if (grppos == 0 && src < endptr) {
			*dest++ = ' ';
			grppos = groupsize;
		}
	}

	/* terminate dest */
	*dest++ = '\0';
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_get_str_size
 *
 *  Return the max size of the string representing a Big Number
 */
int mpa_get_str_size(void)
{
	return MPA_STR_MAX_SIZE;
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   mpa_set_str
 *
 *  Assigns dest the value of the digitstr, where digitstr is a character
 *  string.
 *  If the digitstr starts with a valid number, the valid part will be
 *  converted and the rest of the digitstr will not be parsed further.
 *  digitstr is assumed to be in base 16.
 *  Returns -1 if the digitstr was malformed, and the number of base digits
 *  converted (not including leading zeros) if the conversion was OK.
 *  If the digitstr is a null-ptr we return -1.
 *  If the digitstr is empty, we don't touch dest and just returns 0.
 *  If the digitstr only consists of white spaces, we set dest to zero
 *  returns 0.
 */
int mpa_set_str(mpanum dest, const char *digitstr)
{
	/* length of digitstr after removal of base indicator and spaces */
	int dlen;
	int negative;		/* ==1 if number is negative, 0 otherwise */
	int c;			/* value of characters in digitstr */
	/* a buffer holding the integer values of the digits */
	static unsigned char buf[MPA_STR_MAX_SIZE];
	/* number of digits in digitstr which has been place in buf */
	int bufidx;
	const char *endp;	/* points to the end of digitstr */
	int retval;
	/*
	 * Pointer intto dest->d where we should put the next word during
	 * conversion.
	 */
	mpa_word_t *w;
	int i;			/* loop variable */

	/* some basic sanity checks first */
	if (*digitstr == 0) {
		DPRINT("digitstr was empty, leaving dest unchanged\n");
		return 0;
	}

	/* remove leading spaces */
	do {
		c = (unsigned char)*digitstr++;
	} while (__mpa_isspace(c));

	/* check negative sign */
	negative = 0;
	if (c == '-') {
		negative = 1;
		c = (unsigned char)*digitstr++;
	}
	if (c == '\0') {
		DPRINT("digitstr consisted of only white spaces and possibly a single '-' sign. Setting dest to zero\n");
		mpa_set_word(dest, 0);
		return 0;
	}

	/* see if we have a '0x' prefix */
	if (c == '0') {
		c = (unsigned char)*digitstr++;
		if (c == 'x' || c == 'X')
			c = (unsigned char)*digitstr++;
	}

	/* skip leading zeros and spaces */
	while (c == '0' || __mpa_isspace(c))
		c = (unsigned char)*digitstr++;

	/* check if we had a simple "0" string */
	if (c == '\0') {
		mpa_set_word(dest, 0);
		return 0;
	}

	/* find the end of digitstr */
	endp = digitstr;
	while (*endp != 0)
		endp++;

	/* + 1 since we have one character in 'c' */
	dlen = (int)(endp - digitstr) + 1;
	ASSERT(dlen <= MPA_STR_MAX_SIZE, "String max size is too small");
	/* convert to a buffer of bytes */
	bufidx = 0;
	while (__mpa_is_char_in_base(16, c)) {
		if (!__mpa_isspace(c))
			buf[bufidx++] = __mpa_digit_value(c);
		c = (unsigned char)*digitstr++;
	}

	if (bufidx == 0) {
		retval = -1;
		goto cleanup;
	}

	ASSERT((__mpa_digitstr_to_binary_wsize_base_16(bufidx) <=
		__mpanum_alloced(dest)), "Dest is too small.");

	retval = bufidx;
	w = dest->d;
	mpa_set_word(dest, 0);
	/* start converting */
	*w = 0;
	i = BYTES_PER_WORD;
	dest->size = 1;
	bufidx--;		/* dec to get inside buf range */
	while (bufidx > 1) {
		*w ^=
		    (((buf[bufidx - 1] << 4) ^ (buf[bufidx])) <<
		     ((BYTES_PER_WORD - i) << 3));
		i--;
		bufidx -= 2;
		if (i == 0) {
			w++;
			*w = 0;
			i = BYTES_PER_WORD;
			dest->size++;
		}
	}
	if (bufidx == 1)
		*w ^=
		    (((buf[bufidx - 1] << 4) ^ (buf[bufidx])) <<
		     ((BYTES_PER_WORD - i) << 3));
	if (bufidx == 0)
		*w ^= (buf[bufidx] << ((BYTES_PER_WORD - i) << 3));

	if (negative)
		__mpanum_neg(dest);

cleanup:
	return retval;
}

/*  --------------------------------------------------------------------
 *  Function:   mpa_get_str
 *
 *  Prints a representation of n into str.
 *  The length allocated is the space needed to print n plus additional
 *  chars for the minus sign and the terminating '\0' char.
 *  If grouping is used, we allocate space to pad the number string with
 *  zeros to the left, up to the current group size.
 *  A pointer to str is returned. If something went wrong, we return 0.
 *
 *  mode is one of the following:
 *  MPA_STRING_MODE_HEX_UC      hex notation using upper case
 *  MPA_STRING_MODE_HEX_LC      hex notation using lower case
 *
 */
char *mpa_get_str(char *str, int mode, int groupsize, const mpanum n)
{
	char *str_to_fill;
	/* internal str with only digits, and no grouping */
	static char int_str[MPA_STR_MAX_SIZE];
	int chars_written;

	ASSERT(str != 0, "str destination buffer is null");

	if (groupsize == 0)
		str_to_fill = str;
	else
		str_to_fill = int_str;

	/* insert a minus sign */
	if (__mpanum_sign(n) == MPA_NEG_SIGN) {
		*str_to_fill = '-';
		str_to_fill++;
	}
	switch (mode) {
	case MPA_STRING_MODE_HEX_UC:
		chars_written = __mpa_mpanum_to_hexstr(str_to_fill, 0, n);
		break;
	case MPA_STRING_MODE_HEX_LC:
		chars_written = __mpa_mpanum_to_hexstr(str_to_fill, 1, n);
		break;
	default:
		DPRINT("Unknown mode %d\n", mode);
		return 0;
	}

	if (groupsize != 0)
		__mpa_add_grouping(str, int_str, chars_written, groupsize);

	return str;
}

#endif /* #if defined (MPA_INCLUDE_STRING_CONVERSION) */

static mpa_word_t set_word(const uint8_t *in, size_t in_len)
{
	int i;
	mpa_word_t out;

	out = 0;
	for (i = in_len - 1; i >= 0; i--)
		out |= in[i] << ((in_len - i - 1) * 8);
	return out;
}

int mpa_set_oct_str(mpanum dest, const uint8_t *buffer, size_t buffer_len,
		  bool negative)
{
	const uint8_t *buf = buffer;
	int bufidx = buffer_len;
	mpa_word_t *w;

	/* Strip of leading zero octets */
	while (bufidx > 0) {
		if (*buf != 0)
			break;
		bufidx--;
		buf++;
	}

	if (bufidx == 0) {
		mpa_set_word(dest, 0);
		return 0;
	}

	/*
	 * bufidx is now indexing one byte past past the last byte in the octet
	 * string relative to buf.
	 */

	if ((size_t) (bufidx - 1) > (BYTES_PER_WORD * __mpanum_alloced(dest)))
		return -1;	/* No space */

	w = dest->d;
	mpa_set_word(dest, 0);
	/* start converting */
	dest->size = 0;
	while (bufidx > 0) {
		int l = __MIN(BYTES_PER_WORD, bufidx);

		bufidx -= l;
		*w = set_word(buf + bufidx, l);
		w++;
		dest->size++;
	}

	if (negative)
		__mpanum_neg(dest);

	return 0;
}

static void get_word(mpa_word_t in, uint8_t out[BYTES_PER_WORD])
{
	int i;

	for (i = BYTES_PER_WORD - 1; i >= 0; i--) {
		out[i] = in & UINT8_MAX;
		in >>= 8;
	}
}

int mpa_get_oct_str(uint8_t *buffer, size_t *buffer_len, const mpanum n)
{
	size_t req_blen = __mpa_size_in_base_255(n);
	uint8_t first_word[BYTES_PER_WORD];
	size_t bufidx = 0;
	int d_idx;
	int i;

	if (*buffer_len < req_blen) {
		*buffer_len = req_blen;
		return -1;
	}
	/* get high word with data in, watch out for zero case */
	d_idx = __mpanum_size(n);
	if (d_idx == 0) {
		memset(buffer, 0, *buffer_len);
		goto out;
	}
	d_idx--;

	/* Strip of leading zero octets */
	get_word(n->d[d_idx], first_word);

	for (i = 0; i < BYTES_PER_WORD; i++) {
		if (first_word[i] != 0) {
			memcpy(buffer, first_word + i, BYTES_PER_WORD - i);
			bufidx = BYTES_PER_WORD - i;
			break;
		}
	}
	d_idx--;

	while (d_idx >= 0) {
		if (bufidx > req_blen)
			return -1;
		get_word(n->d[d_idx], buffer + bufidx);

		bufidx += BYTES_PER_WORD;
		d_idx--;
	}

out:
	*buffer_len = req_blen;
	return 0;
}

/* end of file mpa_io.c */
