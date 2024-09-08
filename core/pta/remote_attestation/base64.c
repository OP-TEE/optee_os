#include "base64.h"

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_enc_len(size_t size) { return 4 * ((size + 2) / 3) + 1; }

/**
   base64 Encode a buffer (NUL terminated)
   @param in      The input buffer to encode
   @param inlen   The length of the input buffer
   @param out     [out] The destination of the base64 encoded in
   @param outlen  [in/out] The max size and resulting size
   @return 1 if successful
*/
int base64_encode(const unsigned char *in, unsigned long inlen, char *out,
                  unsigned long *outlen) {
    size_t boffs = 0;
    const unsigned char *d = in;
    size_t n = 0;

    n = base64_enc_len(inlen);
    if (*outlen < n) {
        *outlen = n;
        return 0;
    }

    for (n = 0; n < inlen; n += 3) {
        uint32_t igrp;

        igrp = d[n];
        igrp <<= 8;

        if ((n + 1) < inlen)
            igrp |= d[n + 1];
        igrp <<= 8;

        if ((n + 2) < inlen)
            igrp |= d[n + 2];

        out[boffs] = base64_table[(igrp >> 18) & 0x3f];
        out[boffs + 1] = base64_table[(igrp >> 12) & 0x3f];
        if ((n + 1) < inlen)
            out[boffs + 2] = base64_table[(igrp >> 6) & 0x3f];
        else
            out[boffs + 2] = '=';
        if ((n + 2) < inlen)
            out[boffs + 3] = base64_table[igrp & 0x3f];
        else
            out[boffs + 3] = '=';

        boffs += 4;
    }
    out[boffs++] = '\0';

    *outlen = boffs;
    return 1;
}
