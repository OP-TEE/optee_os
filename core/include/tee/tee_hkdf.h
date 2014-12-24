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
#ifndef TEE_HKDF_H
#define TEE_HKDF_H

/* When sha512 been selected */
#define HKDF_MAX_HASH_SIZE   0x40

int tee_hkdf_extract(int hash,
    const unsigned char *ikm, int ikm_len,
    const unsigned char *salt, int salt_len,
    unsigned char *prk, unsigned long * outlen);

int tee_hkdf_expand(int hash, const unsigned char *prk, unsigned long prk_len,
    const unsigned char *pinfo, unsigned long info_len,
    unsigned char *okm, unsigned long okm_len);

int tee_hkdf(int hash,
    const unsigned char *salt, unsigned long salt_len,
    const unsigned char *ikm, unsigned long ikm_len,
    const unsigned char *info, unsigned long info_len,
    unsigned char *okm, unsigned long okm_len);

int checkmatch(const unsigned char *hashvalue,
                const char *hexstr, int hashsize);

void printxstr(const char *str, int len);

void printResult(uint8_t *Message_Digest, int hashsize,
    const char *hashname, const char *testtype, const char *testname,
    const char *resultarray, int printResults, int printPassFail);

int hkdf_test(int testno, int printResults, int printPassFail);

int hkdf_test_entry(int testno);
#endif /* TEE_HKDF_H */
