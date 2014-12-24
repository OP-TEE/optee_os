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
#include "tomcrypt.h"
#include <kernel/tee_common_unpg.h>
#include <trace.h>
#include <tee/tee_hkdf.h>


/*
 * HKDF
 */
/*
 *  tee_hkdf_extract
 *  Function:
 *      Perform extraction step.
 *      Before use this funciton, Hash function must be registered
 *
 *  Input Parameters:
 *      hash: 
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt[ ]: 
 *          Optional salt value ;
 *      salt_len: 
 *          The length of the salt. 
 *      ikm[ ]:
 *          Input keying material.
 *      ikm_len: 
 *          The length of the input keying material.
 * Output parameters:
 *      prk:
 *          Pointer point to where HKDF extraction result is stored.
 *      outlen:
 *         Size of area where extraction result be stored, must be equal with hash length! 
 *
 *  Returns:
 *      0: OK
 *      Others: Error Code.
 */
int tee_hkdf_extract(int hash,
    const unsigned char *ikm, int ikm_len,
    const unsigned char *salt, int salt_len,
    unsigned char *prk, unsigned long * outlen)
{     
    unsigned char NoneSalt[HKDF_MAX_HASH_SIZE];
    int         err = -1;

    /* make sure hash descriptor is valid */
    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    /* if not provided, it is set to a string of HashLen zeros */
    if( (NULL == salt) || ((unsigned char *)"" == salt)) {
        salt = NoneSalt;
        salt_len = hash_descriptor[hash].hashsize;
        memset(NoneSalt, '\0', salt_len);
    }

    return hmac_memory(hash, salt, salt_len, ikm, ikm_len, prk, outlen);

}

/*
 *  tee_hkdf_expand
 *
 *  Description:
 *      Perform HKDF expansion step.
 *
 *  Input Parameters:
 *      hash:
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      prk[ ]: 
 *          The pseudo-random key to be expanded
 *      prk_len: 
 *          The length of the pseudo-random key in prk;
 *          should at least be equal to USHAHashSize(hash).
 *      info: 
 *          The optional context and application specific information(optional)
 *      info_len:
 *          The length of the optional context and application specific(optional)
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(hash)
 *
 * Output Parameters:
 *      okm: 
 *          Where the HKDF is to be stored.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int tee_hkdf_expand(int hash, const unsigned char *prk, unsigned long prk_len,
    const unsigned char *pinfo, unsigned long info_len,
    unsigned char *okm, unsigned long okm_len)
{
    unsigned char T[HKDF_MAX_HASH_SIZE];
    hmac_state *hmac = NULL;
    unsigned long hash_len, N;
    unsigned int Tlen = 0;
    unsigned int where = 0;
    unsigned int i;
    int err = -1;
    unsigned long outlen = 0;

    /* make sure hash descriptor is valid */
    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (NULL == pinfo) {
        pinfo = (const unsigned char *)"";
        info_len = 0;
    } 
    
    if (NULL == okm) {
        return -1;
    }

    hash_len = hash_descriptor[hash].hashsize;
    outlen = hash_descriptor[hash].blocksize;

    if (prk_len < hash_len) {
        return -1;
    }
    /*N = ceil(L/HashLen)*/
    N = okm_len / hash_len;

    /**/
    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        return -1;
    }

    /* nope, so call the hmac functions */
    /* allocate ram for hmac state */
    hmac = XMALLOC(sizeof(hmac_state));
    if (hmac == NULL) {
       return CRYPT_MEM;
    }

    /*
       *  T = T(1) | T(2) | T(3) | ... | T(N)
       *  OKM = first L octets of T
       * T(0) = empty string (zero length)
       * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
       * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
       * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
       */
    for (i = 1; i <= N; i++) {
        unsigned char c = i;
        int ret = hmac_init(hmac, hash, prk, prk_len) ||
                  hmac_process(hmac, T, Tlen) ||
                  hmac_process(hmac, pinfo, info_len) ||
                  hmac_process(hmac, &c, 1) ||
                  hmac_done(hmac, T, &outlen);
        if (ret != CRYPT_OK) {
            XFREE(hmac);
            return ret;
        }
        memcpy(okm + where, T,
               (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        Tlen = hash_len;
    }
    
    XFREE(hmac);

    return CRYPT_OK;
}

/*
 *  hkdf
 *
 *  Description:
 *      This function will generate keying material using HKDF.
 *
 *  Input Parameters:
 *      hash:
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt: 
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(hash) zeros.
 *      salt_len: 
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm: 
 *          Input keying material.
 *      ikm_len: 
 *          The length of the input keying material.
 *      info: 
 *          The optional context and application specific information.
 *      info_len: 
 *          The length of the optional context and application specific information
 *      okm_len: 
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * BlockSize(hash)
 *  Output Parameters:
 *      okm: 
 *          Where the HKDF is to be stored.
 *
 *  Notes:
 *      Calls hkdfExtract() and hkdfExpand().
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int tee_hkdf(int hash,
    const unsigned char *salt, unsigned long salt_len,
    const unsigned char *ikm, unsigned long ikm_len,
    const unsigned char *info, unsigned long info_len,
    unsigned char *okm, unsigned long okm_len)
{
    unsigned char prk[HKDF_MAX_HASH_SIZE];
    unsigned long outlen = 0;
    int err = -1;

    /* make sure hash descriptor is valid */
    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }
    outlen = hash_descriptor[hash].blocksize;
    
    return tee_hkdf_extract(hash, ikm, ikm_len, salt, salt_len, prk, &outlen) ||
         tee_hkdf_expand(hash, prk, hash_descriptor[hash].hashsize, info,
                    info_len, okm, okm_len);
}


#if 1
/*Test arrays for HKDF*/
struct hkdf_hash_input{
    const char * hash_algo;
    unsigned long ikmlength;
    const char * ikm;
    unsigned long saltlength;
    const char * salt;
    unsigned long infolength;
    const char * info;
    unsigned long prklength;
    const char * prk;
    unsigned long okmlength;
    const char * okm;
} hkdf_input[7] = {
    {   /* RFC 5869 A.1. Test Case 1 */
        "sha256",
        22, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        13, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
        10, "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
        32, "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844A"
            "D7C2B3E5",
        42, "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56"
            "ECC4C5BF34007208D5B887185865"
    },
    {   /* RFC 5869 A.2. Test Case 2 */
        "sha256",
        80, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
            "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
            "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
            "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
            "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
            "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
        80, "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d"
            "\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b"
            "\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
            "\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97"
            "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5"
            "\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf",
        80, "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd"
            "\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb"
            "\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
            "\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"
            "\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5"
            "\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        32, "06A6B88C5853361A06104C9CEB35B45C"
            "EF760014904671014A193F40C15FC244",
        82, "B11E398DC80327A1C8E7F78C596A4934"
            "4F012EDA2D4EFAD8A050CC4C19AFA97C"
            "59045A99CAC7827271CB41C65E590E09"
            "DA3275600C2F09B8367793A9ACA3DB71"
            "CC30C58179EC3E87C14C01D5C1F3434F"
            "1D87"
    },
    {   /* RFC 5869 A.3. Test Case 3 */
        "sha256",
        22, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        0, "",
        0, "",
        32, "19EF24A32C717B167F33A91D6F648BDF"
            "96596776AFDB6377AC434C1C293CCB04",
        42, "8DA4E775A563C18F715F802A063C5A31"
            "B8A11F5C5EE1879EC3454E5F3C738D2D"
            "9D201395FAA4B61A96C8"
    },
    {   /* RFC 5869 A.4. Test Case 4 */
        "sha1",
        11, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        13, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
        10, "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
        20, "9B6C18C432A7BF8F0E71C8EB88F4B30BAA2BA243",
        42, "085A01EA1B10F36933068B56EFA5AD81"
            "A4F14B822F5B091568A9CDD4F155FDA2"
            "C22E422478D305F3F896"
    },
    {   /* RFC 5869 A.5. Test Case 5 */
        "sha1",
        80, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
            "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
            "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
            "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
            "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
            "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
        80, "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D"
            "\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B"
            "\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
            "\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97"
            "\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5"
            "\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF",
        80, "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD"
            "\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB"
            "\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9"
            "\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7"
            "\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5"
            "\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
        20, "8ADAE09A2A307059478D309B26C4115A224CFAF6",
        82, "0BD770A74D1160F7C9F12CD5912A06EB"
            "FF6ADCAE899D92191FE4305673BA2FFE"
            "8FA3F1A4E5AD79F3F334B3B202B2173C"
            "486EA37CE3D397ED034C7F9DFEB15C5E"
            "927336D0441F4C4300E2CFF0D0900B52"
            "D3B4"
    },
    {   /* RFC 5869 A.6. Test Case 6 */
        "sha1",
        22, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        0, "",
        0, "",
        20, "DA8C8A73C7FA77288EC6F5E7C297786AA0D32D01",
        42, "0AC1AF7002B3D761D1E55298DA9D0506"
            "B9AE52057220A306E07B6B87E8DF21D0"
            "EA00033DE03984D34918"
    },
    {   /* RFC 5869 A.7. Test Case 7. */
        "sha1",
        22, "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
            "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
        0, 0,
        0, "",
        20, "2ADCCADA18779E7C2077AD2EB19D3F3E731385DD",
        42, "2C91117204D745F3500D636A62F64F0A"
            "B3BAE548AA53D423B0D1F27EBBA6F5E5"
            "673A081D70CCE7ACFC48"
    }
};

#define PRINTNONE 0
#define PRINTTEXT 1
#define PRINTRAW 2
#define PRINTHEX 3
#define PRINTBASE64 4

#define PRINTPASSFAIL 1
#define PRINTFAIL 2

/*
 * Check the hash value against the expected string, expressed in hex
 */
static const char hexdigits[ ] = "0123456789ABCDEF";
int checkmatch(const unsigned char *hashvalue,
                const char *hexstr, int hashsize)
{
    int i;

    for (i = 0; i < hashsize; ++i) {
        if (*hexstr++ != hexdigits[(hashvalue[i] >> 4) & 0xF])
            return 0;
        if (*hexstr++ != hexdigits[hashvalue[i] & 0xF]) 
	    return 0;
    }

    return 1;
}

/*
 * Print the string, converting all characters to hex "## ".
 */
void printxstr(const char *str, int len)
{
    for ( ; len-- > 0; str++) {
        IMSG("%c%c", hexdigits[(*str >> 4) & 0xF],
          hexdigits[*str & 0xF]);
    }
    return ;
}

void printResult(uint8_t *Message_Digest, int hashsize,
    const char *hashname, const char *testtype, const char *testname,
    const char *resultarray, int printResults, int printPassFail)
{
    /*int i, k;*/
    (void)printResults;
    (void)hashname;
    (void)testtype;
    (void)testname;
    
    if (printPassFail && resultarray) {
        int ret = checkmatch(Message_Digest, resultarray, hashsize);
        if ((printPassFail == PRINTPASSFAIL) || !ret){
            if (ret)
                IMSG("HKDF PASSED\n");
            else
                IMSG("HKDF FAILED\n");
        }
    }
}

int hkdf_test(int testno, int printResults, int printPassFail)
{
    int err = -1;
    unsigned char prk[HKDF_MAX_HASH_SIZE + 1];
    uint8_t okm[255 * HKDF_MAX_HASH_SIZE+1];
    unsigned long outlen = 0;
    int hash = -1;

    hash = find_hash(hkdf_input[testno].hash_algo);
    if (hash == -1)
	IMSG("\nCan't find hash algrithum %s",hkdf_input[testno].hash_algo);

    if (printResults == PRINTTEXT) {
        IMSG("\nTest %d \n\tSALT\t'", testno+1);
        printxstr(hkdf_input[testno].salt,
            hkdf_input[testno].saltlength);
        IMSG("'\n\tIKM\t'");
        printxstr(hkdf_input[testno].ikm,
            hkdf_input[testno].ikmlength);
        IMSG("'\n\tINFO\t'");
        printxstr(hkdf_input[testno].info,
            hkdf_input[testno].infolength);
        IMSG("'\n");
        IMSG("L=%d bytes\n", (int)hkdf_input[testno].okmlength);
    }

    err = tee_hkdf( hash, 
        (const unsigned char *)hkdf_input[testno].salt,
        hkdf_input[testno].saltlength,
        (const unsigned char *)hkdf_input[testno].ikm,
        hkdf_input[testno].ikmlength,
        (const unsigned char *)hkdf_input[testno].info,
        hkdf_input[testno].infolength,
        okm,
        hkdf_input[testno].okmlength);
    if (err != 0){
        IMSG("tee_hkdf(): hkdf error %d \n", err);
        return err;
    }

    printResult(okm, hkdf_input[testno].okmlength,
        hash_descriptor[hash].name, "hkdf standard test",
        "hkdf", hkdf_input[testno].okm, printResults, printPassFail);

    outlen = hash_descriptor[hash].blocksize;

    err = tee_hkdf_extract(hash,
        (const unsigned char *)hkdf_input[testno].ikm,
        hkdf_input[testno].ikmlength,
        (const unsigned char *)hkdf_input[testno].salt,
        hkdf_input[testno].saltlength,
        prk, &outlen );
    if (err != 0){
        IMSG("tee_hkdf_extract(): hkdf extract error %d \n", err);
        return err;
    }

    printResult(prk, hash_descriptor[hash].hashsize,
        hash_descriptor[hash].name, "hkdf standard test",
        "tee_hkdf_extract", hkdf_input[testno].prk, printResults, printPassFail);
    err = tee_hkdf_expand(hash, prk,
                    hash_descriptor[hash].hashsize,
                    (const unsigned char *)hkdf_input[testno].info,
                    hkdf_input[testno].infolength, okm, 
                    hkdf_input[testno].okmlength);
    if (err != 0){
        IMSG("tee_hkdf_expand(): hkdf expand error %d \n", err);
        return err;
    }
    printResult(okm, hash_descriptor[hash].hashsize,
        hash_descriptor[hash].name, "hkdf standard test",
        "tee_hkdf_expand", hkdf_input[testno].okm, printResults, printPassFail);

    return err;
}

int hkdf_test_entry(int testno)
{
    return hkdf_test(testno, 1,1);
}

#endif
