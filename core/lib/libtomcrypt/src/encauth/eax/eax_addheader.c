/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
    @file eax_addheader.c
    EAX implementation, add meta-data, by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_EAX_MODE

/**
    add header (metadata) to the stream
    @param eax    The current EAX state
    @param header The header (meta-data) data you wish to add to the state
    @param length The length of the header data
    @return CRYPT_OK if successful
*/
int eax_addheader(eax_state *eax, const unsigned char *header,
                  unsigned long length)
{
   LTC_ARGCHK(eax    != NULL);
   LTC_ARGCHK(header != NULL);
   return omac_process(&eax->headeromac, header, length);
}

#endif
