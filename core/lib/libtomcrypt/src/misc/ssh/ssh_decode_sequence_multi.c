/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"
#include <stdarg.h>

/**
   @file ssh_decode_sequence_multi.c
   SSH data type representation as per RFC4251, Russ Williams
*/

#ifdef LTC_SSH

/**
  Decode a SSH sequence using a VA list
  @param in     The input buffer
  @param inlen  [in/out] The length of the input buffer and on output the amount of decoded data
  @remark <...> is of the form <type, data*> (int, <unsigned char*,ulong32*,ulong64*>) except for string&name-list <type, data, size*> (int, void*, unsigned long*)
  @return CRYPT_OK on success
*/
int ssh_decode_sequence_multi(const unsigned char *in, unsigned long *inlen, ...)
{
   int           err;
   va_list       args;
   ssh_data_type type;
   void          *vdata;
   unsigned char *cdata;
   char          *sdata;
   ulong32       *u32data;
   ulong64       *u64data;
   unsigned long *bufsize;
   ulong32       size;
   unsigned long remaining;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);

   remaining = *inlen;
   /* Decode values from buffer */
   va_start(args, inlen);
   while ((type = (ssh_data_type)va_arg(args, int)) != LTC_SSHDATA_EOL) {
      /* Size of length field */
      if (type == LTC_SSHDATA_STRING ||
          type == LTC_SSHDATA_NAMELIST ||
          type == LTC_SSHDATA_MPINT)
      {
         /* Check we'll not read too far */
         if (remaining < 4) {
            err = CRYPT_BUFFER_OVERFLOW;
            goto error;
         }
      }

      /* Calculate (or read) length of data */
      size = 0xFFFFFFFFU;
      switch (type) {
         case LTC_SSHDATA_BYTE:
         case LTC_SSHDATA_BOOLEAN:
            size = 1;
            break;
         case LTC_SSHDATA_UINT32:
            size = 4;
            break;
         case LTC_SSHDATA_UINT64:
            size = 8;
            break;
         case LTC_SSHDATA_STRING:
         case LTC_SSHDATA_NAMELIST:
         case LTC_SSHDATA_MPINT:
            LOAD32H(size, in);
            in += 4;
            remaining -= 4;
            break;

         case LTC_SSHDATA_EOL:
            /* Should never get here */
            err = CRYPT_INVALID_ARG;
            goto error;
      }

      /* Check we'll not read too far */
      if (remaining < size) {
         err = CRYPT_BUFFER_OVERFLOW;
         goto error;
      } else {
         remaining -= size;
      }

      vdata = va_arg(args, void*);
      if (vdata == NULL) {
         err = CRYPT_INVALID_ARG;
         goto error;
      }

      /* Read data */
      switch (type) {
         case LTC_SSHDATA_BYTE:
            cdata = vdata;
            *cdata = *in++;
            break;
         case LTC_SSHDATA_BOOLEAN:
            cdata = vdata;
            /*
               The value 0 represents FALSE, and the value 1 represents TRUE.  All non-zero values MUST be
               interpreted as TRUE; however, applications MUST NOT store values other than 0 and 1.
             */
            *cdata = (*in++)?1:0;
            break;
         case LTC_SSHDATA_UINT32:
            u32data = vdata;
            LOAD32H(*u32data, in);
            in += 4;
            break;
         case LTC_SSHDATA_UINT64:
            u64data = vdata;
            LOAD64H(*u64data, in);
            in += 8;
            break;
         case LTC_SSHDATA_STRING:
         case LTC_SSHDATA_NAMELIST:
            sdata = vdata;
            bufsize = va_arg(args, unsigned long*);
            if (bufsize == NULL) {
               err = CRYPT_INVALID_ARG;
               goto error;
            }
            if (size + 1 >= *bufsize) {
               err = CRYPT_BUFFER_OVERFLOW;
               goto error;
            }
            if (size > 0) {
               XMEMCPY(sdata, (const char *)in, size);
            }
            sdata[size] = '\0';
            *bufsize = size;
            in += size;
            break;
         case LTC_SSHDATA_MPINT:
            if (size == 0) {
               if ((err = mp_set(vdata, 0)) != CRYPT_OK)                                                { goto error; }
            } else if ((in[0] & 0x80) != 0) {
               /* Negative number - not supported */
               err = CRYPT_INVALID_PACKET;
               goto error;
            } else {
               if ((err = mp_read_unsigned_bin(vdata, (unsigned char *)in, size)) != CRYPT_OK)          { goto error; }
            }
            in += size;
            break;

         case LTC_SSHDATA_EOL:
            /* Should never get here */
            err = CRYPT_INVALID_ARG;
            goto error;
      }
   }
   err = CRYPT_OK;

   *inlen -= remaining;

error:
   va_end(args);
   return err;
}

#endif
