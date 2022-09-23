/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_PADDING

/**
   Determine the to-be-padded length.

   @param length     [in/out] The size of the data before/after padding
   @param mode       Mask of (LTC_PAD_xxx | block_length)
   @return CRYPT_OK on success
*/
static int s_padding_padded_length(unsigned long *length, unsigned long mode)
{
   enum padding_type padding;
   unsigned char pad, block_length, r, t;

   LTC_ARGCHK(length != NULL);

   block_length = mode & 0xff;
   padding = mode & LTC_PAD_MASK;
   r = *length % block_length;

   switch (padding) {
      case LTC_PAD_ZERO:
         if (r == 0) {
            t = 0;
            break;
         }
         /* FALLTHROUGH */
      case LTC_PAD_PKCS7:
      case LTC_PAD_ONE_AND_ZERO:
      case LTC_PAD_ZERO_ALWAYS:
      case LTC_PAD_SSH:
         t = 1;
         break;
#ifdef LTC_RNG_GET_BYTES
      case LTC_PAD_ISO_10126:
         do {
            if (rng_get_bytes(&t, sizeof(t), NULL) != sizeof(t)) {
               return CRYPT_ERROR_READPRNG;
            }
            t %= (256 / block_length);
         } while (t == 0);
         break;
#endif
      case LTC_PAD_ANSI_X923:
         if (block_length != 16) {
            return CRYPT_INVALID_ARG;
         }
         t = 1;
         break;
      default:
         return CRYPT_INVALID_ARG;
   }

   pad = (t * block_length) - r;

   if ((pad == 0) && (padding != LTC_PAD_ZERO)) {
      pad = block_length;
   }

   *length += pad;

   return CRYPT_OK;
}

/**
   Add padding to data.

      This pads your data.

   @param data          The data to depad
   @param length        The size of the data before padding
   @param padded_length [in/out] The size of the data available/after padding
   @param mode          One of the LTC_PAD_xx flags
   @return CRYPT_OK on success
*/
int padding_pad(unsigned char *data, unsigned long length, unsigned long* padded_length, unsigned long mode)
{
   unsigned long l, n;
   enum padding_type type;
   int err;
   unsigned char diff, pad;

   LTC_ARGCHK(data          != NULL);
   LTC_ARGCHK(padded_length != NULL);

   l = length;
   if ((err = s_padding_padded_length(&l, mode)) != CRYPT_OK) {
      return err;
   }

   type = mode & LTC_PAD_MASK;

   if (*padded_length < l) {
#ifdef LTC_RNG_GET_BYTES
      if (type != LTC_PAD_ISO_10126) {
         *padded_length = l;
      } else {
         *padded_length = length + 256;
      }
#else
      *padded_length = l;
#endif
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (l - length > 255) return CRYPT_INVALID_ARG;
   diff = (unsigned char)(l - length);

   switch (type) {
      case LTC_PAD_PKCS7:
         XMEMSET(&data[length], diff, diff);
         break;
#ifdef LTC_RNG_GET_BYTES
      case LTC_PAD_ISO_10126:
         if (rng_get_bytes(&data[length], diff-1u, NULL) != diff-1u) {
            return CRYPT_ERROR_READPRNG;
         }
         data[l-1] =  diff;
         break;
#endif
      case LTC_PAD_ANSI_X923:
         XMEMSET(&data[length], 0, diff-1);
         data[l-1] =  diff;
         break;
      case LTC_PAD_SSH:
         pad = 0x1;
         for (n = length; n < l; ++n) {
            data[n] = pad++;
         }
         break;
      case LTC_PAD_ONE_AND_ZERO:
         XMEMSET(&data[length + 1], 0, diff);
         data[length] =  0x80;
         break;
      case LTC_PAD_ZERO:
      case LTC_PAD_ZERO_ALWAYS:
         XMEMSET(&data[length], 0, diff);
         break;
      default:
         return CRYPT_INVALID_ARG;
   }
   *padded_length = l;

   return CRYPT_OK;
}

#endif
