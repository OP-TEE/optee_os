/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file rsa_make_key.c
  RSA key generation, Tom St Denis
*/

#ifdef LTC_MRSA

static int s_rsa_make_key(prng_state *prng, int wprng, int size, void *e, rsa_key *key)
{
   void *p, *q, *tmp1, *tmp2;
   int    err;

   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(size        > 0);

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, LTC_NULL)) != CRYPT_OK) {
      return err;
   }

   /* make primes p and q (optimization provided by Wayne Scott) */

   /* make prime "p" */
   do {
       if ((err = rand_prime( p, size/2, prng, wprng)) != CRYPT_OK)  { goto cleanup; }
       if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)               { goto cleanup; }  /* tmp1 = p-1 */
       if ((err = mp_gcd( tmp1,  e,  tmp2)) != CRYPT_OK)             { goto cleanup; }  /* tmp2 = gcd(p-1, e) */
   } while (mp_cmp_d( tmp2, 1) != 0);                                                  /* while e divides p-1 */

   /* make prime "q" */
   do {
       if ((err = rand_prime( q, size/2, prng, wprng)) != CRYPT_OK)  { goto cleanup; }
       if ((err = mp_sub_d( q, 1,  tmp1)) != CRYPT_OK)               { goto cleanup; } /* tmp1 = q-1 */
       if ((err = mp_gcd( tmp1,  e,  tmp2)) != CRYPT_OK)          { goto cleanup; } /* tmp2 = gcd(q-1, e) */
   } while (mp_cmp_d( tmp2, 1) != 0);                                                 /* while e divides q-1 */

   /* tmp1 = lcm(p-1, q-1) */
   if ((err = mp_sub_d( p, 1,  tmp2)) != CRYPT_OK)                   { goto cleanup; } /* tmp2 = p-1 */
                                                                                      /* tmp1 = q-1 (previous do/while loop) */
   if ((err = mp_lcm( tmp1,  tmp2,  tmp1)) != CRYPT_OK)              { goto cleanup; } /* tmp1 = lcm(p-1, q-1) */

   /* make key */
   if ((err = rsa_init(key)) != CRYPT_OK) {
      goto errkey;
   }

   if ((err = mp_copy( e,  key->e)) != CRYPT_OK)                       { goto errkey; } /* key->e =  e */
   if ((err = mp_invmod( key->e,  tmp1,  key->d)) != CRYPT_OK)         { goto errkey; } /* key->d = 1/e mod lcm(p-1,q-1) */
   if ((err = mp_mul( p,  q,  key->N)) != CRYPT_OK)                    { goto errkey; } /* key->N = pq */

   /* optimize for CRT now */
   /* find d mod q-1 and d mod p-1 */
   if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)                     { goto errkey; } /* tmp1 = p-1 */
   if ((err = mp_sub_d( q, 1,  tmp2)) != CRYPT_OK)                     { goto errkey; } /* tmp2 = q-1 */
   if ((err = mp_mod( key->d,  tmp1,  key->dP)) != CRYPT_OK)           { goto errkey; } /* dP = d mod p-1 */
   if ((err = mp_mod( key->d,  tmp2,  key->dQ)) != CRYPT_OK)           { goto errkey; } /* dQ = d mod q-1 */
   if ((err = mp_invmod( q,  p,  key->qP)) != CRYPT_OK)                { goto errkey; } /* qP = 1/q mod p */

   if ((err = mp_copy( p,  key->p)) != CRYPT_OK)                       { goto errkey; }
   if ((err = mp_copy( q,  key->q)) != CRYPT_OK)                       { goto errkey; }

   /* set key type (in this case it's CRT optimized) */
   key->type = PK_PRIVATE;

   /* return ok and free temps */
   err       = CRYPT_OK;
   goto cleanup;
errkey:
   rsa_free(key);
cleanup:
   mp_clear_multi(tmp2, tmp1, q, p, LTC_NULL);
   return err;
}

/**
   Create an RSA key based on a long public exponent type
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param size     The size of the modulus (key size) desired (octets)
   @param e        The "e" value (public key).  e==65537 is a good choice
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
{
   void *tmp_e;
   int err;

   if ((e < 3) || ((e & 1) == 0)) {
     return CRYPT_INVALID_ARG;
   }

   if ((err = mp_init(&tmp_e)) != CRYPT_OK) {
     return err;
   }

   if ((err = mp_set_int(tmp_e, e)) == CRYPT_OK)
     err = s_rsa_make_key(prng, wprng, size, tmp_e, key);

   mp_clear(tmp_e);

   return err;
}

/**
   Create an RSA key based on a hexadecimal public exponent type
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param size     The size of the modulus (key size) desired (octets)
   @param e        The "e" value (public key).  e==65537 is a good choice
   @param elen     The length of e (octets)
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
int rsa_make_key_ubin_e(prng_state *prng, int wprng, int size,
                        const unsigned char *e, unsigned long elen, rsa_key *key)
{
   int err;
   void *tmp_e;

   if ((err = mp_init(&tmp_e)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_read_unsigned_bin(tmp_e, (unsigned char *)e, elen)) == CRYPT_OK)
     err = rsa_make_key_bn_e(prng, wprng, size, tmp_e, key);

   mp_clear(tmp_e);

   return err;
}

/**
   Create an RSA key based on a bignumber public exponent type
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param size     The size of the modulus (key size) desired (octets)
   @param e        The "e" value (public key).  e==65537 is a good choice
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
int rsa_make_key_bn_e(prng_state *prng, int wprng, int size, void *e, rsa_key *key)
{
   int err;
   int e_bits;

   e_bits = mp_count_bits(e);
   if ((e_bits > 1 && e_bits < 256) && (mp_get_digit(e, 0) & 1)) {
     err = s_rsa_make_key(prng, wprng, size, e, key);
   } else {
     err = CRYPT_INVALID_ARG;
   }

   return err;
}

#endif
