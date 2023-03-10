/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/*
 * Copyright (c) 2023, Linaro Limited
 */

/* based on https://github.com/brainhub/SHA3IUF (public domain) */

#include <crypto/crypto_accel.h>
#include <io.h>
#include <tomcrypt_private.h>

#ifdef LTC_SHA3

const struct ltc_hash_descriptor sha3_224_desc =
{
   "sha3-224",                  /* name of hash */
   17,                          /* internal ID */
   28,                          /* Size of digest in octets */
   144,                         /* Input block size in octets */
   { 2,16,840,1,101,3,4,2,7 },  /* ASN.1 OID */
   9,                           /* Length OID */
   &sha3_224_init,
   &sha3_process,
   &sha3_done,
   &sha3_224_test,
   NULL
};

const struct ltc_hash_descriptor sha3_256_desc =
{
   "sha3-256",                  /* name of hash */
   18,                          /* internal ID */
   32,                          /* Size of digest in octets */
   136,                         /* Input block size in octets */
   { 2,16,840,1,101,3,4,2,8 },  /* ASN.1 OID */
   9,                           /* Length OID */
   &sha3_256_init,
   &sha3_process,
   &sha3_done,
   &sha3_256_test,
   NULL
};

const struct ltc_hash_descriptor sha3_384_desc =
{
   "sha3-384",                  /* name of hash */
   19,                          /* internal ID */
   48,                          /* Size of digest in octets */
   104,                         /* Input block size in octets */
   { 2,16,840,1,101,3,4,2,9 },  /* ASN.1 OID */
   9,                           /* Length OID */
   &sha3_384_init,
   &sha3_process,
   &sha3_done,
   &sha3_384_test,
   NULL
};

const struct ltc_hash_descriptor sha3_512_desc =
{
   "sha3-512",                  /* name of hash */
   20,                          /* internal ID */
   64,                          /* Size of digest in octets */
   72,                          /* Input block size in octets */
   { 2,16,840,1,101,3,4,2,10 }, /* ASN.1 OID */
   9,                           /* Length OID */
   &sha3_512_init,
   &sha3_process,
   &sha3_done,
   &sha3_512_test,
   NULL
};

/* Public Inteface */

int sha3_224_init(hash_state *md)
{
   LTC_ARGCHK(md != NULL);
   XMEMSET(&md->sha3, 0, sizeof(md->sha3));
   md->sha3.capacity_words = 2 * 224 / (8 * sizeof(ulong64));
   return CRYPT_OK;
}

int sha3_256_init(hash_state *md)
{
   LTC_ARGCHK(md != NULL);
   XMEMSET(&md->sha3, 0, sizeof(md->sha3));
   md->sha3.capacity_words = 2 * 256 / (8 * sizeof(ulong64));
   return CRYPT_OK;
}

int sha3_384_init(hash_state *md)
{
   LTC_ARGCHK(md != NULL);
   XMEMSET(&md->sha3, 0, sizeof(md->sha3));
   md->sha3.capacity_words = 2 * 384 / (8 * sizeof(ulong64));
   return CRYPT_OK;
}

int sha3_512_init(hash_state *md)
{
   LTC_ARGCHK(md != NULL);
   XMEMSET(&md->sha3, 0, sizeof(md->sha3));
   md->sha3.capacity_words = 2 * 512 / (8 * sizeof(ulong64));
   return CRYPT_OK;
}

int sha3_shake_init(hash_state *md, int num)
{
   LTC_ARGCHK(md != NULL);
   if (num != 128 && num != 256) return CRYPT_INVALID_ARG;
   XMEMSET(&md->sha3, 0, sizeof(md->sha3));
   md->sha3.capacity_words = (unsigned short)(2 * num / (8 * sizeof(ulong64)));
   return CRYPT_OK;
}

int sha3_process(hash_state *md, const unsigned char *in, unsigned long inlen)
{
	unsigned int digest_size = 0;
	unsigned int block_count = 0;
	unsigned int block_size = 0;
	void *state = NULL;
	unsigned int l = 0;

	if (!inlen)
		return CRYPT_OK;
	LTC_ARGCHK(md);
	LTC_ARGCHK(in);

	block_size = 200 - md->sha3.capacity_words * 8;
	digest_size = md->sha3.capacity_words * 8 / 2;
	state = md->sha3.s;

	if (md->sha3.byte_index) {
		l = MIN(block_size - md->sha3.byte_index, inlen);
		memcpy(md->sha3.sb + md->sha3.byte_index, in, l);
		in += l;
		inlen -= l;
		md->sha3.byte_index += l;
		if (md->sha3.byte_index == block_size) {
			crypto_accel_sha3_compress(state, md->sha3.sb, 1,
						   digest_size);
			md->sha3.byte_index = 0;
		}

		if (!inlen)
			return CRYPT_OK;
	}

	if (inlen > block_size) {
		block_count = inlen / block_size;
		crypto_accel_sha3_compress(state, in, block_count,
					   digest_size);
		in += block_count * block_size;
		inlen -= block_count * block_size;
	}

	memcpy(md->sha3.sb + md->sha3.byte_index, in, inlen);
	md->sha3.byte_index += inlen;

	return CRYPT_OK;
}

static void copy_out_digest(ulong64 *s, unsigned int digest_size,
			    unsigned char *out)
{
	unsigned int n = 0;

	for (n = 0; n < digest_size / sizeof(uint64_t); n++) {
		put_unaligned_le64(out, s[n]);
		out += sizeof(uint64_t);
	}

	if (digest_size % sizeof(uint64_t))
		put_unaligned_le32(out, s[n]);
}

int sha3_done(hash_state *md, unsigned char *out)
{
	unsigned int digest_size = 0;
	unsigned int block_size = 0;
	void *state = NULL;
	uint8_t *buf = NULL;

	LTC_ARGCHK(md   != NULL);
	LTC_ARGCHK(out != NULL);

	block_size = 200 - md->sha3.capacity_words * 8;
	digest_size = md->sha3.capacity_words * 8 / 2;
	state = md->sha3.s;
	buf = md->sha3.sb;

	buf[md->sha3.byte_index++] = 0x06;
	memset(buf + md->sha3.byte_index, 0, block_size - md->sha3.byte_index);
	buf[block_size - 1] |= 0x80;
	crypto_accel_sha3_compress(state, buf, 1, digest_size);

	copy_out_digest(state, digest_size, out);

	return CRYPT_OK;
}


int sha3_shake_done(hash_state *md, unsigned char *out, unsigned long outlen)
{
	unsigned int digest_size = 0;
	unsigned int block_size = 0;
	void *state = NULL;
	uint8_t *buf = NULL;
	unsigned int n = 0;

	LTC_ARGCHK(md   != NULL);
	LTC_ARGCHK(out != NULL);

	block_size = 200 - md->sha3.capacity_words * 8;
	digest_size = md->sha3.capacity_words * 8 / 2;
	state = md->sha3.s;
	buf = md->sha3.sb;

	if (!md->sha3.xof_flag) {
		buf[md->sha3.byte_index++] = 0x1f;
		memset(buf + md->sha3.byte_index, 0,
		       block_size - md->sha3.byte_index);
		buf[block_size - 1] |= 0x80;
		crypto_accel_sha3_compress(state, buf, 1, digest_size);
		md->sha3.byte_index = 0;
		copy_out_digest(state, block_size, buf);
		md->sha3.xof_flag = 1;
	}

	for (n = 0; n < outlen; n++) {
		if (md->sha3.byte_index >= block_size) {
			memset(buf, 0, block_size);
			crypto_accel_sha3_compress(state, buf, 1, digest_size);
			md->sha3.byte_index = 0;
			copy_out_digest(state, block_size, buf);
		}
		out[n] = buf[md->sha3.byte_index];
		md->sha3.byte_index++;
	}

	return CRYPT_OK;
}
#endif
