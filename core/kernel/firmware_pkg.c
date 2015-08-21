/*
 * Copyright (c) 2015, Linaro Limited
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

#include <types_ext.h>
#include <kernel/firmware_pkg.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

struct fwp_state {
	const uint8_t *data;
	size_t len;
	struct firmware_pkg_info *fwp;
};

static const unsigned cms_version = 3;
static const uint32_t cms_id_signed_data[] = {
	1, 2, 840, 113549, 1, 7, 2};
static const uint32_t cms_id_ct_firmware_package[] = {
	1, 2, 840, 113549, 1, 9, 16, 1, 16};
static const uint32_t cms_id_sha256[] = {
	2, 16, 840, 1, 101, 3, 4, 2, 1};
static const uint32_t cms_id_sha256_with_rsa_encryption[] = {
	1, 2, 840, 113549, 1, 1, 11};
static const uint32_t cms_id_message_digest[] = {
	1, 2, 840, 113549, 1, 9, 4};

#define FW_TAG_INTEGER		0x02
#define FW_TAG_OCTET_STRING	0x04
#define FW_TAG_OID		0x06
#define FW_TAG_SEQUENCE		0x30
#define FW_TAG_SET		0x31

#define FW_TAG_CONTEXT_SPECIFIC	0x80
#define FW_TAG_CONSTRUCTED	0x20

static bool fwp_decode_tag(struct fwp_state *state, size_t offs, uint8_t *tag,
			size_t *next_offs)
{
	//const uint8_t class_mask = (1 << 7) | (1 << 6);
	const uint8_t constructed = 1 << 5;
	const uint8_t number_mask = constructed - 1;
	uint8_t t;

	if (offs >= state->len)
		return false;
	t = state->data[offs];

	if ((t & number_mask) > 30)
		return false;	/* Only supporting short tag form */

	*tag = t;
	*next_offs = offs + 1;
	return true;
}

static bool fwp_decode_len(struct fwp_state *state, size_t offs, size_t *len,
			size_t *next_offs)
{
	size_t o = offs;
	const uint8_t len_indefinite = 0x80;
	size_t l;
	size_t num_l_bytes;

	if (o >= state->len)
		return false;

	if (state->data[o] == len_indefinite)
		return false; /* Only supporting definite form */

	if (state->data[o] < len_indefinite) {
		/* Short form */
		l = state->data[o];
		o++;
		goto out;
	}
	/* Long form */
	num_l_bytes = state->data[o] & 0x7f;
	o++;
	if ((o + num_l_bytes) >= state->len)
		return false;
	if (num_l_bytes >= sizeof(l))
		return false;
	l = 0;
	while (num_l_bytes) {
		l = l << 8 | state->data[o];
		o++;
		num_l_bytes--;
	}

out:
	*len = l;
	*next_offs = o;
	return true;
}

static bool fwp_decode(struct fwp_state *state, size_t offs,
			uint8_t *tag, size_t *val_offs, size_t *val_len)
{
	size_t o;

	if (!fwp_decode_tag(state, offs, tag, &o))
		return false;

	if (!fwp_decode_len(state, o, val_len, val_offs))
		return false;

	if (*val_len >= state->len || (*val_offs + *val_len) > state->len)
		return false;

	return true;
}

static bool fwp_expect_tag(struct fwp_state *state, size_t offs,
			uint8_t tag, size_t *val_offs, size_t *val_len)
{
	uint8_t t;

	if (!fwp_decode(state, offs, &t, val_offs, val_len))
		return false;
	if (t != tag)
		return false;
	return true;
}

static bool fwp_expect_oid(struct fwp_state *state,
			size_t val_offs, size_t val_len,
			const uint32_t oid[], size_t oid_len)
{
	size_t o = val_offs;
	size_t oid_offs = 0;
	uint32_t w;

	if (oid_len < 2 || !val_len)
		return false; /* has to be at least two words */

	if (oid[0] != (state->data[o] / 40) || oid[1] != (state->data[o] % 40))
		return false;

	o++;
	oid_offs += 2;

	w = 0;
	while (o < (val_offs + val_len) && oid_offs < oid_len) {
		/*
		 * It doesn't matter if w overflows, if that would happen
		 * we'll never have a false positive any way.
		 */
		w = w << 7 | (state->data[o] & 0x7f);
		if (!(state->data[o] & 0x80)) {
			if (w != oid[oid_offs])
				return false;
			w = 0;
			oid_offs++;
		}
		o++;
	}
	if (o != (val_offs + val_len) || oid_offs != oid_len)
		return false;

	return true;
}

static bool fwp_expect_integer(struct fwp_state *state,
			size_t val_offs, size_t val_len, unsigned integer)
{
	/*
	 * We're only dealing with small integers coded in one octet so we
	 * can take some shortcuts when decoding the integer.
	 */
	if (val_len != 1)
		return false;
	if (state->data[val_offs] != integer)
		return false;
	return true;
}

static bool fwp_parse_encapsulated_content_info(struct fwp_state *state,
		size_t offs, size_t *next_offs)
{
	size_t val_len;
	size_t val_offs;
	size_t o;

	/* Beginning of EncapsulatedContentInfo */
	if (!fwp_expect_tag(state, offs, FW_TAG_SEQUENCE, &val_offs, &val_len))
		return false;
	*next_offs = val_offs + val_len;

	/* EncapsulatedContentInfo.eContentType */
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;
	if (!fwp_expect_oid(state, val_offs, val_len,
			    cms_id_ct_firmware_package,
			    ARRAY_SIZE(cms_id_ct_firmware_package)))
		return false;

	/* EncapsulatedContentInfo.eContent */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_OCTET_STRING, &val_offs, &val_len))
		return false;
	if (*next_offs != (val_offs + val_len))
		return false;
	state->fwp->content = state->data + val_offs;
	state->fwp->content_len = val_len;
	return true;
}

static bool fwp_locate_digest(struct fwp_state *state,
			size_t offs, size_t *digest_offs, size_t *digest_len,
			bool *found_it, size_t *next_offs)
{
	size_t o = offs;
	size_t val_offs;
	size_t val_len;

	if (!fwp_expect_tag(state, o, FW_TAG_SEQUENCE, &val_offs, &val_len))
		return false;
	*next_offs = val_offs + val_len;
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;
	if (!fwp_expect_oid(state, val_offs, val_len, cms_id_message_digest,
			    ARRAY_SIZE(cms_id_message_digest))) {
		*found_it = false;
		return true;
	}
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_SET, &val_offs, &val_len))
		return false;
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_OCTET_STRING, &val_offs, &val_len))
		return false;
	*found_it = true;
	*digest_offs = val_offs;
	*digest_len = val_len;
	return true;
}

static bool fwp_set_attrs(struct fwp_state *state, size_t offs, size_t len)
{
	struct fwp_state state2;
	uint8_t *p;
	size_t o;
	size_t val_offs;
	size_t val_len;

	p = malloc(len);
	if (!p)
		return false;
	memcpy(p, state->data + offs, len);
	p[0] = FW_TAG_SET;
	state->fwp->attrs = p;
	state->fwp->attrs_len = len;

	/*
	 * Now look for digest inside the signed attributes
	 */
	state2.data = p;
	state2.len = len;
	state2.fwp = state->fwp;
	if (!fwp_expect_tag(&state2, 0, FW_TAG_SET, &val_offs, &val_len))
		return false;

	o = val_offs;
	while (true) {
		size_t digest_offs = 0;
		size_t digest_len = 0;
		size_t next_offs;
		bool found_it;

		if (!fwp_locate_digest(&state2, o, &digest_offs, &digest_len,
				       &found_it, &next_offs))
			return false;
		if (found_it) {
			state->fwp->digest = p + digest_offs;
			state->fwp->digest_len = digest_len;
			break;
		}
		if (next_offs >= (val_offs + val_len))
			return false;
		o = next_offs;
	}

	return true;
}

static bool fwp_parse_signer_infos(struct fwp_state *state,
		size_t offs, size_t *next_offs)
{
	size_t val_len;
	size_t val_offs;
	size_t o;

	/* Beginning of SET OF SignerInfo (only one) */
	if (!fwp_expect_tag(state, offs, FW_TAG_SET, &val_offs, &val_len))
		return false;
	*next_offs = val_offs + val_len;

	/* Beginning of SignerInfo */
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_SEQUENCE, &val_offs, &val_len))
		return false;
	if (*next_offs != (val_offs + val_len))
		return false;

	/* SignerInfo.version */
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_INTEGER, &val_offs, &val_len))
		return false;
	if (!fwp_expect_integer(state, val_offs, val_len, cms_version))
		return false;

	/* SignerInfo.sid (ignore) */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;

	/* SignerInfo.digestAlgorithm */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;
	if (!fwp_expect_oid(state, val_offs, val_len, cms_id_sha256,
			    ARRAY_SIZE(cms_id_sha256)))
		return false;

	/* SignerInfo.signedAttrs */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o,
			    /* [0] IMPLICIT SignedAttributes */
			    FW_TAG_CONTEXT_SPECIFIC | FW_TAG_CONSTRUCTED,
			    &val_offs, &val_len))
		return false;
	if (!fwp_set_attrs(state, o, val_len + (val_offs - o)))
		return false;

	/* SignerInfo.signatureAlgorithm */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;
	if (!fwp_expect_oid(state, val_offs, val_len,
			    cms_id_sha256_with_rsa_encryption,
			    ARRAY_SIZE(cms_id_sha256_with_rsa_encryption)))
		return false;
	state->fwp->algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;

	/* SignerInfo.signature */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_OCTET_STRING, &val_offs, &val_len))
		return false;
	state->fwp->signature = state->data + val_offs;
	state->fwp->signature_len = val_len;

	/* SignerInfo.unsignedAttrs (ignored) */
	o = val_offs + val_len;
	if (o < *next_offs &&
	    !fwp_expect_tag(state, o, FW_TAG_SET, &val_offs, &val_len))
		return false;

	if (val_offs + val_len != *next_offs)
		return false;
	return true;

}

static bool fwp_parse_signed_data(struct fwp_state *state,
			size_t offs,
			size_t *next_offs)
{
	size_t val_len;
	size_t val_offs;
	size_t o;
	size_t next_o;

	/* Beginning of SignedData */
	if (!fwp_expect_tag(state, offs, FW_TAG_SEQUENCE, &val_offs, &val_len))
		return false;
	*next_offs = val_offs + val_len;

	/* SignedData.version */
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_INTEGER, &val_offs, &val_len))
		return false;
	if (!fwp_expect_integer(state, val_offs, val_len, cms_version))
		return false;

	/* SignedData.digestAlgorithms */
	o = val_offs + val_len;
	if (!fwp_expect_tag(state, o, FW_TAG_SET, &val_offs, &val_len))
		return false;
	next_o = val_offs + val_len;
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;
	if (next_o != (val_offs + val_len))
		return false;
	if (!fwp_expect_oid(state, val_offs, val_len, cms_id_sha256,
			    ARRAY_SIZE(cms_id_sha256)))
		return false;

	/* SignedData.encapContentInfo */
	o = next_o;
	if (!fwp_parse_encapsulated_content_info(state, o, &next_o))
		return false;

	/* SignedData.signerInfos */
	o = next_o;
	if (!fwp_parse_signer_infos(state, o, &next_o))
		return false;
	if (next_o != *next_offs)
		return false;
	return true;
}

static bool fwp_parse_content_info(struct fwp_state *state,
			size_t offs, size_t *next_offs)
{
	size_t val_len;
	size_t val_offs;
	size_t o;

	/* Beginning of ContentInfo */
	if (!fwp_expect_tag(state, offs, FW_TAG_SEQUENCE, &val_offs, &val_len))
		return false;

	/* ContentInfo.contentType == id-signedData */
	o = val_offs;
	if (!fwp_expect_tag(state, o, FW_TAG_OID, &val_offs, &val_len))
		return false;
	if (!fwp_expect_oid(state, val_offs, val_len, cms_id_signed_data,
			    ARRAY_SIZE(cms_id_signed_data)))
		return false;

	o = val_offs + val_len;
	return fwp_parse_signed_data(state, o, next_offs);
}

TEE_Result firmware_pkg_info_parse(const uint8_t *data, size_t len,
			struct firmware_pkg_info *fwp)
{
	struct fwp_state fwp_state = {data, len, fwp};
	size_t next_offs;

	fwp->attrs = NULL;
	if (!fwp_parse_content_info(&fwp_state, 0, &next_offs)) {
		firmware_pkg_info_free(fwp);
		return TEE_ERROR_SECURITY;
	}
	return TEE_SUCCESS;
}

void firmware_pkg_info_free(struct firmware_pkg_info *fwp)
{
	free((void *)fwp->attrs);
	fwp->attrs = NULL;
}
