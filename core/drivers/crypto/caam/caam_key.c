// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 NXP
 */
#include <assert.h>
#include <caam_desc_helper.h>
#include <caam_key.h>
#include <caam_status.h>
#include <caam_trace.h>
#include <caam_utils_mem.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <tee/cache.h>
#include <tee_api_defines.h>
#include <trace.h>
#include <utee_types.h>

/*
 * CAAM Key magic number.
 * When the first 32 bits of a key buffer are equal to this value, the buffer
 * is a serialized CAAM key structure.
 */
#define MAGIC_NUMBER 0xCAAFBFFB

/*
 * Because the CAAM driver relies on this magic number to determine if the key
 * is plain text or black, collision can happen. A randomly generated plain text
 * key could feature the magic number. That's unlikely but still possible.
 *
 * Regarding the possibility of collision or forging attack, there are no
 * security concerns. Forging and trying to make a plain text key look like a
 * black key, won't do much. If the key is forged to look like an ECB Black
 * key, the singing operation will output a corrupted result. If the key is
 * forged to look like a CCM Black key, the import key will fail (because the
 * MAC verification) and no signing operation will be done.
 */

#define BLOB_BKEK_SIZE	     32 /* Blob key encryption key size */
#define BLOB_MAC_SIZE	     16 /* Blob MAC size */
#define BLOB_PAD_SIZE	     (BLOB_BKEK_SIZE + BLOB_MAC_SIZE)

/*
 * CAAM Blob key modifier
 * Key modifier used to derive Blob-key encryption key (BKEK) from the CAAM
 * master key.
 *
 * A CAAM black key is encrypted using a volatile Job Descriptor key encryption
 * key or JDKEK. Black keys are not intended for storage of keys across SoC
 * power cycles. The JDKEK is re-generated upon every power cycle (reset,
 * suspend/resume ...) or CAAM RNG re-seed.
 *
 * To retain key across power cycles, the black key must be encapsulated as a
 * blob. The blob key encryption key is derived from the CAAM master key which
 * makes it non-volatile and can be re-created when the chip powers up again.
 */
#define KEY_BLOB_MODIFIER_SIZE 16
static const uint8_t key_blob_modifier[KEY_BLOB_MODIFIER_SIZE] =
	"NXP_OPTEE_BLOB";

/*
 * Serialized CAAM key structure format.
 *
 * If the incoming key buffer is the following:
 *	| Magic number | key type | key size | key blob buffer |
 * The CAAM Key structure will be populated as following:
 * struct caamkey {
 *	.key_type = key type,
 *	.key_size = key size,
 *	.is_blob = true,
 *	.buf = key blob buffer
 * }
 *
 * If the incoming key buffer is the following:
 *	| Key buffer |
 * The CAAM Key structure will be populated as following:
 * struct caamkey {
 *	.key_type = CAAM_KEY_PLAIN_TEXT,
 *	.key_size = sizeof(Key buffer),
 *	.is_blob = false,
 *	.buf = key buffer
 * }
 */
struct caam_key_serialized {
	uint32_t magic_number; /* Magic number */
	uint32_t key_type; /* Black key type */
	uint32_t sec_size; /* The original plain text key size */
	uint8_t key[];
};

/*
 * CAAM key type enumeration to string
 */
static const char *const caam_key_type_to_str[] __maybe_unused = {
	[CAAM_KEY_PLAIN_TEXT] = "Plain Text",
	[CAAM_KEY_BLACK_ECB] = "Black ECB",
	[CAAM_KEY_BLACK_CCM] = "Black CCM",
};

static struct caam_key_serialized *data_to_serialized_key(const uint8_t *data,
							  size_t size)
{
	assert(data && size);
	assert(size > sizeof(struct caam_key_serialized));

	/*
	 * It's important to make sure uint8_t and caam_key_serialized{} are
	 * actually aligned for performance purpose.
	 *
	 * A __packed attribute to caam_key_serialized{} could solve the
	 * alignment issue but at the cost of un-optimize memory access.
	 * To avoid using the __packed attribute, caam_key_serialized{} is
	 * defined to be aligned on uint8_t. The following assert checks
	 * for this alignment.
	 */
	assert(IS_ALIGNED_WITH_TYPE(data, struct caam_key_serialized));

	/*
	 * The cast to void* instead of struct caam_key_serialized* is needed
	 * to avoid the cast alignment compilation warning.
	 */
	return (void *)data;
}

/*
 * Return the CAAM key type of the given key buffer
 *
 * @data	Input buffer
 * @size	Input buffer size
 */
static enum caam_key_type get_key_type(const uint8_t *data, size_t size)
{
	struct caam_key_serialized *key = data_to_serialized_key(data, size);

	if (key->magic_number != MAGIC_NUMBER)
		return CAAM_KEY_PLAIN_TEXT;

	return key->key_type;
}

/*
 * Return the CAAM key size of the given key buffer
 *
 * @data	Input buffer
 * @size	Input buffer size
 */
static size_t get_key_sec_size(const uint8_t *data, size_t size)
{
	struct caam_key_serialized *key = data_to_serialized_key(data, size);

	if (key->magic_number != MAGIC_NUMBER)
		return size;

	return key->sec_size;
}

/*
 * Return the CAAM key buffer pointer of the given key buffer
 *
 * @data	Input buffer
 * @size	Input buffer size
 */
static unsigned long get_key_buf_offset(const uint8_t *data, size_t size)
{
	struct caam_key_serialized *key = data_to_serialized_key(data, size);

	if (key->magic_number != MAGIC_NUMBER)
		return 0;
	else
		return offsetof(struct caam_key_serialized, key);
}

/*
 * Return the CAAM key buffer size of the given key buffer
 *
 * @data	Input buffer
 * @size	Input buffer size
 */
static size_t get_key_buf_size(const uint8_t *data, size_t size)
{
	struct caam_key_serialized *key = data_to_serialized_key(data, size);

	/*
	 * In the caam_key_serialized{}, the last element of the structure is
	 * a variable-sized buffer.
	 */
	return size - sizeof(*key);
}

size_t caam_key_get_alloc_size(const struct caamkey *key)
{
	if (!key)
		return 0;

	/* A blob size is independent from the key encryption algorithm */
	if (key->is_blob)
		return key->sec_size + BLOB_PAD_SIZE;

	switch (key->key_type) {
	case CAAM_KEY_PLAIN_TEXT:
		/*
		 * If the key is plain text, the allocation size is equal to the
		 * key size and no blob operation on this key is possible.
		 */
		return key->sec_size;
	case CAAM_KEY_BLACK_ECB:
		/* ECB-black key must be a multiple of 16 bytes */
		return ROUNDUP(key->sec_size, 16);
	case CAAM_KEY_BLACK_CCM:
		/*
		 * CCM-black key must be a multiple of 8 bytes. The nonce and
		 * ICV add another 12 bytes to the allocation size
		 */
		return ROUNDUP(key->sec_size, 8) + BLACK_KEY_NONCE_SIZE +
		       BLACK_KEY_ICV_SIZE;
	default:
		return 0;
	}
}

void caam_key_dump(const char *trace, const struct caamkey *key)
{
	if (!key || !trace)
		return;

	if (key->key_type >= CAAM_KEY_MAX_VALUE)
		return;

	KEY_TRACE("%s key_type:%s key_size:%zu is_blob:%s addr:%p",
		  caam_key_type_to_str[key->key_type], trace, key->sec_size,
		  key->is_blob ? "yes" : "no", key->buf.data);

	if (key->buf.data)
		KEY_DUMPBUF("Key data", key->buf.data, key->buf.length);
}

enum caam_status caam_key_alloc(struct caamkey *key)
{
	size_t alloc_size = 0;

	if (!key)
		return CAAM_BAD_PARAM;

	if (key->buf.data) {
		KEY_TRACE("Key already allocated");
		return CAAM_BAD_PARAM;
	}

	alloc_size = caam_key_get_alloc_size(key);
	if (!alloc_size)
		return CAAM_FAILURE;

	return caam_calloc_align_buf(&key->buf, alloc_size);
}

void caam_key_free(struct caamkey *key)
{
	if (!key)
		return;

	caam_free_buf(&key->buf);
}

void caam_key_cache_op(enum utee_cache_operation op, const struct caamkey *key)
{
	if (!key)
		return;

	if (!key->buf.nocache)
		cache_operation(op, key->buf.data, key->buf.length);
}

#define BLOB_OP_DESC_ENTRIES 12
enum caam_status caam_key_operation_blob(const struct caamkey *in_key,
					 struct caamkey *out_key)
{
	enum caam_status status = CAAM_FAILURE;
	struct caam_jobctx jobctx = { };
	uint32_t opflag = PROT_BLOB_TYPE(BLACK_KEY);
	uint32_t *desc = NULL;
	size_t output_buffer_size = 0;
	size_t input_buffer_size = 0;

	assert(in_key && out_key);

	KEY_TRACE("Blob %scapsulation of the following key",
		  in_key->is_blob ? "de" : "en");

	caam_key_dump("Blob input key", in_key);

	/* This function blobs or un-blobs */
	if (in_key->is_blob == out_key->is_blob) {
		KEY_TRACE("Only one key must be defined as a blob");
		return CAAM_BAD_PARAM;
	}

	/* A black blob cannot take a plain test key as input */
	if (out_key->key_type == CAAM_KEY_PLAIN_TEXT ||
	    in_key->key_type == CAAM_KEY_PLAIN_TEXT) {
		KEY_TRACE("A blob in/out operation cannot be plain text");
		return CAAM_BAD_PARAM;
	}

	/* The key type must remain the same */
	if (out_key->key_type != in_key->key_type) {
		KEY_TRACE("The in/out keys must have the same key type");
		return CAAM_BAD_PARAM;
	}

	/* Define blob operation direction */
	if (out_key->is_blob)
		opflag |= BLOB_ENCAPS;
	else
		opflag |= BLOB_DECAPS;

	/* Build OP flags depending on the blob type */
	switch (out_key->key_type) {
	case CAAM_KEY_BLACK_ECB:
		opflag |= PROT_BLOB_INFO(ECB);
		break;
	case CAAM_KEY_BLACK_CCM:
		opflag |= PROT_BLOB_INFO(CCM);
		break;
	default:
		return CAAM_BAD_PARAM;
	}

	/* Allocate the descriptor */
	desc = caam_calloc_desc(BLOB_OP_DESC_ENTRIES);
	if (!desc) {
		KEY_TRACE("CAAM Context Descriptor Allocation error");
		return CAAM_OUT_MEMORY;
	}

	status = caam_key_alloc(out_key);
	if (status) {
		KEY_TRACE("Key output allocation error");
		goto err;
	}

	/* Define input and output buffer size */
	if (out_key->is_blob) {
		/*
		 * For a blob operation, the input key size is the original key
		 * size of the black key.
		 * The output key size is the final blob size.
		 */
		input_buffer_size = in_key->sec_size;
		output_buffer_size = out_key->buf.length;
	} else {
		/*
		 * For an non-blob operation, the input key size is the original
		 * key size of the black key.
		 * The output key size is the key security size.
		 */
		input_buffer_size = in_key->buf.length;
		output_buffer_size = out_key->sec_size;
	}

	/* Create the blob encapsulation/decapsulation descriptor */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Load the key modifier */
	caam_desc_add_word(desc,
			   LD_NOIMM(CLASS_2, REG_KEY, KEY_BLOB_MODIFIER_SIZE));
	caam_desc_add_ptr(desc, virt_to_phys((void *)key_blob_modifier));

	/* Define the Input data sequence */
	caam_desc_add_word(desc, SEQ_IN_PTR(input_buffer_size));
	caam_desc_add_ptr(desc, in_key->buf.paddr);

	/* Define the Output data sequence */
	caam_desc_add_word(desc, SEQ_OUT_PTR(output_buffer_size));
	caam_desc_add_ptr(desc, out_key->buf.paddr);
	caam_desc_add_word(desc, opflag);

	KEY_DUMPDESC(desc);

	caam_key_cache_op(TEE_CACHECLEAN, in_key);
	caam_key_cache_op(TEE_CACHECLEAN, out_key);

	jobctx.desc = desc;
	status = caam_jr_enqueue(&jobctx, NULL);

	if (status == CAAM_NO_ERROR) {
		KEY_TRACE("CAAM Blob %scapsulation Done",
			  out_key->is_blob ? "En" : "De");

		caam_key_cache_op(TEE_CACHEINVALIDATE, out_key);
		caam_key_dump("Blob output key", out_key);

		goto out;
	} else {
		KEY_TRACE("CAAM Blob Status 0x%08" PRIx32 "", jobctx.status);
	}

err:
	caam_key_free(out_key);
out:
	caam_free_desc(&desc);
	return status;
}

enum caam_status caam_key_deserialize_from_bin(uint8_t *data, size_t size,
					       struct caamkey *key,
					       size_t sec_size)
{
	enum caam_status status = CAAM_FAILURE;
	struct caamkey blob = { };

	assert(data && size && key);

	KEY_TRACE("Deserialization binary buffer");
	KEY_DUMPBUF("Deserialize key buffer input", data, size);

	/*
	 * If a security key size is given, use it. Otherwise, rely on
	 * the buffer size.
	 * In some case, like ECC keys, the bignum size is less than the
	 * security size and it requires the key to be padded with 0's.
	 */
	if (sec_size == 0)
		sec_size = get_key_sec_size(data, size);

	blob.key_type = get_key_type(data, size);
	blob.sec_size = sec_size;
	blob.is_blob = true;

	if (blob.key_type == CAAM_KEY_PLAIN_TEXT) {
		key->sec_size = blob.sec_size;
		key->key_type = blob.key_type;
		key->is_blob = false;

		status = caam_key_alloc(key);
		if (status) {
			KEY_TRACE("Key allocation error");
			return status;
		}

		/* Some asymmetric keys have leading zeros we must preserve */
		memcpy(key->buf.data + key->buf.length - size, data, size);

		return CAAM_NO_ERROR;
	}

	status = caam_key_alloc(&blob);
	if (status) {
		KEY_TRACE("Key allocation error");
		return status;
	}

	memcpy(blob.buf.data, data + get_key_buf_offset(data, size),
	       get_key_buf_size(data, size));

	/* Set destination key */
	key->key_type = blob.key_type;
	key->sec_size = blob.sec_size;
	key->is_blob = false;

	/* De-blob operation */
	status = caam_key_operation_blob(&blob, key);
	if (status) {
		KEY_TRACE("De-blob operation fail");
		goto out;
	}

	KEY_TRACE("Deserialization binary buffer done");
	caam_key_dump("Deserialization output key", key);
out:
	caam_key_free(&blob);
	return status;
}

enum caam_status caam_key_serialize_to_bin(uint8_t *data, size_t size,
					   const struct caamkey *key)
{
	struct caam_key_serialized key_ser = { };
	struct caamkey blob = { };
	enum caam_status status = CAAM_FAILURE;
	size_t serialized_size = 0;

	assert(data && size && key);

	caam_key_dump("Serialization input key", key);

	/* If the key is plain text, just copy key to buffer */
	if (key->key_type == CAAM_KEY_PLAIN_TEXT) {
		if (size < key->buf.length) {
			KEY_TRACE("Buffer is too short");
			return CAAM_SHORT_BUFFER;
		}

		memcpy(data, key->buf.data, key->buf.length);

		return CAAM_NO_ERROR;
	}

	/* The input key must not be a blob */
	assert(!key->is_blob);

	/* Blob the given key for serialization and export */
	blob.is_blob = true;
	blob.sec_size = key->sec_size;
	blob.key_type = key->key_type;

	/*
	 * Check if the destination is big enough for the black blob buffer and
	 * header.
	 */
	status = caam_key_serialized_size(&blob, &serialized_size);
	if (status)
		return status;

	if (size < serialized_size) {
		KEY_TRACE("Destination buffer is too short %zu < %zu", size,
			  serialized_size);
		return CAAM_OUT_MEMORY;
	}

	/* Blob the given key */
	status = caam_key_operation_blob(key, &blob);
	if (status) {
		KEY_TRACE("Blob operation fail");
		return status;
	}

	/* Copy the header to destination */
	key_ser.magic_number = MAGIC_NUMBER;
	key_ser.key_type = blob.key_type;
	key_ser.sec_size = blob.sec_size;
	memcpy(data, &key_ser, sizeof(key_ser));

	/* Copy the key buffer */
	memcpy(data + sizeof(key_ser), blob.buf.data, blob.buf.length);

	KEY_DUMPBUF("Key data", data, size);

	caam_key_free(&blob);

	return status;
}

enum caam_status caam_key_serialized_size(const struct caamkey *key,
					  size_t *size)
{
	assert(key && size);

	/* For a plain text key, the serialized key is identical to the key */
	*size = key->buf.length;

	/*
	 * For black keys, the serialized key includes the header and must be
	 * in a blob format
	 */
	if (key->key_type != CAAM_KEY_PLAIN_TEXT) {
		size_t alloc = 0;
		const struct caamkey tmp = {
			.key_type = key->key_type,
			.sec_size = key->sec_size,
			.is_blob = true,
		};

		alloc = caam_key_get_alloc_size(&tmp);
		if (!alloc)
			return CAAM_FAILURE;

		*size = alloc + sizeof(struct caam_key_serialized);
	}

	return CAAM_NO_ERROR;
}

enum caam_status caam_key_deserialize_from_bn(const struct bignum *inkey,
					      struct caamkey *outkey,
					      size_t size_sec)
{
	enum caam_status status = CAAM_FAILURE;
	uint8_t *buf = NULL;
	size_t size = 0;

	assert(inkey && outkey);

	KEY_TRACE("Deserialization bignum");

	/* Get bignum size */
	size = crypto_bignum_num_bytes((struct bignum *)inkey);

	/* Allocate temporary buffer */
	buf = caam_calloc(size);
	if (!buf)
		return CAAM_OUT_MEMORY;

	/* Convert bignum to binary */
	crypto_bignum_bn2bin(inkey, buf);

	status = caam_key_deserialize_from_bin(buf, size, outkey, size_sec);

	caam_key_dump("Output key", outkey);

	caam_free(buf);

	return status;
}

enum caam_status caam_key_serialize_to_bn(struct bignum *outkey,
					  const struct caamkey *inkey)
{
	enum caam_status status = CAAM_FAILURE;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *buf = NULL;
	size_t size = 0;

	assert(inkey && outkey);

	KEY_TRACE("Serialization bignum");
	caam_key_dump("Input key", inkey);

	status = caam_key_serialized_size(inkey, &size);
	if (status)
		return status;

	buf = caam_calloc(size);
	if (!buf)
		return CAAM_OUT_MEMORY;

	status = caam_key_serialize_to_bin(buf, size, inkey);
	if (status)
		goto out;

	res = crypto_bignum_bin2bn(buf, size, outkey);
	if (res)
		status = CAAM_FAILURE;
out:
	caam_free(buf);

	return status;
}

#define MAX_DESC_ENTRIES 22
enum caam_status caam_key_black_encapsulation(struct caamkey *key,
					      enum caam_key_type key_type)
{
	enum caam_status status = CAAM_FAILURE;
	struct caambuf input_buf = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;

	assert(key);
	assert(!key->is_blob && key->key_type == CAAM_KEY_PLAIN_TEXT);
	assert(key_type != CAAM_KEY_PLAIN_TEXT);

	KEY_TRACE("Black key encapsulation");

	/* Copy input plain text key to temp buffer */
	status = caam_calloc_align_buf(&input_buf, key->buf.length);
	if (status)
		return status;

	memcpy(input_buf.data, key->buf.data, key->buf.length);
	cache_operation(TEE_CACHEFLUSH, input_buf.data, input_buf.length);

	/* Re-allocate the output key for black format */
	caam_key_free(key);
	key->key_type = key_type;

	status = caam_key_alloc(key);
	if (status)
		goto out;

	/* Allocate the descriptor */
	desc = caam_calloc_desc(MAX_DESC_ENTRIES);
	if (!desc) {
		KEY_TRACE("Allocation descriptor error");
		status = CAAM_OUT_MEMORY;
		goto out;
	}

	caam_key_dump("Input key", key);

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, LD_KEY(CLASS_1, PKHA_E, key->sec_size));
	caam_desc_add_ptr(desc, input_buf.paddr);

	switch (key->key_type) {
	case CAAM_KEY_BLACK_ECB:
		caam_desc_add_word(desc, FIFO_ST(CLASS_NO, PKHA_E_AES_ECB_JKEK,
						 key->sec_size));
		break;
	case CAAM_KEY_BLACK_CCM:
		caam_desc_add_word(desc, FIFO_ST(CLASS_NO, PKHA_E_AES_CCM_JKEK,
						 key->sec_size));
		break;
	default:
		status = CAAM_FAILURE;
		goto out;
	}

	caam_desc_add_ptr(desc, key->buf.paddr);

	KEY_DUMPDESC(desc);

	caam_key_cache_op(TEE_CACHEFLUSH, key);

	jobctx.desc = desc;
	status = caam_jr_enqueue(&jobctx, NULL);
	if (status != CAAM_NO_ERROR) {
		KEY_TRACE("CAAM return 0x%08x Status 0x%08" PRIx32, status,
			  jobctx.status);
		status = CAAM_FAILURE;
		goto out;
	}

	caam_key_cache_op(TEE_CACHEINVALIDATE, key);

	caam_key_dump("Output Key", key);

out:
	caam_free_buf(&input_buf);
	caam_free_desc(&desc);

	return status;
}

enum caam_status caam_key_init(void)
{
	size_t alloc_size = 0;
	const struct caamkey key = {
		.key_type = caam_key_default_key_gen_type(),
		.sec_size = 4096, /* Max RSA key size */
		.is_blob = true,
	};

	/*
	 * Ensure bignum format maximum size is enough to store a black key
	 * blob. The largest key is a 4096 bits RSA key pair.
	 */
	if (caam_key_serialized_size(&key, &alloc_size))
		return CAAM_FAILURE;

	assert(alloc_size <= CFG_CORE_BIGNUM_MAX_BITS);

	KEY_TRACE("Max serialized key size %zu", alloc_size);

	KEY_TRACE("Default CAAM key generation type %s",
		  caam_key_type_to_str[caam_key_default_key_gen_type()]);

	return CAAM_NO_ERROR;
}
