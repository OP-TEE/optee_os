// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Helper functions to encode and decode the CBOR messages exchanged with the
 * TME.
 */

#include <inttypes.h>
#include <kernel/panic.h>
#include <malloc.h>
#include <qcbor.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <util.h>

#include "tme_message.h"
#include "tme_tags.h"
#include "tme_transport.h"

TEE_Result tme_encode_message(uint32_t tag, const UsefulBufC message_buf,
			      UsefulBuf *encoded_buf)
{
	QCBOREncodeContext encode_context = { };
	UsefulBufC encoded = NULLUsefulBufC;
	QCBORError qerr = QCBOR_SUCCESS;
	size_t encoded_len = 0;

	/* CBOR Encode */
	QCBOREncode_Init(&encode_context, *encoded_buf);

	QCBOREncode_AddTag(&encode_context, tag);
	QCBOREncode_AddBytes(&encode_context, message_buf);

	qerr = QCBOREncode_Finish(&encode_context, &encoded);
	if (qerr != QCBOR_SUCCESS) {
		EMSG("TME: QCBOR error %d encoding tag %"PRIu32,
		     (int)qerr, tag);
		return TEE_ERROR_GENERIC;
	}
	encoded_len = encoded.len;

	if (encoded_len <= encoded_buf->len) {
		encoded_buf->len = encoded_len;
	} else {
		encoded_buf->len = 0;
		EMSG("TME: encoded length %zu too large, tag %"PRIu32,
		     encoded_len, tag);
		return TEE_ERROR_SHORT_BUFFER;
	}

	return TEE_SUCCESS;
}

TEE_Result tme_decode_message(uint32_t tag, const UsefulBufC encoded_buf,
			      UsefulBuf *message_buf)
{
	QCBORDecodeContext decode_context = { };
	QCBORItem item = { };
	QCBORError qerr = QCBOR_SUCCESS;
	size_t decoded_len = 0;
	uint64_t item_tag = 0;
	uint32_t fips_approved_tag = 0;

	/* CBOR Decode */
	QCBORDecode_Init(&decode_context, encoded_buf,
			 QCBOR_DECODE_MODE_NORMAL);

	qerr = QCBORDecode_GetNext(&decode_context, &item);
	if (qerr != QCBOR_SUCCESS) {
		EMSG("TME: QCBOR error %d decoding tag %"PRIu32,
		     (int)qerr, tag);
		return TEE_ERROR_GENERIC;
	}

	/*
	 * The FIPS_INDICATOR field of the tag might be set by the TME in the
	 * response. Either the tag matches the message (possibly with the FIPS
	 * indicator set to 1) or the TME responded with an error tag.
	 */
	item_tag = QCBORDecode_GetNthTag(&decode_context, &item, 0);
	fips_approved_tag = TME_MSG_TAG_FVAL(tag, FIPS_INDICATOR, 1);
	if (item_tag != tag && item_tag != fips_approved_tag &&
	    item_tag != TME_MSG_CBOR_TAG_ERROR) {
		EMSG("TME: response tag %#"PRIx64" for tag %"PRIu32, item_tag,
		     tag);
		return TEE_ERROR_GENERIC;
	}

	/*
	 * Generic errors sent as integers. Valid bstr message handled below.
	 * For example, the message may have failed some integrity checks due
	 * to corruption in flight.
	 */
	if (item.uDataType == QCBOR_TYPE_UINT64 ||
	    item.uDataType == QCBOR_TYPE_INT64) {
		EMSG("TME: error %#"PRIx64" for tag %"PRIu32, item.val.uint64,
		     tag);
		return TEE_ERROR_GENERIC;
	}

	/* A valid and handled message has bstr formatted response */
	if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
		EMSG("TME: response type %d for tag %"PRIu32,
		     (int)item.uDataType, tag);
		return TEE_ERROR_GENERIC;
	}

	decoded_len = MIN(message_buf->len, item.val.string.len);
	memcpy(message_buf->ptr, item.val.string.ptr, decoded_len);

	if (decoded_len <= message_buf->len) {
		message_buf->len = decoded_len;
	} else {
		message_buf->len = 0;
		EMSG("TME: cannot copy the message, tag %"PRIu32, tag);
		return TEE_ERROR_SHORT_BUFFER;
	}

	return TEE_SUCCESS;
}

size_t tme_get_encoded_number_size(uint64_t number)
{
	size_t encoded_size = sizeof(uint8_t);

	if (number > 0xffffffff)
		encoded_size += sizeof(uint64_t);
	else if (number > 0xffff)
		encoded_size += sizeof(uint32_t);
	else if (number > 0xff)
		encoded_size += sizeof(uint16_t);
	else if (number >= 24)
		encoded_size += sizeof(uint8_t);

	return encoded_size;
}

size_t tme_get_max_request_payload(void)
{
	return TME_MAX_CBOR_REQ_LEN -	/* Max CBOR request size */
	       /* Maximum CBOR tag value */
	       tme_get_encoded_number_size(TME_MSG_CBOR_TAG_MAX) -
	       /* Number of bytes to store the CBOR size */
	       tme_get_encoded_number_size(TME_MAX_CBOR_REQ_LEN);
}

size_t tme_get_max_response_payload(void)
{
	return TME_MAX_CBOR_RSP_LEN -	/* Max CBOR response size */
	       /* Maximum CBOR tag value */
	       tme_get_encoded_number_size(TME_MSG_CBOR_TAG_MAX) -
	       /* Number of bytes to store the CBOR size */
	       tme_get_encoded_number_size(TME_MAX_CBOR_RSP_LEN);
}

TEE_Result tme_transceive_message(uint32_t tag, void *req_buf,
				  size_t req_buf_len, void *resp_buf,
				  size_t resp_buf_capacity,
				  size_t *resp_buf_len)
{
	TEE_Result res = TEE_SUCCESS;

	tme_msg_req_t *tme_msg_req = NULL;
	size_t tme_msg_req_len = 0;
	UsefulBufC request_buf = { .ptr = req_buf, .len = req_buf_len };
	UsefulBuf encoded_request_buf = { };
	size_t encoded_request_len = 0;

	tme_msg_rsp_t *tme_msg_rsp = NULL;
	size_t tme_msg_rsp_len = 0;
	UsefulBuf response_buf = { .ptr = resp_buf, .len = resp_buf_capacity };
	UsefulBuf encoded_response_buf = { };
	size_t encoded_response_len = 0;

	/* Allocate request and response buffers */
	encoded_request_len = tme_get_encoded_number_size(tag) +
			      tme_get_encoded_number_size(req_buf_len) +
			      req_buf_len;

	if (encoded_request_len > TME_MAX_CBOR_REQ_LEN) {
		EMSG("TME: request length %zu too large, tag %"PRIu32,
		     encoded_request_len, tag);
		res = TEE_ERROR_EXCESS_DATA;
		goto exit;
	}

	tme_msg_req_len = sizeof(tme_msg_hdr_t) + encoded_request_len;
	tme_msg_req = malloc(tme_msg_req_len);

	if (!tme_msg_req) {
		EMSG("TME: cannot allocate %zu bytes, tag %"PRIu32,
		     tme_msg_req_len, tag);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	encoded_request_buf.ptr = tme_msg_req->enc_req_buf;
	encoded_request_buf.len = encoded_request_len;

	encoded_response_len = tme_get_encoded_number_size(tag) +
			       tme_get_encoded_number_size(resp_buf_capacity) +
			       resp_buf_capacity;

	if (encoded_response_len > TME_MAX_CBOR_RSP_LEN) {
		EMSG("TME: response length %zu too large, tag %"PRIu32,
		     encoded_response_len, tag);
		res = TEE_ERROR_EXCESS_DATA;
		goto exit;
	}

	tme_msg_rsp_len = sizeof(tme_msg_hdr_t) + encoded_response_len;
	tme_msg_rsp = malloc(tme_msg_rsp_len);

	if (!tme_msg_rsp) {
		EMSG("TME: cannot allocate %zu bytes, tag %"PRIu32,
		     tme_msg_rsp_len, tag);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}

	encoded_response_buf.ptr = tme_msg_rsp->enc_rsp_buf;
	encoded_response_buf.len = encoded_response_len;

	/* CBOR Encode request */
	res = tme_encode_message(tag, request_buf, &encoded_request_buf);
	if (res != TEE_SUCCESS) {
		EMSG("TME: cannot encode tag %"PRIu32", result %#"PRIx32, tag,
		     res);
		goto exit;
	}

	/* Send synchronous request to the TME */
	res = tme_send_recv_message(tme_msg_req, tme_msg_req_len,
				    tme_msg_rsp, &tme_msg_rsp_len,
				    TMECOM_RESPONSE_TIMEOUT_MS);
	if (res != TEE_SUCCESS) {
		/*
		 * A protocol failure in communication with the TME is
		 * non-recoverable
		 */
		panic("TME: message transport failure");
	}

	/*
	 * Update the encoded response buffer length taking in to account the
	 * header included in the response.
	 */
	encoded_response_buf.len = tme_msg_rsp_len - sizeof(tme_msg_hdr_t);

	/* CBOR Decode Response */
	res = tme_decode_message(tag, UsefulBuf_Const(encoded_response_buf),
				 &response_buf);

	if (res != TEE_SUCCESS) {
		EMSG("TME: cannot decode tag %"PRIu32", result %#"PRIx32, tag,
		     res);
		goto exit;
	}

	*resp_buf_len = response_buf.len;

exit:
	if (tme_msg_req)
		free(tme_msg_req);
	if (tme_msg_rsp)
		free(tme_msg_rsp);

	if (res != TEE_SUCCESS)
		EMSG("TME: transceive failed, tag %"PRIu32, tag);

	return res;
}
