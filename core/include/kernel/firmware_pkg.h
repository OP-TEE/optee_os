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
#ifndef FIRMWARE_PKG_H
#define FIRMWARE_PKG_H

#include <types_ext.h>
#include <tee_api_types.h>

/**
 * struct firmware_pkg_info - information from parsed CMS Firmware package
 * @algo:	signature algorithm (TEE_ALG_*)
 * @digest:	digest of content (pointing into attrs)
 * @digest_len:	length of digest
 * @signature:	signature on digest
 * @signature_len: length of signature
 * @content:	the signed payload
 * @content_len: length of signed payload
 * @attrs:	signed attributes
 * @attrs_len	length of signed attributes
 */
struct firmware_pkg_info {
	uint32_t algo;
	const uint8_t *digest;
	size_t digest_len;
	const uint8_t *signature;
	size_t signature_len;
	const uint8_t *content;
	size_t content_len;
	const uint8_t *attrs;
	size_t attrs_len;
};

/**
 * firmware_pkg_parse_info() - copy firmware info from data
 * @data:	data encoded according to RFC4108
 * @len:	lenth of data
 * @fwp:	Extracted firmware package information
 *
 * @data is parsed and pointers to matching fields in struct
 * firmware_pkg_info are set to matching parts inside data. Each byte in
 * @data is read only once so it's safe to have @data in non-secure memory.
 * In case @data is in non-secure memory digest and signature need to be
 * copied before they are used.
 */
TEE_Result firmware_pkg_info_parse(const uint8_t *data, size_t len,
			struct firmware_pkg_info *fwp);

/**
 * firmware_pkg_info_free() - free allocated parts of firmware info
 * @fwp:	Firmware package info pointer
 */
void firmware_pkg_info_free(struct firmware_pkg_info *fwp);

#endif /*FIRMWARE_PKG_H*/

