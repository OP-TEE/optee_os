/* SPDX-License-Identifier: BSD-2-Clause */
/* TA call-site C-object capacity checks. Preserve the out-of-line ABI. */
#ifndef TEE_INTERNAL_API_FORTIFY_H
#define TEE_INTERNAL_API_FORTIFY_H

#if (defined(__GNUC__) || defined(__clang__)) && \
	!defined(__OPTEE_LIBUTEE_INTERNAL) && \
	!defined(__OPTEE_DISABLE_TA_API_FORTIFY) && \
	(!defined(__cplusplus) || __cplusplus >= 201103L)

/* Reject a known overlong output before entering libutee. */
#define __ta_fail() do { \
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS); \
	__builtin_unreachable(); \
} while (0)

#define __ta_check_bytes(p, captured, n) do { \
	size_t __ta_bos = __builtin_object_size((p), 1); \
	if (__ta_bos == (size_t)-1) \
		__ta_bos = __builtin_object_size((const void *)(captured), 1); \
	if (__ta_bos != (size_t)-1 && \
	    (size_t)(n) > __ta_bos) \
		__ta_fail(); \
} while (0)

#define __ta_check_words(p, captured, n) do { \
	size_t __ta_bos = __builtin_object_size((p), 1); \
	if (__ta_bos == (size_t)-1) \
		__ta_bos = __builtin_object_size((const void *)(captured), 1); \
	if (__ta_bos != (size_t)-1 && \
	    (size_t)(n) > __ta_bos / sizeof(uint32_t)) \
		__ta_fail(); \
} while (0)

/* The public GP 1.1 aliases remain object-like macros. Wrapping their
 * __GP11 symbols preserves function pointer uses of the public names.
 */
#if __OPTEE_CORE_API_COMPAT_1_1

#define __GP11_TEE_MemMove(dest, src, size) \
	(__extension__ ({ \
	void *__ta_arg0 = (dest); \
	uint32_t __ta_arg2 = (size); \
	__ta_check_bytes((dest), __ta_arg0, __ta_arg2); \
	__GP11_TEE_MemMove(__ta_arg0, src, __ta_arg2); \
	}))

#define __GP11_TEE_MemFill(buff, x, size) \
	(__extension__ ({ \
	void *__ta_arg0 = (buff); \
	uint32_t __ta_arg2 = (size); \
	__ta_check_bytes((buff), __ta_arg0, __ta_arg2); \
	__GP11_TEE_MemFill(__ta_arg0, x, __ta_arg2); \
	}))

#define __GP11_TEE_GetPropertyAsString(propsetOrEnumerator, name, \
	valueBuffer, valueBufferLen) \
	(__extension__ ({ \
	char *__ta_arg2 = (valueBuffer); \
	uint32_t *__ta_arg3 = (valueBufferLen); \
	if (__ta_arg3) \
		__ta_check_bytes((valueBuffer), __ta_arg2, *__ta_arg3); \
	__GP11_TEE_GetPropertyAsString(propsetOrEnumerator, name, __ta_arg2, \
		__ta_arg3); \
	}))

#define __GP11_TEE_GetPropertyAsBinaryBlock(propsetOrEnumerator, name, \
	valueBuffer, valueBufferLen) \
	(__extension__ ({ \
	void *__ta_arg2 = (valueBuffer); \
	uint32_t *__ta_arg3 = (valueBufferLen); \
	if (__ta_arg3) \
		__ta_check_bytes((valueBuffer), __ta_arg2, *__ta_arg3); \
	__GP11_TEE_GetPropertyAsBinaryBlock(propsetOrEnumerator, name, \
		__ta_arg2, __ta_arg3); \
	}))

#define __GP11_TEE_GetPropertyName(enumerator, nameBuffer, nameBufferLen) \
	(__extension__ ({ \
	void *__ta_arg1 = (nameBuffer); \
	uint32_t *__ta_arg2 = (nameBufferLen); \
	if (__ta_arg2) \
		__ta_check_bytes((nameBuffer), __ta_arg1, *__ta_arg2); \
	__GP11_TEE_GetPropertyName(enumerator, __ta_arg1, __ta_arg2); \
	}))

#define __GP11_TEE_GetObjectBufferAttribute(object, attributeID, buffer, size) \
	(__extension__ ({ \
	void *__ta_arg2 = (buffer); \
	uint32_t *__ta_arg3 = (size); \
	if (__ta_arg3) \
		__ta_check_bytes((buffer), __ta_arg2, *__ta_arg3); \
	__GP11_TEE_GetObjectBufferAttribute(object, attributeID, __ta_arg2, \
		__ta_arg3); \
	}))

#define __GP11_TEE_ReadObjectData(object, buffer, size, count) \
	(__extension__ ({ \
	void *__ta_arg1 = (buffer); \
	uint32_t __ta_arg2 = (size); \
	__ta_check_bytes((buffer), __ta_arg1, __ta_arg2); \
	__GP11_TEE_ReadObjectData(object, __ta_arg1, __ta_arg2, count); \
	}))

#define __GP11_TEE_GetOperationInfoMultiple(operation, \
	operationInfoMultiple, operationSize) \
	(__extension__ ({ \
	TEE_OperationInfoMultiple *__ta_arg1 = (operationInfoMultiple); \
	uint32_t *__ta_arg2 = (operationSize); \
	if (__ta_arg2) \
		__ta_check_bytes((operationInfoMultiple), \
			__ta_arg1, *__ta_arg2); \
	__GP11_TEE_GetOperationInfoMultiple(operation, __ta_arg1, __ta_arg2); \
	}))

#define __GP11_TEE_DigestDoFinal(operation, chunk, chunkLen, hash, hashLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (hash); \
	uint32_t *__ta_arg4 = (hashLen); \
	if (__ta_arg4) \
		__ta_check_bytes((hash), __ta_arg3, *__ta_arg4); \
	__GP11_TEE_DigestDoFinal(operation, chunk, chunkLen, \
		__ta_arg3, __ta_arg4); \
	}))

#define __GP11_TEE_CipherUpdate(operation, srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	uint32_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	__GP11_TEE_CipherUpdate(operation, srcData, srcLen, \
		__ta_arg3, __ta_arg4); \
	}))

#define __GP11_TEE_CipherDoFinal(operation, srcData, srcLen, destData, \
	destLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	uint32_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	__GP11_TEE_CipherDoFinal(operation, srcData, srcLen, \
		__ta_arg3, __ta_arg4); \
	}))

#define __GP11_TEE_MACComputeFinal(operation, message, messageLen, mac, \
	macLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (mac); \
	uint32_t *__ta_arg4 = (macLen); \
	if (__ta_arg4) \
		__ta_check_bytes((mac), __ta_arg3, *__ta_arg4); \
	__GP11_TEE_MACComputeFinal(operation, message, messageLen, __ta_arg3, \
		__ta_arg4); \
	}))

#define __GP11_TEE_AEUpdate(operation, srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	uint32_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	__GP11_TEE_AEUpdate(operation, srcData, srcLen, __ta_arg3, __ta_arg4); \
	}))

#define __GP11_TEE_AEEncryptFinal(operation, srcData, srcLen, destData, \
	destLen, tag, tagLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	uint32_t *__ta_arg4 = (destLen); \
	void *__ta_arg5 = (tag); \
	uint32_t *__ta_arg6 = (tagLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	if (__ta_arg6) \
		__ta_check_bytes((tag), __ta_arg5, *__ta_arg6); \
	__GP11_TEE_AEEncryptFinal(operation, srcData, srcLen, __ta_arg3, \
		__ta_arg4, __ta_arg5, __ta_arg6); \
	}))

#define __GP11_TEE_AEDecryptFinal(operation, srcData, srcLen, destData, \
	destLen, tag, tagLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	uint32_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	__GP11_TEE_AEDecryptFinal(operation, srcData, srcLen, __ta_arg3, \
		__ta_arg4, tag, tagLen); \
	}))

#define __GP11_TEE_AsymmetricEncrypt(operation, params, paramCount, \
	srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg5 = (destData); \
	uint32_t *__ta_arg6 = (destLen); \
	if (__ta_arg6) \
		__ta_check_bytes((destData), __ta_arg5, *__ta_arg6); \
	__GP11_TEE_AsymmetricEncrypt(operation, params, paramCount, srcData, \
		srcLen, __ta_arg5, __ta_arg6); \
	}))

#define __GP11_TEE_AsymmetricDecrypt(operation, params, paramCount, \
	srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg5 = (destData); \
	uint32_t *__ta_arg6 = (destLen); \
	if (__ta_arg6) \
		__ta_check_bytes((destData), __ta_arg5, *__ta_arg6); \
	__GP11_TEE_AsymmetricDecrypt(operation, params, paramCount, srcData, \
		srcLen, __ta_arg5, __ta_arg6); \
	}))

#define __GP11_TEE_AsymmetricSignDigest(operation, params, paramCount, \
	digest, digestLen, signature, signatureLen) \
	(__extension__ ({ \
	void *__ta_arg5 = (signature); \
	uint32_t *__ta_arg6 = (signatureLen); \
	if (__ta_arg6) \
		__ta_check_bytes((signature), __ta_arg5, *__ta_arg6); \
	__GP11_TEE_AsymmetricSignDigest(operation, params, paramCount, digest, \
		digestLen, __ta_arg5, __ta_arg6); \
	}))

#define __GP11_TEE_GenerateRandom(randomBuffer, randomBufferLen) \
	(__extension__ ({ \
	void *__ta_arg0 = (randomBuffer); \
	uint32_t __ta_arg1 = (randomBufferLen); \
	__ta_check_bytes((randomBuffer), __ta_arg0, __ta_arg1); \
	__GP11_TEE_GenerateRandom(__ta_arg0, __ta_arg1); \
	}))

#define __GP11_TEE_BigIntInitFMM(bigIntFMM, len) \
	(__extension__ ({ \
	TEE_BigIntFMM *__ta_arg0 = (bigIntFMM); \
	uint32_t __ta_arg1 = (len); \
	__ta_check_words((bigIntFMM), __ta_arg0, __ta_arg1); \
	__GP11_TEE_BigIntInitFMM(__ta_arg0, __ta_arg1); \
	}))

#define __GP11_TEE_BigIntConvertToOctetString(buffer, bufferLen, bigInt) \
	(__extension__ ({ \
	uint8_t *__ta_arg0 = (buffer); \
	uint32_t *__ta_arg1 = (bufferLen); \
	if (__ta_arg1) \
		__ta_check_bytes((buffer), __ta_arg0, *__ta_arg1); \
	__GP11_TEE_BigIntConvertToOctetString(__ta_arg0, __ta_arg1, bigInt); \
	}))

#else /* Current API ABI */

#define TEE_MemMove(dest, src, size) \
	(__extension__ ({ \
	void *__ta_arg0 = (dest); \
	size_t __ta_arg2 = (size); \
	__ta_check_bytes((dest), __ta_arg0, __ta_arg2); \
	TEE_MemMove(__ta_arg0, src, __ta_arg2); \
	}))

#define TEE_MemFill(buff, x, size) \
	(__extension__ ({ \
	void *__ta_arg0 = (buff); \
	size_t __ta_arg2 = (size); \
	__ta_check_bytes((buff), __ta_arg0, __ta_arg2); \
	TEE_MemFill(__ta_arg0, x, __ta_arg2); \
	}))

#define TEE_GetPropertyAsString(propsetOrEnumerator, name, valueBuffer, \
	valueBufferLen) \
	(__extension__ ({ \
	char *__ta_arg2 = (valueBuffer); \
	size_t *__ta_arg3 = (valueBufferLen); \
	if (__ta_arg3) \
		__ta_check_bytes((valueBuffer), __ta_arg2, *__ta_arg3); \
	TEE_GetPropertyAsString(propsetOrEnumerator, name, \
		__ta_arg2, __ta_arg3); \
	}))

#define TEE_GetPropertyAsBinaryBlock(propsetOrEnumerator, name, \
	valueBuffer, valueBufferLen) \
	(__extension__ ({ \
	void *__ta_arg2 = (valueBuffer); \
	size_t *__ta_arg3 = (valueBufferLen); \
	if (__ta_arg3) \
		__ta_check_bytes((valueBuffer), __ta_arg2, *__ta_arg3); \
	TEE_GetPropertyAsBinaryBlock(propsetOrEnumerator, name, __ta_arg2, \
		__ta_arg3); \
	}))

#define TEE_GetPropertyName(enumerator, nameBuffer, nameBufferLen) \
	(__extension__ ({ \
	void *__ta_arg1 = (nameBuffer); \
	size_t *__ta_arg2 = (nameBufferLen); \
	if (__ta_arg2) \
		__ta_check_bytes((nameBuffer), __ta_arg1, *__ta_arg2); \
	TEE_GetPropertyName(enumerator, __ta_arg1, __ta_arg2); \
	}))

#define TEE_GetObjectBufferAttribute(object, attributeID, buffer, size) \
	(__extension__ ({ \
	void *__ta_arg2 = (buffer); \
	size_t *__ta_arg3 = (size); \
	if (__ta_arg3) \
		__ta_check_bytes((buffer), __ta_arg2, *__ta_arg3); \
	TEE_GetObjectBufferAttribute(object, attributeID, \
		__ta_arg2, __ta_arg3); \
	}))

#define TEE_ReadObjectData(object, buffer, size, count) \
	(__extension__ ({ \
	void *__ta_arg1 = (buffer); \
	size_t __ta_arg2 = (size); \
	__ta_check_bytes((buffer), __ta_arg1, __ta_arg2); \
	TEE_ReadObjectData(object, __ta_arg1, __ta_arg2, count); \
	}))

#define TEE_GetOperationInfoMultiple(operation, operationInfoMultiple, \
	operationSize) \
	(__extension__ ({ \
	TEE_OperationInfoMultiple *__ta_arg1 = (operationInfoMultiple); \
	size_t *__ta_arg2 = (operationSize); \
	if (__ta_arg2) \
		__ta_check_bytes((operationInfoMultiple), \
			__ta_arg1, *__ta_arg2); \
	TEE_GetOperationInfoMultiple(operation, __ta_arg1, __ta_arg2); \
	}))

#define TEE_DigestDoFinal(operation, chunk, chunkLen, hash, hashLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (hash); \
	size_t *__ta_arg4 = (hashLen); \
	if (__ta_arg4) \
		__ta_check_bytes((hash), __ta_arg3, *__ta_arg4); \
	TEE_DigestDoFinal(operation, chunk, chunkLen, __ta_arg3, __ta_arg4); \
	}))

#define TEE_DigestExtract(operation, hash, hashLen) \
	(__extension__ ({ \
	void *__ta_arg1 = (hash); \
	size_t *__ta_arg2 = (hashLen); \
	if (__ta_arg2) \
		__ta_check_bytes((hash), __ta_arg1, *__ta_arg2); \
	TEE_DigestExtract(operation, __ta_arg1, __ta_arg2); \
	}))

#define TEE_CipherUpdate(operation, srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	size_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	TEE_CipherUpdate(operation, srcData, srcLen, __ta_arg3, __ta_arg4); \
	}))

#define TEE_CipherDoFinal(operation, srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	size_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	TEE_CipherDoFinal(operation, srcData, srcLen, __ta_arg3, __ta_arg4); \
	}))

#define TEE_MACComputeFinal(operation, message, messageLen, mac, macLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (mac); \
	size_t *__ta_arg4 = (macLen); \
	if (__ta_arg4) \
		__ta_check_bytes((mac), __ta_arg3, *__ta_arg4); \
	TEE_MACComputeFinal(operation, message, messageLen, \
		__ta_arg3, __ta_arg4); \
	}))

#define TEE_AEUpdate(operation, srcData, srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	size_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	TEE_AEUpdate(operation, srcData, srcLen, __ta_arg3, __ta_arg4); \
	}))

#define TEE_AEEncryptFinal(operation, srcData, srcLen, destData, destLen, \
	tag, tagLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	size_t *__ta_arg4 = (destLen); \
	void *__ta_arg5 = (tag); \
	size_t *__ta_arg6 = (tagLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	if (__ta_arg6) \
		__ta_check_bytes((tag), __ta_arg5, *__ta_arg6); \
	TEE_AEEncryptFinal(operation, srcData, srcLen, __ta_arg3, __ta_arg4, \
		__ta_arg5, __ta_arg6); \
	}))

#define TEE_AEDecryptFinal(operation, srcData, srcLen, destData, destLen, \
	tag, tagLen) \
	(__extension__ ({ \
	void *__ta_arg3 = (destData); \
	size_t *__ta_arg4 = (destLen); \
	if (__ta_arg4) \
		__ta_check_bytes((destData), __ta_arg3, *__ta_arg4); \
	TEE_AEDecryptFinal(operation, srcData, srcLen, __ta_arg3, __ta_arg4, \
		tag, tagLen); \
	}))

#define TEE_AsymmetricEncrypt(operation, params, paramCount, srcData, \
	srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg5 = (destData); \
	size_t *__ta_arg6 = (destLen); \
	if (__ta_arg6) \
		__ta_check_bytes((destData), __ta_arg5, *__ta_arg6); \
	TEE_AsymmetricEncrypt(operation, params, paramCount, srcData, srcLen, \
		__ta_arg5, __ta_arg6); \
	}))

#define TEE_AsymmetricDecrypt(operation, params, paramCount, srcData, \
	srcLen, destData, destLen) \
	(__extension__ ({ \
	void *__ta_arg5 = (destData); \
	size_t *__ta_arg6 = (destLen); \
	if (__ta_arg6) \
		__ta_check_bytes((destData), __ta_arg5, *__ta_arg6); \
	TEE_AsymmetricDecrypt(operation, params, paramCount, srcData, srcLen, \
		__ta_arg5, __ta_arg6); \
	}))

#define TEE_AsymmetricSignDigest(operation, params, paramCount, digest, \
	digestLen, signature, signatureLen) \
	(__extension__ ({ \
	void *__ta_arg5 = (signature); \
	size_t *__ta_arg6 = (signatureLen); \
	if (__ta_arg6) \
		__ta_check_bytes((signature), __ta_arg5, *__ta_arg6); \
	TEE_AsymmetricSignDigest(operation, params, paramCount, digest, \
		digestLen, __ta_arg5, __ta_arg6); \
	}))

#define TEE_GenerateRandom(randomBuffer, randomBufferLen) \
	(__extension__ ({ \
	void *__ta_arg0 = (randomBuffer); \
	size_t __ta_arg1 = (randomBufferLen); \
	__ta_check_bytes((randomBuffer), __ta_arg0, __ta_arg1); \
	TEE_GenerateRandom(__ta_arg0, __ta_arg1); \
	}))

#define TEE_BigIntInit(bigInt, len) \
	(__extension__ ({ \
	TEE_BigInt *__ta_arg0 = (bigInt); \
	size_t __ta_arg1 = (len); \
	__ta_check_words((bigInt), __ta_arg0, __ta_arg1); \
	TEE_BigIntInit(__ta_arg0, __ta_arg1); \
	}))

#define TEE_BigIntInitFMM(bigIntFMM, len) \
	(__extension__ ({ \
	TEE_BigIntFMM *__ta_arg0 = (bigIntFMM); \
	size_t __ta_arg1 = (len); \
	__ta_check_words((bigIntFMM), __ta_arg0, __ta_arg1); \
	TEE_BigIntInitFMM(__ta_arg0, __ta_arg1); \
	}))

#define TEE_BigIntConvertToOctetString(buffer, bufferLen, bigInt) \
	(__extension__ ({ \
	uint8_t *__ta_arg0 = (buffer); \
	size_t *__ta_arg1 = (bufferLen); \
	if (__ta_arg1) \
		__ta_check_bytes((buffer), __ta_arg0, *__ta_arg1); \
	TEE_BigIntConvertToOctetString(__ta_arg0, __ta_arg1, bigInt); \
	}))

#endif /* __OPTEE_CORE_API_COMPAT_1_1 */

/* These two APIs have no GP 1.1 public alias. */
#if __OPTEE_CORE_API_COMPAT_1_1

#define TEE_DigestExtract(operation, hash, hashLen) \
	(__extension__ ({ \
	void *__ta_arg1 = (hash); \
	size_t *__ta_arg2 = (hashLen); \
	if (__ta_arg2) \
		__ta_check_bytes((hash), __ta_arg1, *__ta_arg2); \
	TEE_DigestExtract(operation, __ta_arg1, __ta_arg2); \
	}))

#define TEE_BigIntInit(bigInt, len) \
	(__extension__ ({ \
	TEE_BigInt *__ta_arg0 = (bigInt); \
	size_t __ta_arg1 = (len); \
	__ta_check_words((bigInt), __ta_arg0, __ta_arg1); \
	TEE_BigIntInit(__ta_arg0, __ta_arg1); \
	}))
#endif

#endif /* compiler and build guard */
#endif /* TEE_INTERNAL_API_FORTIFY_H */
