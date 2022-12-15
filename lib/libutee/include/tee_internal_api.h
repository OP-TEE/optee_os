/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

/* Based on GP TEE Internal API Specification Version 0.27 */
#ifndef TEE_INTERNAL_API_H
#define TEE_INTERNAL_API_H

#ifdef __TEE_API_COMPAT_H
#error "<tee_api_compat.h> must not be included before <tee_internal_api.h>"
#endif

#include <compiler.h>
#include <stddef.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <trace.h>

/* Property access functions */

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
				   const char *name, char *valueBuffer,
				   size_t *valueBufferLen);
TEE_Result __GP11_TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
					  const char *name, char *valueBuffer,
					  uint32_t *valueBufferLen);

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
				 const char *name, bool *value);

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
				const char *name, uint32_t *value);

TEE_Result TEE_GetPropertyAsU64(TEE_PropSetHandle propsetOrEnumerator,
				const char *name, uint64_t *value);

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
					const char *name, void *valueBuffer,
					size_t *valueBufferLen);
TEE_Result
__GP11_TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
				    const char *name, void *valueBuffer,
				    uint32_t *valueBufferLen);

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
				 const char *name, TEE_UUID *value);

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
				     const char *name, TEE_Identity *value);

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator);

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator);

void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator,
				 TEE_PropSetHandle propSet);

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator);

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator,
			       void *nameBuffer, size_t *nameBufferLen);
TEE_Result __GP11_TEE_GetPropertyName(TEE_PropSetHandle enumerator,
				      void *nameBuffer,
				      uint32_t *nameBufferLen);

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator);

/* System API - Misc */

void TEE_Panic(TEE_Result panicCode);

/* System API - Internal Client API */

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
			     uint32_t cancellationRequestTimeout,
			     uint32_t paramTypes,
			     TEE_Param params[TEE_NUM_PARAMS],
			     TEE_TASessionHandle *session,
			     uint32_t *returnOrigin);
TEE_Result __GP11_TEE_OpenTASession(const TEE_UUID *destination,
				    uint32_t cancellationRequestTimeout,
				    uint32_t paramTypes,
				    __GP11_TEE_Param params[TEE_NUM_PARAMS],
				    TEE_TASessionHandle *session,
				    uint32_t *returnOrigin);

void TEE_CloseTASession(TEE_TASessionHandle session);

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
			       uint32_t cancellationRequestTimeout,
			       uint32_t commandID, uint32_t paramTypes,
			       TEE_Param params[TEE_NUM_PARAMS],
			       uint32_t *returnOrigin);
TEE_Result __GP11_TEE_InvokeTACommand(TEE_TASessionHandle session,
				      uint32_t cancellationRequestTimeout,
				      uint32_t commandID, uint32_t paramTypes,
				      __GP11_TEE_Param params[TEE_NUM_PARAMS],
				      uint32_t *returnOrigin);

/* System API - Cancellations */

bool TEE_GetCancellationFlag(void);

bool TEE_UnmaskCancellation(void);

bool TEE_MaskCancellation(void);

/* System API - Memory Management */

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
				       size_t size);
TEE_Result __GP11_TEE_CheckMemoryAccessRights(uint32_t accessFlags,
					      void *buffer, uint32_t size);

void TEE_SetInstanceData(const void *instanceData);

const void *TEE_GetInstanceData(void);

void *TEE_Malloc(size_t size, uint32_t hint);
void *__GP11_TEE_Malloc(uint32_t size, uint32_t hint);

void *TEE_Realloc(void *buffer, size_t newSize);
void *__GP11_TEE_Realloc(void *buffer, uint32_t newSize);

void TEE_Free(void *buffer);

void *TEE_MemMove(void *dest, const void *src, size_t size);
void *__GP11_TEE_MemMove(void *dest, const void *src, uint32_t size);

/*
 * Note: TEE_MemCompare() has a constant-time implementation (execution time
 * does not depend on buffer content but only on buffer size). It is the main
 * difference with memcmp().
 */
int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, size_t size);
int32_t __GP11_TEE_MemCompare(const void *buffer1, const void *buffer2,
			      uint32_t size);

void TEE_MemFill(void *buff, uint32_t x, size_t size);
void __GP11_TEE_MemFill(void *buff, uint32_t x, uint32_t size);

/* Data and Key Storage API  - Generic Object Functions */

void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo);
void __GP11_TEE_GetObjectInfo(TEE_ObjectHandle object,
			      __GP11_TEE_ObjectInfo *objectInfo);

TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
			      TEE_ObjectInfo *objectInfo);
TEE_Result __GP11_TEE_GetObjectInfo1(TEE_ObjectHandle object,
				     __GP11_TEE_ObjectInfo *objectInfo);

void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage);
TEE_Result TEE_RestrictObjectUsage1(TEE_ObjectHandle object,
				    uint32_t objectUsage);

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					uint32_t attributeID, void *buffer,
					size_t *size);
TEE_Result __GP11_TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					       uint32_t attributeID,
					       void *buffer, uint32_t *size);

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
				       uint32_t attributeID, uint32_t *a,
				       uint32_t *b);

void TEE_CloseObject(TEE_ObjectHandle object);

/* Data and Key Storage API  - Transient Object Functions */

TEE_Result TEE_AllocateTransientObject(TEE_ObjectType objectType,
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object);
TEE_Result __GP11_TEE_AllocateTransientObject(TEE_ObjectType objectType,
					      uint32_t maxKeySize,
					      TEE_ObjectHandle *object);

void TEE_FreeTransientObject(TEE_ObjectHandle object);

void TEE_ResetTransientObject(TEE_ObjectHandle object);

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       const TEE_Attribute *attrs,
				       uint32_t attrCount);
TEE_Result __GP11_TEE_PopulateTransientObject(TEE_ObjectHandle object,
					      const __GP11_TEE_Attribute *attrs,
					      uint32_t attrCount);

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID,
			  const void *buffer, size_t length);
void __GP11_TEE_InitRefAttribute(__GP11_TEE_Attribute *attr,
				 uint32_t attributeID,
				 const void *buffer, uint32_t length);

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID,
			    uint32_t a, uint32_t b);
void __GP11_TEE_InitValueAttribute(__GP11_TEE_Attribute *attr,
				   uint32_t attributeID,
				   uint32_t a, uint32_t b);

void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject,
			      TEE_ObjectHandle srcObject);

TEE_Result TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
				     TEE_ObjectHandle srcObject);

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
			   const TEE_Attribute *params, uint32_t paramCount);
TEE_Result __GP11_TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
				  const __GP11_TEE_Attribute *params,
				  uint32_t paramCount);

/* Data and Key Storage API  - Persistent Object Functions */

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void *objectID,
				    size_t objectIDLen, uint32_t flags,
				    TEE_ObjectHandle *object);
TEE_Result __GP11_TEE_OpenPersistentObject(uint32_t storageID,
					   const void *objectID,
					   uint32_t objectIDLen, uint32_t flags,
					   TEE_ObjectHandle *object);

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, const void *objectID,
				      size_t objectIDLen, uint32_t flags,
				      TEE_ObjectHandle attributes,
				      const void *initialData,
				      size_t initialDataLen,
				      TEE_ObjectHandle *object);
TEE_Result __GP11_TEE_CreatePersistentObject(uint32_t storageID,
					     const void *objectID,
					     uint32_t objectIDLen,
					     uint32_t flags,
					     TEE_ObjectHandle attributes,
					     const void *initialData,
					     uint32_t initialDataLen,
					     TEE_ObjectHandle *object);

void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object);

TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object);

TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
				      const void *newObjectID,
				      size_t newObjectIDLen);
TEE_Result __GP11_TEE_RenamePersistentObject(TEE_ObjectHandle object,
					     const void *newObjectID,
					     uint32_t newObjectIDLen);

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *
						  objectEnumerator);

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator);

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle
					       objectEnumerator,
					       uint32_t storageID);

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo,
				       void *objectID, size_t *objectIDLen);
TEE_Result
__GP11_TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				   __GP11_TEE_ObjectInfo *objectInfo,
				   void *objectID, uint32_t *objectIDLen);

/* Data and Key Storage API  - Data Stream Access Functions */

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer,
			      size_t size, size_t *count);
TEE_Result __GP11_TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer,
				     uint32_t size, uint32_t *count);

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void *buffer,
			       size_t size);
TEE_Result __GP11_TEE_WriteObjectData(TEE_ObjectHandle object,
				      const void *buffer, uint32_t size);

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, size_t size);
TEE_Result __GP11_TEE_TruncateObjectData(TEE_ObjectHandle object,
					 uint32_t size);

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, intmax_t offset,
			      TEE_Whence whence);
TEE_Result __GP11_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset,
				     TEE_Whence whence);

/* Cryptographic Operations API - Generic Operation Functions */

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
				 uint32_t algorithm, uint32_t mode,
				 uint32_t maxKeySize);

void TEE_FreeOperation(TEE_OperationHandle operation);
void __GP11_TEE_FreeOperation(TEE_OperationHandle operation);

void TEE_GetOperationInfo(TEE_OperationHandle operation,
			  TEE_OperationInfo *operationInfo);

TEE_Result
TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
			     TEE_OperationInfoMultiple *operationInfoMultiple,
			     size_t *operationSize);
TEE_Result
__GP11_TEE_GetOperationInfoMultiple(TEE_OperationHandle operation,
				    TEE_OperationInfoMultiple *info,
				    uint32_t *operationSize);

void TEE_ResetOperation(TEE_OperationHandle operation);

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
			       TEE_ObjectHandle key);
TEE_Result __GP11_TEE_SetOperationKey(TEE_OperationHandle operation,
				      TEE_ObjectHandle key);

TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
				TEE_ObjectHandle key1, TEE_ObjectHandle key2);
TEE_Result __GP11_TEE_SetOperationKey2(TEE_OperationHandle operation,
				       TEE_ObjectHandle key1,
				       TEE_ObjectHandle key2);

void TEE_CopyOperation(TEE_OperationHandle dstOperation,
		       TEE_OperationHandle srcOperation);

TEE_Result TEE_IsAlgorithmSupported(uint32_t algId, uint32_t element);

/* Cryptographic Operations API - Message Digest Functions */

void TEE_DigestUpdate(TEE_OperationHandle operation,
		      const void *chunk, size_t chunkSize);
void __GP11_TEE_DigestUpdate(TEE_OperationHandle operation,
			     const void *chunk, uint32_t chunkSize);

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, const void *chunk,
			     size_t chunkLen, void *hash, size_t *hashLen);
TEE_Result __GP11_TEE_DigestDoFinal(TEE_OperationHandle operation,
				    const void *chunk, uint32_t chunkLen,
				    void *hash, uint32_t *hashLen);

TEE_Result TEE_DigestExtract(TEE_OperationHandle operation, void *hash,
			     size_t *hashLen);

/* Cryptographic Operations API - Symmetric Cipher Functions */

void TEE_CipherInit(TEE_OperationHandle operation, const void *IV,
		    size_t IVLen);
void __GP11_TEE_CipherInit(TEE_OperationHandle operation, const void *IV,
			   uint32_t IVLen);

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation, const void *srcData,
			    size_t srcLen, void *destData, size_t *destLen);
TEE_Result __GP11_TEE_CipherUpdate(TEE_OperationHandle operation,
				   const void *srcData, uint32_t srcLen,
				   void *destData, uint32_t *destLen);

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
			     const void *srcData, size_t srcLen,
			     void *destData, size_t *destLen);
TEE_Result __GP11_TEE_CipherDoFinal(TEE_OperationHandle operation,
				    const void *srcData, uint32_t srcLen,
				    void *destData, uint32_t *destLen);

/* Cryptographic Operations API - MAC Functions */

void TEE_MACInit(TEE_OperationHandle operation, const void *IV,
		 size_t IVLen);
void __GP11_TEE_MACInit(TEE_OperationHandle operation, const void *IV,
			uint32_t IVLen);

void TEE_MACUpdate(TEE_OperationHandle operation, const void *chunk,
		   size_t chunkSize);
void __GP11_TEE_MACUpdate(TEE_OperationHandle operation, const void *chunk,
			  uint32_t chunkSize);

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
			       const void *message, size_t messageLen,
			       void *mac, size_t *macLen);
TEE_Result __GP11_TEE_MACComputeFinal(TEE_OperationHandle operation,
				      const void *message, uint32_t messageLen,
				      void *mac, uint32_t *macLen);

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
			       const void *message, size_t messageLen,
			       const void *mac, size_t macLen);
TEE_Result __GP11_TEE_MACCompareFinal(TEE_OperationHandle operation,
				      const void *message, uint32_t messageLen,
				      const void *mac, uint32_t macLen);

/* Cryptographic Operations API - Authenticated Encryption Functions */

TEE_Result TEE_AEInit(TEE_OperationHandle operation, const void *nonce,
		      size_t nonceLen, uint32_t tagLen, size_t AADLen,
		      size_t payloadLen);
TEE_Result __GP11_TEE_AEInit(TEE_OperationHandle operation, const void *nonce,
			     uint32_t nonceLen, uint32_t tagLen,
			     uint32_t AADLen, uint32_t payloadLen);

void TEE_AEUpdateAAD(TEE_OperationHandle operation, const void *AADdata,
		     size_t AADdataLen);
void __GP11_TEE_AEUpdateAAD(TEE_OperationHandle operation, const void *AADdata,
			    uint32_t AADdataLen);

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, const void *srcData,
			size_t srcLen, void *destData, size_t *destLen);
TEE_Result __GP11_TEE_AEUpdate(TEE_OperationHandle operation,
			       const void *srcData, uint32_t srcLen,
			       void *destData, uint32_t *destLen);

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t *tagLen);
TEE_Result __GP11_TEE_AEEncryptFinal(TEE_OperationHandle operation,
				     const void *srcData, uint32_t srcLen,
				     void *destData, uint32_t *destLen,
				     void *tag, uint32_t *tagLen);

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t tagLen);
TEE_Result __GP11_TEE_AEDecryptFinal(TEE_OperationHandle operation,
				     const void *srcData, uint32_t srcLen,
				     void *destData, uint32_t *destLen,
				     void *tag, uint32_t tagLen);

/* Cryptographic Operations API - Asymmetric Functions */

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
				 const TEE_Attribute *params,
				 uint32_t paramCount, const void *srcData,
				 size_t srcLen, void *destData,
				 size_t *destLen);
TEE_Result __GP11_TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
					const __GP11_TEE_Attribute *params,
					uint32_t paramCount,
					const void *srcData, uint32_t srcLen,
					void *destData, uint32_t *destLen);

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
				 const TEE_Attribute *params,
				 uint32_t paramCount, const void *srcData,
				 size_t srcLen, void *destData,
				 size_t *destLen);
TEE_Result __GP11_TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
					const __GP11_TEE_Attribute *params,
					uint32_t paramCount,
					const void *srcData, uint32_t srcLen,
					void *destData, uint32_t *destLen);

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
				    const TEE_Attribute *params,
				    uint32_t paramCount, const void *digest,
				    size_t digestLen, void *signature,
				    size_t *signatureLen);
TEE_Result __GP11_TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
					   const __GP11_TEE_Attribute *params,
					   uint32_t paramCount,
					   const void *digest,
					   uint32_t digestLen, void *signature,
					   uint32_t *signatureLen);

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
				      const TEE_Attribute *params,
				      uint32_t paramCount, const void *digest,
				      size_t digestLen, const void *signature,
				      size_t signatureLen);
TEE_Result __GP11_TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
					     const __GP11_TEE_Attribute *params,
					     uint32_t paramCount,
					     const void *digest,
					     uint32_t digestLen,
					     const void *signature,
					     uint32_t signatureLen);

/* Cryptographic Operations API - Key Derivation Functions */

void TEE_DeriveKey(TEE_OperationHandle operation,
		   const TEE_Attribute *params, uint32_t paramCount,
		   TEE_ObjectHandle derivedKey);
void __GP11_TEE_DeriveKey(TEE_OperationHandle operation,
			  const __GP11_TEE_Attribute *params,
			  uint32_t paramCount, TEE_ObjectHandle derivedKey);

/* Cryptographic Operations API - Random Number Generation Functions */

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen);
void __GP11_TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen);

/* Date & Time API */

void TEE_GetSystemTime(TEE_Time *time);

TEE_Result TEE_Wait(uint32_t timeout);

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);

TEE_Result TEE_SetTAPersistentTime(const TEE_Time *time);

void TEE_GetREETime(TEE_Time *time);

/* TEE Arithmetical API - Memory allocation and size of objects */

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits);
uint32_t __GP11_TEE_BigIntFMMSizeInU32(uint32_t modulusSizeInBits);

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits);
uint32_t __GP11_TEE_BigIntFMMContextSizeInU32(uint32_t modulusSizeInBits);

/* TEE Arithmetical API - Initialization functions */

void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len);
void __GP11_TEE_BigIntInit(TEE_BigInt *bigInt, uint32_t len);

void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
			      const TEE_BigInt *modulus);
void __GP11_TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context,
				     uint32_t len, const TEE_BigInt *modulus);

TEE_Result TEE_BigIntInitFMMContext1(TEE_BigIntFMMContext *context,
				     size_t len, const TEE_BigInt *modulus);

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len);
void __GP11_TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, uint32_t len);

/* TEE Arithmetical API - Converter functions */

TEE_Result TEE_BigIntConvertFromOctetString(TEE_BigInt *dest,
					    const uint8_t *buffer,
					    size_t bufferLen,
					    int32_t sign);
TEE_Result __GP11_TEE_BigIntConvertFromOctetString(TEE_BigInt *dest,
						   const uint8_t *buffer,
						   uint32_t bufferLen,
						   int32_t sign);

TEE_Result TEE_BigIntConvertToOctetString(uint8_t *buffer, size_t *bufferLen,
					  const TEE_BigInt *bigInt);
TEE_Result __GP11_TEE_BigIntConvertToOctetString(uint8_t *buffer,
						 uint32_t *bufferLen,
						 const TEE_BigInt *bigInt);

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal);

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, const TEE_BigInt *src);

/* TEE Arithmetical API - Logical operations */

int32_t TEE_BigIntCmp(const TEE_BigInt *op1, const TEE_BigInt *op2);

int32_t TEE_BigIntCmpS32(const TEE_BigInt *op, int32_t shortVal);

void TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op,
			  size_t bits);
void __GP11_TEE_BigIntShiftRight(TEE_BigInt *dest, const TEE_BigInt *op,
				 uint32_t bits);

bool TEE_BigIntGetBit(const TEE_BigInt *src, uint32_t bitIndex);

uint32_t TEE_BigIntGetBitCount(const TEE_BigInt *src);

TEE_Result TEE_BigIntSetBit(TEE_BigInt *op, uint32_t bitIndex, bool value);

TEE_Result TEE_BigIntAssign(TEE_BigInt *dest, const TEE_BigInt *src);

TEE_Result TEE_BigIntAbs(TEE_BigInt *dest, const TEE_BigInt *src);

void TEE_BigIntAdd(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2);

void TEE_BigIntSub(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2);

void TEE_BigIntNeg(TEE_BigInt *dest, const TEE_BigInt *op);

void TEE_BigIntMul(TEE_BigInt *dest, const TEE_BigInt *op1,
		   const TEE_BigInt *op2);

void TEE_BigIntSquare(TEE_BigInt *dest, const TEE_BigInt *op);

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
		   const TEE_BigInt *op1, const TEE_BigInt *op2);

/* TEE Arithmetical API - Modular arithmetic operations */

void TEE_BigIntMod(TEE_BigInt *dest, const TEE_BigInt *op,
		   const TEE_BigInt *n);

void TEE_BigIntAddMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n);

void TEE_BigIntSubMod(TEE_BigInt *dest, const TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n);

void TEE_BigIntMulMod(TEE_BigInt *dest, const  TEE_BigInt *op1,
		      const TEE_BigInt *op2, const TEE_BigInt *n);

void TEE_BigIntSquareMod(TEE_BigInt *dest, const TEE_BigInt *op,
			 const TEE_BigInt *n);

void TEE_BigIntInvMod(TEE_BigInt *dest, const TEE_BigInt *op,
		      const TEE_BigInt *n);

TEE_Result TEE_BigIntExpMod(TEE_BigInt *dest, const TEE_BigInt *op1,
			    const TEE_BigInt *op2, const TEE_BigInt *n,
			    const TEE_BigIntFMMContext *context);

/* TEE Arithmetical API - Other arithmetic operations */

bool TEE_BigIntRelativePrime(const TEE_BigInt *op1, const TEE_BigInt *op2);

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
				  TEE_BigInt *v, const TEE_BigInt *op1,
				  const TEE_BigInt *op2);

int32_t TEE_BigIntIsProbablePrime(const TEE_BigInt *op,
				  uint32_t confidenceLevel);

/* TEE Arithmetical API - Fast modular multiplication operations */

void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest, const TEE_BigInt *src,
			    const TEE_BigInt *n,
			    const TEE_BigIntFMMContext *context);

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest, const TEE_BigIntFMM *src,
			      const TEE_BigInt *n,
			      const TEE_BigIntFMMContext *context);

void TEE_BigIntFMMConvertToBigInt(TEE_BigInt *dest, const TEE_BigIntFMM *src,
				  const TEE_BigInt *n,
				  const TEE_BigIntFMMContext *context);

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest, const TEE_BigIntFMM *op1,
			  const TEE_BigIntFMM *op2, const TEE_BigInt *n,
			  const TEE_BigIntFMMContext *context);

#define TA_EXPORT

/*
 * TA Interface
 *
 * Each Trusted Application must provide the Implementation with a number
 * of functions, collectively called the “TA interface”. These functions
 * are the entry points called by the Trusted Core Framework to create the
 * instance, notify the instance that a new client is connecting, notify
 * the instance when the client invokes a command, etc.
 *
 * Trusted Application Entry Points:
 */

/*
 * The function TA_CreateEntryPoint is the Trusted Application's
 * constructor, which the Framework calls when it creates a new instance of
 * the Trusted Application. To register instance data, the implementation
 * of this constructor can use either global variables or the function
 * TEE_InstanceSetData.
 *
 * Return Value:
 * - TEE_SUCCESS: if the instance is successfully created, the function
 *   must return TEE_SUCCESS.
 * - Any other value: if any other code is returned the instance is not
 *   created, and no other entry points of this instance will be called.
 *   The Framework MUST reclaim all resources and dereference all objects
 *   related to the creation of the instance.
 *
 *   If this entry point was called as a result of a client opening a
 *   session, the error code is returned to the client and the session is
 *   not opened.
 */
TEE_Result TA_EXPORT TA_CreateEntryPoint(void);

/*
 * The function TA_DestroyEntryPoint is the Trusted Application‟s
 * destructor, which the Framework calls when the instance is being
 * destroyed.
 *
 * When the function TA_DestroyEntryPoint is called, the Framework
 * guarantees that no client session is currently open. Once the call to
 * TA_DestroyEntryPoint has been completed, no other entry point of this
 * instance will ever be called.
 *
 * Note that when this function is called, all resources opened by the
 * instance are still available. It is only after the function returns that
 * the Implementation MUST start automatically reclaiming resources left
 * opened.
 *
 * Return Value:
 * This function can return no success or error code. After this function
 * returns the Implementation MUST consider the instance destroyed and
 * reclaims all resources left open by the instance.
 */
void TA_EXPORT TA_DestroyEntryPoint(void);

/*
 * The Framework calls the function TA_OpenSessionEntryPoint when a client
 * requests to open a session with the Trusted Application. The open
 * session request may result in a new Trusted Application instance being
 * created as defined in section 4.5.
 *
 * The client can specify parameters in an open operation which are passed
 * to the Trusted Application instance in the arguments paramTypes and
 * params. These arguments can also be used by the Trusted Application
 * instance to transfer response data back to the client. See section 4.3.6
 * for a specification of how to handle the operation parameters.
 *
 * If this function returns TEE_SUCCESS, the client is connected to a
 * Trusted Application instance and can invoke Trusted Application
 * commands. When the client disconnects, the Framework will eventually
 * call the TA_CloseSessionEntryPoint entry point.
 *
 * If the function returns any error, the Framework rejects the connection
 * and returns the error code and the current content of the parameters the
 * client. The return origin is then set to TEE_ORIGIN_TRUSTED_APP.
 *
 * The Trusted Application instance can register a session data pointer by
 * setting *psessionContext. The value of this pointer is not interpreted
 * by the Framework, and is simply passed back to other TA_ functions
 * within this session. Note that *sessionContext may be set with a pointer
 * to a memory allocated by the Trusted Application instance or with
 * anything else, like an integer, a handle etc. The Framework will not
 * automatically free *sessionContext when the session is closed; the
 * Trusted Application instance is responsible for freeing memory if
 * required.
 *
 * During the call to TA_OpenSessionEntryPoint the client may request to
 * cancel the operation. See section 4.10 for more details on
 * cancellations. If the call to TA_OpenSessionEntryPoint returns
 * TEE_SUCCESS, the client must consider the session as successfully opened
 * and explicitly close it if necessary.
 *
 * Parameters:
 * - paramTypes: the types of the four parameters.
 * - params: a pointer to an array of four parameters.
 * - sessionContext: A pointer to a variable that can be filled by the
 *   Trusted Application instance with an opaque void* data pointer
 *
 * Return Value:
 * - TEE_SUCCESS if the session is successfully opened.
 * - Any other value if the session could not be open.
 *   o The error code may be one of the pre-defined codes, or may be a new
 *     error code defined by the Trusted Application implementation itself.
 */
TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
					      TEE_Param params[TEE_NUM_PARAMS],
					      void **sessionContext);
TEE_Result TA_EXPORT
__GP11_TA_OpenSessionEntryPoint(uint32_t paramTypes,
				__GP11_TEE_Param params[TEE_NUM_PARAMS],
				void **sessionContext);

/*
 * The Framework calls this function to close a client session. During the
 * call to this function the implementation can use any session functions.
 *
 * The Trusted Application implementation is responsible for freeing any
 * resources consumed by the session being closed. Note that the Trusted
 * Application cannot refuse to close a session, but can hold the closing
 * until it returns from TA_CloseSessionEntryPoint. This is why this
 * function cannot return an error code.
 *
 * Parameters:
 * - sessionContext: The value of the void* opaque data pointer set by the
 *   Trusted Application in the function TA_OpenSessionEntryPoint for this
 *   session.
 */
void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext);

/*
 * The Framework calls this function when the client invokes a command
 * within the given session.
 *
 * The Trusted Application can access the parameters sent by the client
 * through the paramTypes and params arguments. It can also use these
 * arguments to transfer response data back to the client.
 *
 * During the call to TA_InvokeCommandEntryPoint the client may request to
 * cancel the operation.
 *
 * A command is always invoked within the context of a client session.
 * Thus, any session function  can be called by the command implementation.
 *
 * Parameter:
 * - sessionContext: The value of the void* opaque data pointer set by the
 *   Trusted Application in the function TA_OpenSessionEntryPoint.
 * - commandID: A Trusted Application-specific code that identifies the
 *   command to be invoked.
 * - paramTypes: the types of the four parameters.
 * - params: a pointer to an array of four parameters.
 *
 * Return Value:
 * - TEE_SUCCESS: if the command is successfully executed, the function
 *   must return this value.
 * - Any other value: if the invocation of the command fails for any
 *   reason.
 *   o The error code may be one of the pre-defined codes, or may be a new
 *     error code defined by the Trusted Application implementation itself.
 */

TEE_Result TA_EXPORT
TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
			   uint32_t paramTypes,
			   TEE_Param params[TEE_NUM_PARAMS]);
TEE_Result TA_EXPORT
__GP11_TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
				  uint32_t paramTypes,
				  __GP11_TEE_Param params[TEE_NUM_PARAMS]);

/*
 * Matching Client Functions <--> TA Functions
 *
 * TEE_OpenSession or TEE_OpenTASession:
 * If a new Trusted Application instance is needed to handle the session,
 * TA_CreateEntryPoint is called.
 * Then, TA_OpenSessionEntryPoint is called.
 *
 * TEE_InvokeCommand or TEE_InvokeTACommand:
 * TA_InvokeCommandEntryPoint is called.
 *
 * TEE_CloseSession or TEE_CloseTASession:
 * TA_CloseSessionEntryPoint is called.
 * For a multi-instance TA or for a single-instance, non keep-alive TA, if
 * the session closed was the last session on the instance, then
 * TA_DestroyEntryPoint is called. Otherwise, the instance is kept until
 * the TEE shuts down.
 */

#include <tee_api_compat.h>

#endif /*TEE_INTERNAL_API_H*/
