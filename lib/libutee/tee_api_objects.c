// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdlib.h>
#include <string.h>

#include <tee_api.h>
#include <utee_syscalls.h>
#include "tee_api_private.h"

#define TEE_USAGE_DEFAULT   0xffffffff

void __utee_from_attr(struct utee_attribute *ua, const TEE_Attribute *attrs,
			uint32_t attr_count)
{
	size_t n;

	for (n = 0; n < attr_count; n++) {
		ua[n].attribute_id = attrs[n].attributeID;
		if (attrs[n].attributeID & TEE_ATTR_FLAG_VALUE) {
			ua[n].a = attrs[n].content.value.a;
			ua[n].b = attrs[n].content.value.b;
		} else {
			ua[n].a = (uintptr_t)attrs[n].content.ref.buffer;
			ua[n].b = attrs[n].content.ref.length;
		}
	}
}

/* Data and Key Storage API  - Generic Object Functions */
/*
 * Use of this function is deprecated
 * new code SHOULD use the TEE_GetObjectInfo1 function instead
 * These functions will be removed at some future major revision of
 * this specification
 */
void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo)
{
	TEE_Result res;

	res = _utee_cryp_obj_get_info((unsigned long)object, objectInfo);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if (objectInfo->objectType == TEE_TYPE_CORRUPTED_OBJECT) {
		objectInfo->keySize = 0;
		objectInfo->maxKeySize = 0;
		objectInfo->objectUsage = 0;
		objectInfo->dataSize = 0;
		objectInfo->dataPosition = 0;
		objectInfo->handleFlags = 0;
	}
}

TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo)
{
	TEE_Result res;

	res = _utee_cryp_obj_get_info((unsigned long)object, objectInfo);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

/*
 * Use of this function is deprecated
 * new code SHOULD use the TEE_RestrictObjectUsage1 function instead
 * These functions will be removed at some future major revision of
 * this specification
 */
void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage)
{
	TEE_Result res;
	TEE_ObjectInfo objectInfo;

	res = _utee_cryp_obj_get_info((unsigned long)object, &objectInfo);
	if (objectInfo.objectType == TEE_TYPE_CORRUPTED_OBJECT)
		return;

	res = TEE_RestrictObjectUsage1(object, objectUsage);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_RestrictObjectUsage1(TEE_ObjectHandle object, uint32_t objectUsage)
{
	TEE_Result res;

	res = _utee_cryp_obj_restrict_usage((unsigned long)object,
					    objectUsage);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					uint32_t attributeID, void *buffer,
					uint32_t *size)
{
	TEE_Result res;
	TEE_ObjectInfo info;
	uint64_t sz;

	__utee_check_inout_annotation(size, sizeof(*size));

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		goto exit;

	/* This function only supports reference attributes */
	if ((attributeID & TEE_ATTR_FLAG_VALUE)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	sz = *size;
	res = _utee_cryp_obj_get_attr((unsigned long)object, attributeID,
				      buffer, &sz);
	*size = sz;

exit:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_SHORT_BUFFER &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
				       uint32_t attributeID, uint32_t *a,
				       uint32_t *b)
{
	TEE_Result res;
	TEE_ObjectInfo info;
	uint32_t buf[2];
	uint64_t size = sizeof(buf);

	if (a)
		__utee_check_out_annotation(a, sizeof(*a));
	if (b)
		__utee_check_out_annotation(b, sizeof(*b));

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		goto exit;

	/* This function only supports value attributes */
	if (!(attributeID & TEE_ATTR_FLAG_VALUE)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	res = _utee_cryp_obj_get_attr((unsigned long)object, attributeID, buf,
				      &size);

exit:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	if (size != sizeof(buf))
		TEE_Panic(0);

	if (res == TEE_SUCCESS) {
		if (a)
			*a = buf[0];
		if (b)
			*b = buf[1];
	}

	return res;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL)
		return;

	res = _utee_cryp_obj_close((unsigned long)object);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

/* Data and Key Storage API  - Transient Object Functions */

TEE_Result TEE_AllocateTransientObject(TEE_ObjectType objectType,
				       uint32_t maxKeySize,
				       TEE_ObjectHandle *object)
{
	TEE_Result res;
	uint32_t obj;

	__utee_check_out_annotation(object, sizeof(*object));

	res = _utee_cryp_obj_alloc(objectType, maxKeySize, &obj);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_NOT_SUPPORTED)
		TEE_Panic(res);

	if (res == TEE_SUCCESS)
		*object = (TEE_ObjectHandle)(uintptr_t)obj;

	return res;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	TEE_Result res;
	TEE_ObjectInfo info;

	if (object == TEE_HANDLE_NULL)
		return;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if ((info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	res = _utee_cryp_obj_close((unsigned long)object);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	TEE_Result res;
	TEE_ObjectInfo info;

	if (object == TEE_HANDLE_NULL)
		return;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if ((info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	res = _utee_cryp_obj_reset((unsigned long)object);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       const TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	TEE_Result res;
	TEE_ObjectInfo info;
	struct utee_attribute ua[attrCount];

	__utee_check_attr_in_annotation(attrs, attrCount);

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	/* Must be a transient object */
	if ((info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	/* Must not be initialized already */
	if ((info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		TEE_Panic(0);

	__utee_from_attr(ua, attrs, attrCount);
	res = _utee_cryp_obj_populate((unsigned long)object, ua, attrCount);
	if (res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);
	return res;
}

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID,
			  const void *buffer, uint32_t length)
{
	__utee_check_out_annotation(attr, sizeof(*attr));

	if ((attributeID & TEE_ATTR_FLAG_VALUE) != 0)
		TEE_Panic(0);
	attr->attributeID = attributeID;
	attr->content.ref.buffer = (void *)buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute *attr, uint32_t attributeID,
			    uint32_t a, uint32_t b)
{
	__utee_check_out_annotation(attr, sizeof(*attr));

	if ((attributeID & TEE_ATTR_FLAG_VALUE) == 0)
		TEE_Panic(0);
	attr->attributeID = attributeID;
	attr->content.value.a = a;
	attr->content.value.b = b;
}

/*
 * Use of this function is deprecated
 * new code SHOULD use the TEE_CopyObjectAttributes1 function instead
 * These functions will be removed at some future major revision of
 * this specification
 */
void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject,
			      TEE_ObjectHandle srcObject)
{
	TEE_Result res;
	TEE_ObjectInfo src_info;

	res = _utee_cryp_obj_get_info((unsigned long)srcObject, &src_info);
	if (src_info.objectType == TEE_TYPE_CORRUPTED_OBJECT)
		return;

	res = TEE_CopyObjectAttributes1(destObject, srcObject);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
			      TEE_ObjectHandle srcObject)
{
	TEE_Result res;
	TEE_ObjectInfo dst_info;
	TEE_ObjectInfo src_info;

	res = _utee_cryp_obj_get_info((unsigned long)destObject, &dst_info);
	if (res != TEE_SUCCESS)
		goto exit;

	res = _utee_cryp_obj_get_info((unsigned long)srcObject, &src_info);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!(src_info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(0);

	if ((dst_info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT))
		TEE_Panic(0);

	if ((dst_info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(0);

	res = _utee_cryp_obj_copy((unsigned long)destObject,
				  (unsigned long)srcObject);

exit:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
			   const TEE_Attribute *params, uint32_t paramCount)
{
	TEE_Result res;
	struct utee_attribute ua[paramCount];

	__utee_check_attr_in_annotation(params, paramCount);

	__utee_from_attr(ua, params, paramCount);
	res = _utee_cryp_obj_generate_key((unsigned long)object, keySize,
					  ua, paramCount);

	if (res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);

	return res;
}

/* Data and Key Storage API  - Persistent Object Functions */

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void *objectID,
				    uint32_t objectIDLen, uint32_t flags,
				    TEE_ObjectHandle *object)
{
	TEE_Result res;
	uint32_t obj;

	if (!objectID) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	__utee_check_out_annotation(object, sizeof(*object));

	res = _utee_storage_obj_open(storageID, objectID, objectIDLen, flags,
				     &obj);
	if (res == TEE_SUCCESS)
		*object = (TEE_ObjectHandle)(uintptr_t)obj;

exit:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_ACCESS_CONFLICT &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	if (res != TEE_SUCCESS)
		*object = TEE_HANDLE_NULL;

	return res;
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, const void *objectID,
				      uint32_t objectIDLen, uint32_t flags,
				      TEE_ObjectHandle attributes,
				      const void *initialData,
				      uint32_t initialDataLen,
				      TEE_ObjectHandle *object)
{
	TEE_Result res;
	uint32_t obj;

	if (!objectID) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto exit;
	}

	__utee_check_out_annotation(object, sizeof(*object));

	res = _utee_storage_obj_create(storageID, objectID, objectIDLen, flags,
				       (unsigned long)attributes, initialData,
				       initialDataLen, &obj);

	if (res == TEE_SUCCESS)
		*object = (TEE_ObjectHandle)(uintptr_t)obj;

exit:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_ACCESS_CONFLICT &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_STORAGE_NO_SPACE &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	if (res != TEE_SUCCESS)
		*object = TEE_HANDLE_NULL;

	return res;
}

/*
 * Use of this function is deprecated
 * new code SHOULD use the TEE_CloseAndDeletePersistentObject1 function instead
 * These functions will be removed at some future major revision of
 * this specification
 */
void TEE_CloseAndDeletePersistentObject(TEE_ObjectHandle object)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL)
		return;

	res = TEE_CloseAndDeletePersistentObject1(object);

	if (res != TEE_SUCCESS)
		TEE_Panic(0);
}

TEE_Result TEE_CloseAndDeletePersistentObject1(TEE_ObjectHandle object)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL)
		return TEE_SUCCESS;

	res = _utee_storage_obj_del((unsigned long)object);

	if (res != TEE_SUCCESS && res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}


TEE_Result TEE_RenamePersistentObject(TEE_ObjectHandle object,
				      const void *newObjectID,
				      uint32_t newObjectIDLen)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	res = _utee_storage_obj_rename((unsigned long)object, newObjectID,
				       newObjectIDLen);

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ACCESS_CONFLICT &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_AllocatePersistentObjectEnumerator(TEE_ObjectEnumHandle *
						  objectEnumerator)
{
	TEE_Result res;
	uint32_t oe;

	__utee_check_out_annotation(objectEnumerator,
				    sizeof(*objectEnumerator));

	res = _utee_storage_alloc_enum(&oe);

	if (res != TEE_SUCCESS)
		oe = TEE_HANDLE_NULL;

	*objectEnumerator = (TEE_ObjectEnumHandle)(uintptr_t)oe;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ACCESS_CONFLICT)
		TEE_Panic(res);

	return res;
}

void TEE_FreePersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	TEE_Result res;

	if (objectEnumerator == TEE_HANDLE_NULL)
		return;

	res = _utee_storage_free_enum((unsigned long)objectEnumerator);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

void TEE_ResetPersistentObjectEnumerator(TEE_ObjectEnumHandle objectEnumerator)
{
	TEE_Result res;

	if (objectEnumerator == TEE_HANDLE_NULL)
		return;

	res = _utee_storage_reset_enum((unsigned long)objectEnumerator);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_StartPersistentObjectEnumerator(TEE_ObjectEnumHandle
					       objectEnumerator,
					       uint32_t storageID)
{
	TEE_Result res;

	res = _utee_storage_start_enum((unsigned long)objectEnumerator,
				       storageID);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				       TEE_ObjectInfo *objectInfo,
				       void *objectID, uint32_t *objectIDLen)
{
	TEE_Result res;
	uint64_t len;
	TEE_ObjectInfo local_info;
	TEE_ObjectInfo *pt_info;

	if (objectInfo)
		__utee_check_out_annotation(objectInfo, sizeof(*objectInfo));
	__utee_check_out_annotation(objectIDLen, sizeof(*objectIDLen));

	if (!objectID) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (objectInfo)
		pt_info = objectInfo;
	else
		pt_info = &local_info;
	len = *objectIDLen;
	res = _utee_storage_next_enum((unsigned long)objectEnumerator,
				      pt_info, objectID, &len);
	*objectIDLen = len;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

/* Data and Key Storage API  - Data Stream Access Functions */

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer,
			      uint32_t size, uint32_t *count)
{
	TEE_Result res;
	uint64_t cnt64;

	if (object == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	__utee_check_out_annotation(count, sizeof(*count));

	cnt64 = *count;
	res = _utee_storage_obj_read((unsigned long)object, buffer, size,
				     &cnt64);
	*count = cnt64;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void *buffer,
			       uint32_t size)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (size > TEE_DATA_MAX_POSITION) {
		res = TEE_ERROR_OVERFLOW;
		goto out;
	}

	res = _utee_storage_obj_write((unsigned long)object, buffer, size);

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_STORAGE_NO_SPACE &&
	    res != TEE_ERROR_OVERFLOW &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, uint32_t size)
{
	TEE_Result res;

	if (object == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = _utee_storage_obj_trunc((unsigned long)object, size);

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_STORAGE_NO_SPACE &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset,
			      TEE_Whence whence)
{
	TEE_Result res;
	TEE_ObjectInfo info;

	if (object == TEE_HANDLE_NULL) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		goto out;

	switch (whence) {
	case TEE_DATA_SEEK_SET:
		if (offset > 0 && (uint32_t)offset > TEE_DATA_MAX_POSITION) {
			res = TEE_ERROR_OVERFLOW;
			goto out;
		}
		break;
	case TEE_DATA_SEEK_CUR:
		if (offset > 0 &&
		    ((uint32_t)offset + info.dataPosition >
		     TEE_DATA_MAX_POSITION ||
		     (uint32_t)offset + info.dataPosition <
		     info.dataPosition)) {
			res = TEE_ERROR_OVERFLOW;
			goto out;
		}
		break;
	case TEE_DATA_SEEK_END:
		if (offset > 0 &&
		    ((uint32_t)offset + info.dataSize > TEE_DATA_MAX_POSITION ||
		     (uint32_t)offset + info.dataSize < info.dataSize)) {
			res = TEE_ERROR_OVERFLOW;
			goto out;
		}
		break;
	default:
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	res = _utee_storage_obj_seek((unsigned long)object, offset, whence);

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_OVERFLOW &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}
