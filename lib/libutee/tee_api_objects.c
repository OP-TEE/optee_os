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

void __utee_from_gp11_attr(struct utee_attribute *ua,
			   const __GP11_TEE_Attribute *attrs,
			   uint32_t attr_count)
{
	size_t n = 0;

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
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if (info.obj_type == TEE_TYPE_CORRUPTED_OBJECT) {
		objectInfo->objectSize = 0;
		objectInfo->maxObjectSize = 0;
		objectInfo->objectUsage = 0;
		objectInfo->dataSize = 0;
		objectInfo->dataPosition = 0;
		objectInfo->handleFlags = 0;
	} else {
		objectInfo->objectType = info.obj_type;
		objectInfo->objectSize = info.obj_size;
		objectInfo->maxObjectSize = info.max_obj_size;
		objectInfo->objectUsage = info.obj_usage;
		objectInfo->dataSize = info.data_size;
		objectInfo->dataPosition = info.data_pos;
		objectInfo->handleFlags = info.handle_flags;
	}
}

void __GP11_TEE_GetObjectInfo(TEE_ObjectHandle object,
			      __GP11_TEE_ObjectInfo *objectInfo)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);

	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if (info.obj_type == TEE_TYPE_CORRUPTED_OBJECT) {
		objectInfo->keySize = 0;
		objectInfo->maxKeySize = 0;
		objectInfo->objectUsage = 0;
		objectInfo->dataSize = 0;
		objectInfo->dataPosition = 0;
		objectInfo->handleFlags = 0;
	} else {
		objectInfo->objectType = info.obj_type;
		objectInfo->keySize = info.obj_size;
		objectInfo->maxKeySize = info.max_obj_size;
		objectInfo->objectUsage = info.obj_usage;
		objectInfo->dataSize = info.data_size;
		objectInfo->dataPosition = info.data_pos;
		objectInfo->handleFlags = info.handle_flags;
	}
}

TEE_Result TEE_GetObjectInfo1(TEE_ObjectHandle object,
			      TEE_ObjectInfo *objectInfo)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	objectInfo->objectType = info.obj_type;
	objectInfo->objectSize = info.obj_size;
	objectInfo->maxObjectSize = info.max_obj_size;
	objectInfo->objectUsage = info.obj_usage;
	objectInfo->dataSize = info.data_size;
	objectInfo->dataPosition = info.data_pos;
	objectInfo->handleFlags = info.handle_flags;

	return res;
}

TEE_Result __GP11_TEE_GetObjectInfo1(TEE_ObjectHandle object,
				     __GP11_TEE_ObjectInfo *objectInfo)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	objectInfo->objectType = info.obj_type;
	objectInfo->keySize = info.obj_size;
	objectInfo->maxKeySize = info.max_obj_size;
	objectInfo->objectUsage = info.obj_usage;
	objectInfo->dataSize = info.data_size;
	objectInfo->dataPosition = info.data_pos;
	objectInfo->handleFlags = info.handle_flags;

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
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (info.obj_type == TEE_TYPE_CORRUPTED_OBJECT)
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
					size_t *size)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;
	uint64_t sz = 0;

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

TEE_Result __GP11_TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
					       uint32_t attributeID,
					       void *buffer, uint32_t *size)
{
	TEE_Result res = TEE_SUCCESS;
	size_t l = 0;

	__utee_check_inout_annotation(size, sizeof(*size));
	l = *size;
	res = TEE_GetObjectBufferAttribute(object, attributeID, buffer, &l);
	*size = l;
	return res;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
				       uint32_t attributeID, uint32_t *a,
				       uint32_t *b)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;
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
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object)
{
	if (objectType == TEE_TYPE_DATA)
		return TEE_ERROR_NOT_SUPPORTED;

	return __GP11_TEE_AllocateTransientObject(objectType, maxObjectSize,
						  object);
}

TEE_Result __GP11_TEE_AllocateTransientObject(TEE_ObjectType objectType,
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
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	if (object == TEE_HANDLE_NULL)
		return;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if ((info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	res = _utee_cryp_obj_close((unsigned long)object);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	if (object == TEE_HANDLE_NULL)
		return;

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	if ((info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	res = _utee_cryp_obj_reset((unsigned long)object);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       const TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	struct utee_attribute ua[attrCount];
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	__utee_check_attr_in_annotation(attrs, attrCount);

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	/* Must be a transient object */
	if ((info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	/* Must not be initialized already */
	if ((info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		TEE_Panic(0);

	__utee_from_attr(ua, attrs, attrCount);
	res = _utee_cryp_obj_populate((unsigned long)object, ua, attrCount);
	if (res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);
	return res;
}

TEE_Result __GP11_TEE_PopulateTransientObject(TEE_ObjectHandle object,
					      const __GP11_TEE_Attribute *attrs,
					      uint32_t attrCount)
{
	struct utee_attribute ua[attrCount];
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

	__utee_check_gp11_attr_in_annotation(attrs, attrCount);

	res = _utee_cryp_obj_get_info((unsigned long)object, &info);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);

	/* Must be a transient object */
	if ((info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0)
		TEE_Panic(0);

	/* Must not be initialized already */
	if ((info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED) != 0)
		TEE_Panic(0);

	__utee_from_gp11_attr(ua, attrs, attrCount);
	res = _utee_cryp_obj_populate((unsigned long)object, ua, attrCount);
	if (res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);
	return res;
}

void TEE_InitRefAttribute(TEE_Attribute *attr, uint32_t attributeID,
			  const void *buffer, size_t length)
{
	__utee_check_out_annotation(attr, sizeof(*attr));

	if ((attributeID & TEE_ATTR_FLAG_VALUE) != 0)
		TEE_Panic(0);
	attr->attributeID = attributeID;
	attr->content.ref.buffer = (void *)buffer;
	attr->content.ref.length = length;
}

void __GP11_TEE_InitRefAttribute(__GP11_TEE_Attribute *attr,
				 uint32_t attributeID,
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

void __GP11_TEE_InitValueAttribute(__GP11_TEE_Attribute *attr,
				   uint32_t attributeID,
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
	struct utee_object_info src_info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)srcObject, &src_info);
	if (src_info.obj_type == TEE_TYPE_CORRUPTED_OBJECT)
		return;

	res = TEE_CopyObjectAttributes1(destObject, srcObject);
	if (res != TEE_SUCCESS)
		TEE_Panic(res);
}

TEE_Result TEE_CopyObjectAttributes1(TEE_ObjectHandle destObject,
			      TEE_ObjectHandle srcObject)
{
	struct utee_object_info dst_info = { };
	struct utee_object_info src_info = { };
	TEE_Result res = TEE_SUCCESS;

	res = _utee_cryp_obj_get_info((unsigned long)destObject, &dst_info);
	if (res != TEE_SUCCESS)
		goto exit;

	res = _utee_cryp_obj_get_info((unsigned long)srcObject, &src_info);
	if (res != TEE_SUCCESS)
		goto exit;

	if (!(src_info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED))
		TEE_Panic(0);

	if ((dst_info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT))
		TEE_Panic(0);

	if ((dst_info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED))
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

TEE_Result __GP11_TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
				  const __GP11_TEE_Attribute *params,
				  uint32_t paramCount)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_attribute ua[paramCount];

	__utee_check_gp11_attr_in_annotation(params, paramCount);

	__utee_from_gp11_attr(ua, params, paramCount);
	res = _utee_cryp_obj_generate_key((unsigned long)object, keySize,
					  ua, paramCount);

	if (res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS)
		TEE_Panic(res);

	return res;
}

/* Data and Key Storage API  - Persistent Object Functions */

TEE_Result TEE_OpenPersistentObject(uint32_t storageID, const void *objectID,
				    size_t objectIDLen, uint32_t flags,
				    TEE_ObjectHandle *object)
{
	TEE_Result res;
	uint32_t obj;

	__utee_check_out_annotation(object, sizeof(*object));

	res = _utee_storage_obj_open(storageID, objectID, objectIDLen, flags,
				     &obj);
	if (res == TEE_SUCCESS)
		*object = (TEE_ObjectHandle)(uintptr_t)obj;

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

TEE_Result __GP11_TEE_OpenPersistentObject(uint32_t storageID,
					   const void *objectID,
					   uint32_t objectIDLen, uint32_t flags,
					   TEE_ObjectHandle *object)
{
	return TEE_OpenPersistentObject(storageID, objectID, objectIDLen,
					flags, object);
}

TEE_Result TEE_CreatePersistentObject(uint32_t storageID, const void *objectID,
				      size_t objectIDLen, uint32_t flags,
				      TEE_ObjectHandle attributes,
				      const void *initialData,
				      size_t initialDataLen,
				      TEE_ObjectHandle *object)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t *obj_ptr = NULL;
	uint32_t obj = 0;

	if (object) {
		__utee_check_out_annotation(object, sizeof(*object));
		obj_ptr = &obj;
	}

	res = _utee_storage_obj_create(storageID, objectID, objectIDLen, flags,
				       (unsigned long)attributes, initialData,
				       initialDataLen, obj_ptr);

	if (res == TEE_SUCCESS && object)
		*object = (TEE_ObjectHandle)(uintptr_t)obj;

	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_ACCESS_CONFLICT &&
	    res != TEE_ERROR_OUT_OF_MEMORY &&
	    res != TEE_ERROR_STORAGE_NO_SPACE &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	if (res != TEE_SUCCESS && object)
		*object = TEE_HANDLE_NULL;

	return res;
}

TEE_Result __GP11_TEE_CreatePersistentObject(uint32_t storageID,
					     const void *objectID,
					     uint32_t objectIDLen,
					     uint32_t flags,
					     TEE_ObjectHandle attributes,
					     const void *initialData,
					     uint32_t initialDataLen,
					     TEE_ObjectHandle *object)
{
	__utee_check_out_annotation(object, sizeof(*object));

	return TEE_CreatePersistentObject(storageID, objectID, objectIDLen,
					  flags, attributes, initialData,
					  initialDataLen, object);
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
				      size_t newObjectIDLen)
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

TEE_Result __GP11_TEE_RenamePersistentObject(TEE_ObjectHandle object,
					     const void *newObjectID,
					     uint32_t newObjectIDLen)
{
	return TEE_RenamePersistentObject(object, newObjectID, newObjectIDLen);
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
				       void *objectID, size_t *objectIDLen)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;
	uint64_t len = 0;

	if (objectInfo)
		__utee_check_out_annotation(objectInfo, sizeof(*objectInfo));
	__utee_check_out_annotation(objectIDLen, sizeof(*objectIDLen));

	if (!objectID) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	len = *objectIDLen;
	res = _utee_storage_next_enum((unsigned long)objectEnumerator,
				      &info, objectID, &len);
	if (objectInfo) {
		objectInfo->objectType = info.obj_type;
		objectInfo->objectSize = info.obj_size;
		objectInfo->maxObjectSize = info.max_obj_size;
		objectInfo->objectUsage = info.obj_usage;
		objectInfo->dataSize = info.data_size;
		objectInfo->dataPosition = info.data_pos;
		objectInfo->handleFlags = info.handle_flags;
	}
	*objectIDLen = len;

out:
	if (res != TEE_SUCCESS &&
	    res != TEE_ERROR_ITEM_NOT_FOUND &&
	    res != TEE_ERROR_CORRUPT_OBJECT &&
	    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(res);

	return res;
}

TEE_Result
__GP11_TEE_GetNextPersistentObject(TEE_ObjectEnumHandle objectEnumerator,
				   __GP11_TEE_ObjectInfo *objectInfo,
				   void *objectID, uint32_t *objectIDLen)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;
	uint64_t len = 0;

	if (objectInfo)
		__utee_check_out_annotation(objectInfo, sizeof(*objectInfo));
	__utee_check_out_annotation(objectIDLen, sizeof(*objectIDLen));

	if (!objectID) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	len = *objectIDLen;
	res = _utee_storage_next_enum((unsigned long)objectEnumerator,
				      &info, objectID, &len);
	if (objectInfo) {
		objectInfo->objectType = info.obj_type;
		objectInfo->keySize = info.obj_size;
		objectInfo->maxKeySize = info.max_obj_size;
		objectInfo->objectUsage = info.obj_usage;
		objectInfo->dataSize = info.data_size;
		objectInfo->dataPosition = info.data_pos;
		objectInfo->handleFlags = info.handle_flags;
	}
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
			      size_t size, size_t *count)
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

TEE_Result __GP11_TEE_ReadObjectData(TEE_ObjectHandle object, void *buffer,
				     uint32_t size, uint32_t *count)
{
	TEE_Result res = TEE_SUCCESS;
	size_t cnt = 0;

	__utee_check_out_annotation(count, sizeof(*count));
	cnt = *count;
	res = TEE_ReadObjectData(object, buffer, size, &cnt);
	*count = cnt;
	return res;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object, const void *buffer,
			       size_t size)
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

TEE_Result __GP11_TEE_WriteObjectData(TEE_ObjectHandle object,
				      const void *buffer, uint32_t size)
{
	return TEE_WriteObjectData(object, buffer, size);
}

TEE_Result TEE_TruncateObjectData(TEE_ObjectHandle object, size_t size)
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

TEE_Result __GP11_TEE_TruncateObjectData(TEE_ObjectHandle object,
					 uint32_t size)
{
	return TEE_TruncateObjectData(object, size);
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object, intmax_t offset,
			      TEE_Whence whence)
{
	struct utee_object_info info = { };
	TEE_Result res = TEE_SUCCESS;

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
		    ((uint32_t)offset + info.data_pos > TEE_DATA_MAX_POSITION ||
		     (uint32_t)offset + info.data_pos < info.data_pos)) {
			res = TEE_ERROR_OVERFLOW;
			goto out;
		}
		break;
	case TEE_DATA_SEEK_END:
		if (offset > 0 &&
		    ((uint32_t)offset + info.data_size >
		     TEE_DATA_MAX_POSITION ||
		     (uint32_t)offset + info.data_size < info.data_size)) {
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

TEE_Result __GP11_TEE_SeekObjectData(TEE_ObjectHandle object, int32_t offset,
				     TEE_Whence whence)
{
	return TEE_SeekObjectData(object, offset, whence);
}
