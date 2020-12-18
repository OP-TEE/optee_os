/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef PKCS11_TA_SANITIZE_OBJECT_H
#define PKCS11_TA_SANITIZE_OBJECT_H

#include "serializer.h"

/*
 * sanitize_consistent_class_and_type - Check object type matches object class
 *
 * @attrs - object attributes
 * Return true if class/type matches, else return false
 */
bool sanitize_consistent_class_and_type(struct obj_attrs *attrs);

/**
 * sanitize_client_object - Setup a serializer from a serialized object
 *
 * @dst - output structure tracking the generated serial object
 * @head - pointer to the formatted serialized object (its head)
 * @size - byte size of the serialized binary blob
 * @class_hint - Hint for class to be added to template if not presnet
 *               in serialized object.
 * @type_hint - Hint for type to be added to template if not presnet
 *               in serialized object.
 *
 * This function copies an attribute list from a client API attribute head
 * into a PKCS11 TA internal attribute structure. It generates a serialized
 * attribute list with a consistent format and identified attribute IDs.
 *
 * @head points to a blob starting with a pkcs11 attribute header.
 * @head may point to an unaligned address.
 * This function allocates, fills and returns a serialized attribute list
 * into a serializer container.
 */
enum pkcs11_rc sanitize_client_object(struct obj_attrs **dst, void *head,
				      size_t size, uint32_t class_hint,
				      uint32_t type_hint);

/* Debug: dump attribute content as debug traces */
void trace_attributes_from_api_head(const char *prefix, void *ref, size_t size);

#endif /*PKCS11_TA_SANITIZE_OBJECT_H*/
