/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIAL_SANITIZE_H
#define __SERIAL_SANITIZE_H

#include "serializer.h"

/**
 * sanitize_client_object - Setup a serializer from a serialized object
 *
 * @dst - output structure tracking the generated serial object
 * @head - pointer to the formated serialized object (its head)
 * @size - byte size of the serialized binary blob
 *
 * This function copies an attribute list from a client API attribute head
 * into a SKS internal attribute structure. It generates a serialized attribute
 * list with a consistent format and identifed attribute IDs.
 *
 * ref points to a blob starting with a sks head.
 * ref may pointer to an unaligned address.
 * This function allocates, fill and returns a serialized attribute list
 * into a serializer container.
 */
uint32_t sanitize_client_object(struct serializer *dst, void *head, size_t size);

/* Debug: dump attribute content as debug traces */
uint32_t trace_attributes_from_api_head(const char *prefix, void *ref);

#endif /*__SERIAL_SANITIZE_H*/

