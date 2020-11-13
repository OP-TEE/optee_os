/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2020, Linaro Limited
 */

#ifndef PKCS11_TA_HANDLE_H
#define PKCS11_TA_HANDLE_H

#include <stddef.h>

struct handle_db {
	void **ptrs;
	uint32_t max_ptrs;
};

/*
 * Initialize the handle database
 */
void handle_db_init(struct handle_db *db);

/*
 * Free all internal data structures of the database, but does not free
 * the db pointer. The database is safe to reuse after it's destroyed, it
 * just be empty again.
 */
void handle_db_destroy(struct handle_db *db);

/*
 * Allocate a new handle ID and assigns the supplied pointer to it,
 * The function returns > 0 on success and 0 on failure.
 */
uint32_t handle_get(struct handle_db *db, void *ptr);

/*
 * Deallocate a handle. Returns the associated pointer of the handle
 * if the handle was valid or NULL if it's invalid.
 */
void *handle_put(struct handle_db *db, uint32_t handle);

/*
 * Return the associated pointer of the handle if the handle is a valid
 * handle.
 * Returns NULL on failure.
 */
void *handle_lookup(struct handle_db *db, uint32_t handle);

/* Return the handle associated to a pointer if found, else return 0 */
uint32_t handle_lookup_handle(struct handle_db *db, void *ptr);

#endif /*PKCS11_TA_HANDLE_H*/
