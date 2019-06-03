/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef KERNEL_HANDLE_H
#define KERNEL_HANDLE_H

#include <stdint.h>

struct handle_db {
	void **ptrs;
	size_t max_ptrs;
};

#define HANDLE_DB_INITIALIZER { NULL, 0 }

/*
 * Frees all internal data structures of the database, but does not free
 * the db pointer. The database is safe to reuse after it's destroyed, it
 * will just be empty again. If ptr_destructor is non-null it will be
 * called for each registered pointer before the database is cleared.
 */
void handle_db_destroy(struct handle_db *db, void (*ptr_destructor)(void *ptr));

/*
 * Allocates a new handle and assigns the supplied pointer to it,
 * ptr must not be NULL.
 * The function returns
 * >= 0 on success and
 * -1 on failure
 */
int handle_get(struct handle_db *db, void *ptr);

/*
 * Deallocates a handle. Returns the assiciated pointer of the handle
 * the the handle was valid or NULL if it's invalid.
 */
void *handle_put(struct handle_db *db, int handle);

/*
 * Returns the assiciated pointer of the handle if the handle is a valid
 * handle.
 * Returns NULL on failure.
 */
void *handle_lookup(struct handle_db *db, int handle);

#endif /*KERNEL_HANDLE_H*/
