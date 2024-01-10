// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2020, Linaro Limited
 */

#include <stdlib.h>
#include <tee_internal_api.h>

#include "handle.h"

/*
 * Define the initial capacity of the database. It should be a low number
 * multiple of 2 since some databases a likely to only use a few handles.
 * Since the algorithm is to doubles up when growing it shouldn't cause a
 * noticeable overhead on large databases.
 */
#define HANDLE_DB_INITIAL_MAX_PTRS	4

/* Specific pointer ~0 denotes a still allocated but invalid handle */
#define INVALID_HANDLE_PTR	((void *)~0)

void handle_db_init(struct handle_db *db)
{
	TEE_MemFill(db, 0, sizeof(*db));
}

void handle_db_destroy(struct handle_db *db)
{
	if (db) {
		TEE_Free(db->ptrs);
		db->ptrs = NULL;
		db->max_ptrs = 0;
	}
}

uint32_t handle_get(struct handle_db *db, void *ptr)
{
	uint32_t n = 0;
	void *p = NULL;
	uint32_t new_max_ptrs = 0;

	if (!db || !ptr || ptr == INVALID_HANDLE_PTR)
		return 0;

	/* Try to find an empty location (index 0 is reserved as invalid) */
	for (n = 1; n < db->max_ptrs; n++) {
		if (!db->ptrs[n]) {
			db->ptrs[n] = ptr;
			return n;
		}
	}

	/* No location available, grow the ptrs array */
	if (db->max_ptrs)
		new_max_ptrs = db->max_ptrs * 2;
	else
		new_max_ptrs = HANDLE_DB_INITIAL_MAX_PTRS;

	p = TEE_Realloc(db->ptrs, new_max_ptrs * sizeof(void *));
	if (!p)
		return 0;
	db->ptrs = p;
	TEE_MemFill(db->ptrs + db->max_ptrs, 0,
		    (new_max_ptrs - db->max_ptrs) * sizeof(void *));
	db->max_ptrs = new_max_ptrs;

	/* Since n stopped at db->max_ptrs there is an empty location there */
	db->ptrs[n] = ptr;
	return n;
}

static bool handle_is_valid(struct handle_db *db, uint32_t handle)
{
	return db && handle && handle < db->max_ptrs;
}

void *handle_put(struct handle_db *db, uint32_t handle)
{
	void *p = NULL;

	if (!handle_is_valid(db, handle))
		return NULL;

	p = db->ptrs[handle];
	db->ptrs[handle] = NULL;
	return p;
}

void *handle_lookup(struct handle_db *db, uint32_t handle)
{
	if (!handle_is_valid(db, handle) ||
	    db->ptrs[handle] == INVALID_HANDLE_PTR)
		return NULL;

	return db->ptrs[handle];
}

void handle_invalidate(struct handle_db *db, uint32_t handle)
{
	if (handle_is_valid(db, handle)) {
		if (!db->ptrs[handle])
			TEE_Panic(TEE_ERROR_GENERIC);

		db->ptrs[handle] = INVALID_HANDLE_PTR;
	}
}

uint32_t handle_lookup_handle(struct handle_db *db, void *ptr)
{
	uint32_t n = 0;

	if (ptr && ptr != INVALID_HANDLE_PTR) {
		for (n = 1; n < db->max_ptrs; n++)
			if (db->ptrs[n] == ptr)
				return n;
	}

	return 0;
}
