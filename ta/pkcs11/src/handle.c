// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2020, Linaro Limited
 */

#include <stdlib.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "handle.h"

/*
 * Define the initial capacity of the database. It should be a low number
 * multiple of 2 since some databases a likely to only use a few handles.
 * Since the algorithm is to doubles up when growing it shouldn't cause a
 * noticeable overhead on large databases.
 */
#define HANDLE_DB_INITIAL_MAX_PTRS	4

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

	if (!db || !ptr)
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

void *handle_put(struct handle_db *db, uint32_t handle)
{
	void *p = NULL;

	if (!db || !handle || handle >= db->max_ptrs)
		return NULL;

	p = db->ptrs[handle];
	db->ptrs[handle] = NULL;
	return p;
}

void *handle_lookup(struct handle_db *db, uint32_t handle)
{
	if (!db || !handle || handle >= db->max_ptrs)
		return NULL;

	return db->ptrs[handle];
}

uint32_t handle_lookup_handle(struct handle_db *db, void *ptr)
{
	uint32_t n = 0;

	if (ptr) {
		for (n = 1; n < db->max_ptrs; n++)
			if (db->ptrs[n] == ptr)
				return n;
	}

	return 0;
}
