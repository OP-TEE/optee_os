// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2017, GlobalLogic  */

#include "failure_record.h"

#include <string.h>
#include <tee_internal_api.h>

static struct failure_recordable_t frecord_table;
static const int FAILURE_TIMEOUT_MS = 30000;
static const int DAY_IN_MS = 1000 * 60 * 60 * 24;

void init_failure_record(void)
{
	memset(&frecord_table, 0, sizeof(frecord_table));
}

void get_failure_record(secure_id_t user_id, struct failure_record *record)
{
	uint32_t i;
	struct failure_record *records = frecord_table.records;

	for (i = 0; i < frecord_table.size; i++) {
		if (records[i].secure_user_id == user_id) {
			*record = records[i];
			return;
		}
	}

	record->secure_user_id = user_id;
	record->failure_counter = 0;
	record->last_checked_timestamp = 0;
}

void write_failure_record(const struct failure_record *record)
{
	uint32_t i;
	int min_idx = 0;
	uint64_t min_timestamp = ~0ULL;
	struct failure_record *records = frecord_table.records;

	for (i = 0; i < frecord_table.size; i++) {
		if (records[i].secure_user_id == record->secure_user_id)
			break;

		if (records[i].last_checked_timestamp <= min_timestamp) {
			min_timestamp = records[i].last_checked_timestamp;
			min_idx = i;
		}
	}

	if (i >= MAX_FAILURE_RECORDS)
		/* replace the oldest element if all records are in use */
		i = min_idx;
	else if (i == frecord_table.size)
		frecord_table.size++;

	records[i] = *record;
}

void inc_failure_record(struct failure_record *record,
			uint64_t timestamp)
{
	record->failure_counter++;
	record->last_checked_timestamp = timestamp;

	write_failure_record(record);
}


void clear_failure_record(secure_id_t user_id)
{
	struct failure_record record;

	record.secure_user_id = user_id;
	record.last_checked_timestamp = 0;
	record.failure_counter = 0;

	write_failure_record(&record);
}


uint32_t compute_retry_timeout(const struct failure_record *record)
{

	uint32_t failure_counter = record->failure_counter;

	if (!failure_counter)
		return 0;

	if (failure_counter > 0 && failure_counter <= 10)
		if (failure_counter % 5 == 0)
			return FAILURE_TIMEOUT_MS;
		else
			return 0;
	else if (failure_counter < 30)
		return FAILURE_TIMEOUT_MS;
	else if (failure_counter < 140)
		return FAILURE_TIMEOUT_MS << ((failure_counter - 30)/10);

	return DAY_IN_MS;
}


uint64_t get_timestamp(void)
{
	TEE_Time secure_time;

	TEE_GetSystemTime(&secure_time);

	return secure_time.seconds * 1000 + secure_time.millis;
}


bool throttle_request(struct failure_record *record, uint64_t timestamp,
		      uint32_t *response_timeout)
{
	uint64_t last_checked = record->last_checked_timestamp;
	uint64_t timeout;

	timeout = compute_retry_timeout(record);

	/* we have a pending timeout */
	if (timestamp < last_checked + timeout &&
			timestamp > last_checked) {
		/* attempt before timeout expired, return remaining time */
		*response_timeout = timeout - (timestamp-last_checked);

		return true;
	} else if (timestamp <= last_checked) {
		/*
		 * device was rebooted or timer reset, don't count as
		 *  new failure but reset timeout
		 */
		record->last_checked_timestamp = timestamp;
		write_failure_record(record);
		*response_timeout = timeout;

		return true;
	}

	return false;
}
