/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2017, GlobalLogic  */

#ifndef __FAILURE_RECORD_H
#define __FAILURE_RECORD_H

#include "ta_gatekeeper.h"

#include <stdint.h>
#include <stdbool.h>

#define MAX_FAILURE_RECORDS 32
/*
 * Structure is a failure table entry
 */
struct failure_record {
	secure_id_t secure_user_id;
	uint64_t last_checked_timestamp;
	uint32_t failure_counter;
};

struct failure_recordable_t {
	uint32_t size;
	struct failure_record records[MAX_FAILURE_RECORDS];
};
/*
 * Initialize failure record table
 */
void init_failure_record(void);

/*
 * Returns failure @record for secure @user_id
 */
void get_failure_record(secure_id_t user_id, struct failure_record *record);

/*
 * Write failure @record to failure record table. Function will rewrite the
 * oldest record if failure record table is full
 */
void write_failure_record(const struct failure_record *record);

/*
 * Increment failure counter for @record and set new @timestamp
 */
void inc_failure_record(struct failure_record *record,
			uint64_t timestamp);

/*
 * Clean failure record counter and timestamp for @user_id
 */
void clear_failure_record(secure_id_t user_id);

/*
 * Calculates the timeout in milliseconds as a function of the failure
 * counter 'x' for @record as follows:
 *
 * [0. 5) -> 0
 * 5 -> 30
 * [6, 10) -> 0
 * [11, 30) -> 30
 * [30, 140) -> 30 * (2^((x - 30)/10))
 * [140, inf) -> 1 day
 *
 */
uint32_t compute_retry_timeout(const struct failure_record *record);

/*
 * @return current secure timestamp
 */
uint64_t get_timestamp(void);

/*
 * Function checks if current @record has @response_timeout if current time
 * is @timestamp
 *
 * @return true if response_timeout is not 0
 */
bool throttle_request(struct failure_record *record, uint64_t timestamp,
		      uint32_t *response_timeout);

#endif /* __FAILURE_RECORD_H */
