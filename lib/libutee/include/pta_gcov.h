/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef PTA_GCOV_H_
#define PTA_GCOV_H_

/*
 * GCOV_UUID The UUID to contact the gcov STA
 */
#define PTA_GCOV_UUID \
	{ \
		0xa1527d6c, 0x1f80, 0x417c, \
		{ \
			0x97, 0x27, 0x1b, 0x93, 0x0c, 0x52, 0xfe, 0x75 \
		} \
	}

/* Get version of gcov for the core */
#define PTA_CMD_GCOV_GET_VERSION 0

/* Store code coverage data */
#define PTA_CMD_GCOV_DUMP 1

/* Reset the code coverage of the core */
#define PTA_CMD_GCOV_CORE_RESET 2

/* Generate and store the code coverage for the core */
#define PTA_CMD_GCOV_CORE_DUMP_ALL 3

#endif /* PTA_GCOV_H_ */
