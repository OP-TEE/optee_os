/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __PTA_INVOKE_TESTS_H
#define __PTA_INVOKE_TESTS_H

#define PTA_INVOKE_TESTS_UUID \
		{ 0xd96a5b40, 0xc3e5, 0x21e3, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

/* Trace some hello string. Parameters are not used/checked. */
#define PTA_INVOKE_TESTS_CMD_TRACE		0

/*
 * Types of parameter drives the test sequences:
 * - test on value parameters
 * - test on SHM memory reference parameters
 * - test on SDP memory reference parameters
 */
#define PTA_INVOKE_TESTS_CMD_PARAMS		1

/* Run some core internal tests. Parameters are not used/checked. */
#define PTA_INVOKE_TESTS_CMD_SELF_TESTS		2

/*
 * Secure data path: check that PTA can copy data from non-secure shared memory
 * to SDP secure memory
 *
 * [in]     memref[0]        source (non-secure shared memory)
 * [out]    memref[1]        destination (SDP secure memory)
 */
#define PTA_INVOKE_TESTS_CMD_COPY_NSEC_TO_SEC	3

/*
 * Secure data path: check that PTA can read data from SDP secure memory and
 * write it back. Data are processed so that client check the expected
 * read/write sequence succeed.
 *
 * [in/out]     memref[0]        SDP secure buffer to read from and write to
 */
#define PTA_INVOKE_TESTS_CMD_READ_MODIFY_SEC	4

/*
 * Secure data path: check that PTA can copy data from SDP secure memory to
 * non-secure shared memory
 *
 * [in]     memref[0]        source (SDP secure memory)
 * [out]    memref[1]        destination (non-secure shared memory)
 */
#define PTA_INVOKE_TESTS_CMD_COPY_SEC_TO_NSEC	5

/*
 * Tests FS hash-tree corner cases in error handling
 */
#define PTA_INVOKE_TESTS_CMD_FS_HTREE		6

/*
 * Tests mutex
 *
 * [in]  value[0].a	Test function PTA_MUTEX_TEST_*
 * [in]  value[0].b	delay number
 * [out] value[1].a	before lock concurency
 * [out] value[1].b	during lock concurency
 */
#define PTA_MUTEX_TEST_WRITER			0
#define PTA_MUTEX_TEST_READER			1
#define PTA_INVOKE_TESTS_CMD_MUTEX		7

/*
 * Tests lock dependency checking algorithm
 */
#define PTA_INVOKE_TESTS_CMD_LOCKDEP		8

/*
 * These values should match the ones in
 * optee_test/ta/aes_perf/include/ta_aes_perf.h
 */
#define PTA_INVOKE_TESTS_AES_ECB		0
#define PTA_INVOKE_TESTS_AES_CBC		1
#define PTA_INVOKE_TESTS_AES_CTR		2
#define PTA_INVOKE_TESTS_AES_XTS		3
#define PTA_INVOKE_TESTS_AES_GCM		4

/*
 * AES performance tests
 *
 * [in]     value[0].a	Top 16 bits Decrypt, low 16 bits key size in bits
 * [in]     value[0].b	AES mode, one of
 *			PTA_INVOKE_TESTS_AES_{ECB_NOPAD,CBC_NOPAD,CTR,XTS,GCM}
 * [in]     value[1].a	repetition count
 * [in]     value[1].b	unit size
 * [in]     memref[2]	In buffer
 * [in]     memref[3]	Out buffer
 */
#define PTA_INVOKE_TEST_CMD_AES_PERF		9

/*
 * NULL memory reference parameter
 *
 * [in/out] memref[0]	NULL memory reference of size zero
 */
#define PTA_INVOKE_TESTS_CMD_MEMREF_NULL	10

#endif /*__PTA_INVOKE_TESTS_H*/

