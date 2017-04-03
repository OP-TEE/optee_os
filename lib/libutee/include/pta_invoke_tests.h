/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
 * Secure data path: check that pTA can copy data from non-secure shared memory
 * to SDP secure memory
 *
 * [in]     memref[0]        source (non-secure shared memory)
 * [out]    memref[1]        destination (SDP secure memory)
 */
#define PTA_INVOKE_TESTS_CMD_COPY_NSEC_TO_SEC	3

/*
 * Secure data path: check that pTA can read data from SDP secure memory and
 * write it back. Data are processed so that client check the expected
 * read/write sequence succeed.
 *
 * [in/out]     memref[0]        SDP secure buffer to read from and write to
 */
#define PTA_INVOKE_TESTS_CMD_READ_MODIFY_SEC	4

/*
 * Secure data path: check that pTA can copy data from SDP secure memory to
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

#endif /*__PTA_INVOKE_TESTS_H*/

