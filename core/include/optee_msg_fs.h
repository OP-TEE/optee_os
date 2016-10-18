/*
 * Copyright (c) 2016, Linaro Limited
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

#ifndef __OPTEE_MSG_FS_H
#define __OPTEE_MSG_FS_H

/*
 * Define protocol for messages with .cmd == OPTEE_MSG_RPC_CMD_FS
 * and first parameter has the attribute OPTEE_MSG_ATTR_TYPE_VALUE_INPUT.
 */

/*
 * Open a file
 *
 * [in]     param[0].u.value.a	OPTEE_MRF_OPEN
 * [in]     param[1].u.tmem	a string holding the file name
 * [out]    param[2].u.value.a	file descriptor of open file
 */
#define OPTEE_MRF_OPEN			0

/*
 * Create a file
 *
 * [in]     param[0].u.value.a	OPTEE_MRF_CREATE
 * [in]     param[1].u.tmem	a string holding the file name
 * [out]    param[2].u.value.a	file descriptor of open file
 */
#define OPTEE_MRF_CREATE		1

/*
 * Close a file
 *
 * [in]     param[0].u.value.a	OPTEE_MRF_CLOSE
 * [in]     param[0].u.value.b	file descriptor of open file.
 */
#define OPTEE_MRF_CLOSE			2

/*
 * Read from a file
 *
 * [in]     param[0].u.value.a	OPTEE_MRF_READ
 * [in]     param[0].u.value.b	file descriptor of open file
 * [in]     param[0].u.value.c	offset into file
 * [out]    param[1].u.tmem	buffer to hold returned data
 */
#define OPTEE_MRF_READ			3

/*
 * Write to a file
 *
 * [in]     param[0].u.value.a	OPTEE_MRF_WRITE
 * [in]     param[0].u.value.b	file descriptor of open file
 * [in]     param[0].u.value.c	offset into file
 * [in]     param[1].u.tmem	buffer holding data to be written
 */
#define OPTEE_MRF_WRITE			4

/*
 * Truncate a file
 *
 * [in]     param[0].u.value.a	OPTEE_MRF_TRUNCATE
 * [in]     param[0].u.value.b	file descriptor of open file
 * [in]     param[0].u.value.c	length of file.
 */
#define OPTEE_MRF_TRUNCATE		5

/*
 * Remove a file
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_REMOVE
 * [in]  param[1].u.tmem	a string holding the file name
 */
#define OPTEE_MRF_REMOVE		6

/*
 * Rename a file
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_RENAME
 * [in]  param[0].u.value.b	true if existing target should be removed
 * [in]  param[1].u.tmem	a string holding the old file name
 * [in]  param[2].u.tmem	a string holding the new file name
 */
#define OPTEE_MRF_RENAME		7

/*
 * Opens a directory for file listing
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_OPENDIR
 * [in]  param[1].u.tmem	a string holding the name of the directory
 * [out] param[2].u.value.a	handle to open directory
 */
#define OPTEE_MRF_OPENDIR		8

/*
 * Closes a directory handle
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_CLOSEDIR
 * [in]  param[0].u.value.b	handle to open directory
 */
#define OPTEE_MRF_CLOSEDIR		9

/*
 * Read next file name of directory
 *
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_READDIR
 * [in]  param[0].u.value.b	handle to open directory
 * [out] param[1].u.tmem	a string holding the file name
 */
#define OPTEE_MRF_READDIR		10

/*
 * Begins a new transaction (only valid for SQL FS)
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_BEGIN_TRANSACTION
 */
#define OPTEE_MRF_BEGIN_TRANSACTION	11

/*
 * Ends a transaction (only valid for SQL FS)
 *
 * [in]  param[0].u.value.a	OPTEE_MRF_END_TRANSACTION
 * [in]  param[0].u.value.b	true if rolling back to previous state
 */
#define OPTEE_MRF_END_TRANSACTION	12

#endif /*__OPTEE_MSG_FS_H*/
