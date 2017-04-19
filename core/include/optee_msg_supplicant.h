/*
 * Copyright (c) 2016-2017, Linaro Limited
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

#ifndef __OPTEE_MSG_SUPPLICANT_H
#define __OPTEE_MSG_SUPPLICANT_H

/*
 * Load a TA into memory
 */
#define OPTEE_MSG_RPC_CMD_LOAD_TA	0

/*
 * Replay Protected Memory Block access
 */
#define OPTEE_MSG_RPC_CMD_RPMB		1

/*
 * File system access
 */
#define OPTEE_MSG_RPC_CMD_FS		2

/* Was OPTEE_MSG_RPC_CMD_SQL_FS, which isn't supported any longer */
#define OPTEE_MSG_RPC_CMD_SQL_FS_RESERVED	8

/*
 * Values 3-7 are reserved in optee_msg.h for use by the kernel driver
 */

/*
 * Define protocol for messages with .cmd == OPTEE_MSG_RPC_CMD_FS and first
 * parameter has the attribute OPTEE_MSG_ATTR_TYPE_VALUE_INPUT.
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
 * End of definitions for messages with .cmd == OPTEE_MSG_RPC_CMD_FS
 */

/*
 * Send TA profiling information to normal world
 *
 * [in/out] param[0].u.value.a		File identifier. Must be set to 0 on
 *					first call. A value >= 1 will be
 *					returned on success. Re-use this value
 *					to append data to the same file.
 *
 * [in] param[1].u.tmem.buf_ptr		Physical address of TA UUID
 * [in] param[1].u.tmem.size		Size of UUID
 * [in] param[1].u.tmem.shm_ref		Shared memory reference
 *
 * [in] param[2].u.tmem.buf_ptr		Physical address of profile data buffer
 * [in] param[2].u.tmem.size		Buffer size
 * [in] param[2].u.tmem.shm_ref		Shared memory reference
 */
#define OPTEE_MSG_RPC_CMD_GPROF		9

/*
 * Socket commands
 */
#define OPTEE_MSG_RPC_CMD_SOCKET	10


/*
 * Define protocol for messages with .cmd == OPTEE_MSG_RPC_CMD_SOCKET
 */

#define OPTEE_MRC_SOCKET_TIMEOUT_NONBLOCKING	0
#define OPTEE_MRC_SOCKET_TIMEOUT_BLOCKING	0xffffffff

/*
 * Open socket
 *
 * [in]     param[0].u.value.a	OPTEE_MRC_SOCKET_OPEN
 * [in]     param[0].u.value.b	TA instance id
 * [in]     param[1].u.value.a	server port number
 * [in]     param[1].u.value.b	protocol, TEE_ISOCKET_PROTOCOLID_*
 * [in]     param[1].u.value.c	ip version TEE_IP_VERSION_* from tee_ipsocket.h
 * [in]     param[2].u.tmem	server address
 * [out]    param[3].u.value.a	socket handle (32-bit)
 */
#define OPTEE_MRC_SOCKET_OPEN	0

/*
 * Close socket
 *
 * [in]     param[0].u.value.a	OPTEE_MRC_SOCKET_CLOSE
 * [in]     param[0].u.value.b	TA instance id
 * [in]     param[0].u.value.c	socket handle
 */
#define OPTEE_MRC_SOCKET_CLOSE	1

/*
 * Close all sockets
 *
 * [in]     param[0].u.value.a	OPTEE_MRC_SOCKET_CLOSE_ALL
 * [in]     param[0].u.value.b	TA instance id
 */
#define OPTEE_MRC_SOCKET_CLOSE_ALL 2

/*
 * Send data on socket
 *
 * [in]     param[0].u.value.a	OPTEE_MRC_SOCKET_SEND
 * [in]     param[0].u.value.b	TA instance id
 * [in]     param[0].u.value.c	socket handle
 * [in]     param[1].u.tmem	buffer to transmit
 * [in]     param[2].u.value.a	timeout ms or OPTEE_MRC_SOCKET_TIMEOUT_*
 * [out]    param[2].u.value.b	number of transmitted bytes
 */
#define OPTEE_MRC_SOCKET_SEND	3

/*
 * Receive data on socket
 *
 * [in]     param[0].u.value.a	OPTEE_MRC_SOCKET_RECV
 * [in]     param[0].u.value.b	TA instance id
 * [in]     param[0].u.value.c	socket handle
 * [out]    param[1].u.tmem	buffer to receive
 * [in]     param[2].u.value.a	timeout ms or OPTEE_MRC_SOCKET_TIMEOUT_*
 */
#define OPTEE_MRC_SOCKET_RECV	4

/*
 * Perform IOCTL on socket
 *
 * [in]     param[0].u.value.a	OPTEE_MRC_SOCKET_IOCTL
 * [in]     param[0].u.value.b	TA instance id
 * [in]     param[0].u.value.c	socket handle
 * [in/out] param[1].u.tmem	buffer
 * [in]     param[2].u.value.a	ioctl command
 */
#define OPTEE_MRC_SOCKET_IOCTL	5

/*
 * End of definitions for messages with .cmd == OPTEE_MSG_RPC_CMD_SOCKET
 */

#endif /*__OPTEE_MSG_SUPPLICANT_H*/
