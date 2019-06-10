/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef __OPTEE_RPC_CMD_H
#define __OPTEE_RPC_CMD_H

/*
 * All RPC is done with a struct optee_msg_arg as bearer of information,
 * struct optee_msg_arg::arg holds values defined by OPTEE_RPC_CMD_* below.
 * Only the commands handled by the kernel driver are defined here.
 *
 * RPC communication with tee-supplicant is reversed compared to normal
 * client communication described above. The supplicant receives requests
 * and sends responses.
 */

/*
 * Load a TA into memory
 *
 * Since the size of the TA isn't known in advance the size of the TA is
 * can be queried with a NULL buffer.
 *
 * [in]     value[0].a-b    UUID
 * [out]    memref[1]	    Buffer with TA
 */
#define OPTEE_RPC_CMD_LOAD_TA		0

/*
 * Replay Protected Memory Block access
 *
 * [in]     memref[0]	    Frames to device
 * [out]    memref[1]	    Frames from device
 */
#define OPTEE_RPC_CMD_RPMB		1

/*
 * File system access, see definition of protocol below
 */
#define OPTEE_RPC_CMD_FS		2

/*
 * Get time
 *
 * Returns number of seconds and nano seconds since the Epoch,
 * 1970-01-01 00:00:00 +0000 (UTC).
 *
 * [out]    value[0].a	    Number of seconds
 * [out]    value[0].b	    Number of nano seconds.
 */
#define OPTEE_RPC_CMD_GET_TIME		3

/*
 * Wait queue primitive, helper for secure world to implement a wait queue.
 *
 * If secure world needs to wait for a secure world mutex it issues a sleep
 * request instead of spinning in secure world. Conversely is a wakeup
 * request issued when a secure world mutex with a thread waiting thread is
 * unlocked.
 *
 * Waiting on a key
 * [in]    value[0].a	    OPTEE_RPC_WAIT_QUEUE_SLEEP
 * [in]    value[0].b	    Wait key
 *
 * Waking up a key
 * [in]    value[0].a	    OPTEE_RPC_WAIT_QUEUE_WAKEUP
 * [in]    value[0].b	    Wakeup key
 */
#define OPTEE_RPC_CMD_WAIT_QUEUE	4
#define OPTEE_RPC_WAIT_QUEUE_SLEEP	0
#define OPTEE_RPC_WAIT_QUEUE_WAKEUP	1

/*
 * Suspend execution
 *
 * [in]    value[0].a	Number of milliseconds to suspend
 */
#define OPTEE_RPC_CMD_SUSPEND		5

/*
 * Allocate a piece of shared memory
 *
 * [in]    value[0].a	    Type of memory one of
 *			    OPTEE_RPC_SHM_TYPE_* below
 * [in]    value[0].b	    Requested size
 * [in]    value[0].c	    Required alignment
 * [out]   memref[0]	    Buffer
 */
#define OPTEE_RPC_CMD_SHM_ALLOC		6
/* Memory that can be shared with a non-secure user space application */
#define OPTEE_RPC_SHM_TYPE_APPL		0
/* Memory only shared with non-secure kernel */
#define OPTEE_RPC_SHM_TYPE_KERNEL	1
/*
 * Memory shared with non-secure kernel and exported to a non-secure user
 * space application
 */
#define OPTEE_RPC_SHM_TYPE_GLOBAL	2

/*
 * Free shared memory previously allocated with OPTEE_RPC_CMD_SHM_ALLOC
 *
 * [in]     value[0].a	    Type of memory one of
 *			    OPTEE_RPC_SHM_TYPE_* above
 * [in]     value[0].b	    Value of shared memory reference or cookie
 */
#define OPTEE_RPC_CMD_SHM_FREE		7

/* Was OPTEE_RPC_CMD_SQL_FS, which isn't supported any longer */
#define OPTEE_RPC_CMD_SQL_FS_RESERVED	8

/*
 * Send TA profiling information to normal world
 *
 * [in/out] value[0].a	    File identifier. Must be set to 0 on
 *			    first call. A value >= 1 will be
 *			    returned on success. Re-use this value
 *			    to append data to the same file.
 * [in]     memref[1]	    TA UUID
 * [in]     memref[2]	    Profile data
 */
#define OPTEE_RPC_CMD_GPROF		9

/*
 * Socket command, see definition of protocol below
 */
#define OPTEE_RPC_CMD_SOCKET		10

/*
 * Send TA function graph data to normal world
 *
 * [in/out] value[0].a	    File identifier. Must be set to 0 on
 *			    first call. A value >= 1 will be
 *			    returned on success. Re-use this value
 *			    to append data to the same file.
 * [in]     memref[1]	    TA UUID
 * [in]     memref[2]	    function graph data
 */
#define OPTEE_RPC_CMD_FTRACE		11

/*
 * Register timestamp buffer in the linux kernel optee driver
 *
 * [in]     value[0].a	    Subcommand (register buffer, unregister buffer)
 * [in]     value[0].b	    Physical address of timestamp buffer
 * [in]     value[0].c	    Size of buffer
 */
#define OPTEE_RPC_CMD_BENCH_REG		20

/*
 * Definition of protocol for command OPTEE_RPC_CMD_FS
 */

/*
 * Open a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_OPEN
 * [in]     memref[1]	    A string holding the file name
 * [out]    value[2].a	    File descriptor of open file
 */
#define OPTEE_RPC_FS_OPEN		0

/*
 * Create a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_CREATE
 * [in]     memref[1]	    A string holding the file name
 * [out]    value[2].a	    File descriptor of open file
 */
#define OPTEE_RPC_FS_CREATE		1

/*
 * Close a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_CLOSE
 * [in]     value[0].b	    File descriptor of open file.
 */
#define OPTEE_RPC_FS_CLOSE		2

/*
 * Read from a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_READ
 * [in]     value[0].b	    File descriptor of open file
 * [in]     value[0].c	    Offset into file
 * [out]    memref[1]	    Buffer to hold returned data
 */
#define OPTEE_RPC_FS_READ		3

/*
 * Write to a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_WRITE
 * [in]     value[0].b	    File descriptor of open file
 * [in]     value[0].c	    Offset into file
 * [in]     memref[1]	    Buffer holding data to be written
 */
#define OPTEE_RPC_FS_WRITE		4

/*
 * Truncate a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_TRUNCATE
 * [in]     value[0].b	    File descriptor of open file
 * [in]     value[0].c	    Length of file.
 */
#define OPTEE_RPC_FS_TRUNCATE		5

/*
 * Remove a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_REMOVE
 * [in]     memref[1]	    A string holding the file name
 */
#define OPTEE_RPC_FS_REMOVE		6

/*
 * Rename a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_RENAME
 * [in]     value[0].b	    True if existing target should be removed
 * [in]     memref[1]	    A string holding the old file name
 * [in]     memref[2]	    A string holding the new file name
 */
#define OPTEE_RPC_FS_RENAME		7

/*
 * Opens a directory for file listing
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_OPENDIR
 * [in]     memref[1]	    A string holding the name of the directory
 * [out]    value[2].a	    Handle to open directory
 */
#define OPTEE_RPC_FS_OPENDIR		8

/*
 * Closes a directory handle
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_CLOSEDIR
 * [in]     value[0].b	    Handle to open directory
 */
#define OPTEE_RPC_FS_CLOSEDIR		9

/*
 * Read next file name of directory
 *
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_READDIR
 * [in]     value[0].b	    Handle to open directory
 * [out]    memref[1]	    A string holding the file name
 */
#define OPTEE_RPC_FS_READDIR		10

/* End of definition of protocol for command OPTEE_RPC_CMD_FS */

/*
 * Definition of protocol for command OPTEE_RPC_CMD_SOCKET
 */

#define OPTEE_RPC_SOCKET_TIMEOUT_NONBLOCKING	0
#define OPTEE_RPC_SOCKET_TIMEOUT_BLOCKING	0xffffffff

/*
 * Open socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_OPEN
 * [in]     value[0].b	    TA instance id
 * [in]     value[1].a	    Server port number
 * [in]     value[1].b	    Protocol, TEE_ISOCKET_PROTOCOLID_*
 * [in]     value[1].c	    Ip version TEE_IP_VERSION_* from tee_ipsocket.h
 * [in]     memref[2]	    Server address
 * [out]    value[3].a	    Socket handle (32-bit)
 */
#define OPTEE_RPC_SOCKET_OPEN	0

/*
 * Close socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_CLOSE
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 */
#define OPTEE_RPC_SOCKET_CLOSE	1

/*
 * Close all sockets
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_CLOSE_ALL
 * [in]     value[0].b	    TA instance id
 */
#define OPTEE_RPC_SOCKET_CLOSE_ALL 2

/*
 * Send data on socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_SEND
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 * [in]     memref[1]	    Buffer to transmit
 * [in]     value[2].a	    Timeout ms or OPTEE_RPC_SOCKET_TIMEOUT_*
 * [out]    value[2].b	    Number of transmitted bytes
 */
#define OPTEE_RPC_SOCKET_SEND	3

/*
 * Receive data on socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_RECV
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 * [out]    memref[1]	    Buffer to receive
 * [in]     value[2].a	    Timeout ms or OPTEE_RPC_SOCKET_TIMEOUT_*
 */
#define OPTEE_RPC_SOCKET_RECV	4

/*
 * Perform IOCTL on socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_IOCTL
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 * [in/out] memref[1]	    Buffer
 * [in]     value[2].a	    Ioctl command
 */
#define OPTEE_RPC_SOCKET_IOCTL	5

/* End of definition of protocol for command OPTEE_RPC_CMD_SOCKET */

#endif /*__OPTEE_RPC_CMD_H*/
