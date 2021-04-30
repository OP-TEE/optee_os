/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2021, Linaro Limited
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
#define OPTEE_RPC_CMD_LOAD_TA		U(0)

/*
 * Replay Protected Memory Block access
 *
 * [in]     memref[0]	    Frames to device
 * [out]    memref[1]	    Frames from device
 */
#define OPTEE_RPC_CMD_RPMB		U(1)

/*
 * File system access, see definition of protocol below
 */
#define OPTEE_RPC_CMD_FS		U(2)

/*
 * Get time
 *
 * Returns number of seconds and nano seconds since the Epoch,
 * 1970-01-01 00:00:00 +0000 (UTC).
 *
 * [out]    value[0].a	    Number of seconds
 * [out]    value[0].b	    Number of nano seconds.
 */
#define OPTEE_RPC_CMD_GET_TIME		U(3)

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
#define OPTEE_RPC_CMD_WAIT_QUEUE	U(4)
#define OPTEE_RPC_WAIT_QUEUE_SLEEP	U(0)
#define OPTEE_RPC_WAIT_QUEUE_WAKEUP	U(1)

/*
 * Suspend execution
 *
 * [in]    value[0].a	Number of milliseconds to suspend
 */
#define OPTEE_RPC_CMD_SUSPEND		U(5)

/*
 * Allocate a piece of shared memory
 *
 * [in]    value[0].a	    Type of memory one of
 *			    OPTEE_RPC_SHM_TYPE_* below
 * [in]    value[0].b	    Requested size
 * [in]    value[0].c	    Required alignment
 * [out]   memref[0]	    Buffer
 */
#define OPTEE_RPC_CMD_SHM_ALLOC		U(6)
/* Memory that can be shared with a non-secure user space application */
#define OPTEE_RPC_SHM_TYPE_APPL		U(0)
/* Memory only shared with non-secure kernel */
#define OPTEE_RPC_SHM_TYPE_KERNEL	U(1)
/*
 * Memory shared with non-secure kernel and exported to a non-secure user
 * space application
 */
#define OPTEE_RPC_SHM_TYPE_GLOBAL	U(2)

/*
 * Free shared memory previously allocated with OPTEE_RPC_CMD_SHM_ALLOC
 *
 * [in]     value[0].a	    Type of memory one of
 *			    OPTEE_RPC_SHM_TYPE_* above
 * [in]     value[0].b	    Value of shared memory reference or cookie
 */
#define OPTEE_RPC_CMD_SHM_FREE		U(7)

/* Was OPTEE_RPC_CMD_SQL_FS, which isn't supported any longer */
#define OPTEE_RPC_CMD_SQL_FS_RESERVED	U(8)

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
#define OPTEE_RPC_CMD_GPROF		U(9)

/*
 * Socket command, see definition of protocol below
 */
#define OPTEE_RPC_CMD_SOCKET		U(10)

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
#define OPTEE_RPC_CMD_FTRACE		U(11)

/*
 * tee-supplicant plugin command, see definition of protocol below
 */
#define OPTEE_RPC_CMD_SUPP_PLUGIN	U(12)

/*
 * Register timestamp buffer in the linux kernel optee driver
 *
 * [in]     value[0].a	    Subcommand (register buffer, unregister buffer)
 * [in]     value[0].b	    Physical address of timestamp buffer
 * [in]     value[0].c	    Size of buffer
 */
#define OPTEE_RPC_CMD_BENCH_REG		U(20)

/*
 * Issue master requests (read and write operations) to an I2C chip.
 *
 * [in]     value[0].a	    Transfer mode (OPTEE_RPC_I2C_TRANSFER_*)
 * [in]     value[0].b	    The I2C bus (a.k.a adapter).
 *				16 bit field.
 * [in]     value[0].c	    The I2C chip (a.k.a address).
 *				16 bit field (either 7 or 10 bit effective).
 * [in]     value[1].a	    The I2C master control flags (ie, 10 bit address).
 *				16 bit field.
 * [in/out] memref[2]	    Buffer used for data transfers.
 * [out]    value[3].a	    Number of bytes transferred by the REE.
 */
#define OPTEE_RPC_CMD_I2C_TRANSFER	U(21)

/* I2C master transfer modes */
#define OPTEE_RPC_I2C_TRANSFER_RD	U(0)
#define OPTEE_RPC_I2C_TRANSFER_WR	U(1)

/* I2C master control flags */
#define OPTEE_RPC_I2C_FLAGS_TEN_BIT	BIT(0)

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
#define OPTEE_RPC_FS_OPEN		U(0)

/*
 * Create a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_CREATE
 * [in]     memref[1]	    A string holding the file name
 * [out]    value[2].a	    File descriptor of open file
 */
#define OPTEE_RPC_FS_CREATE		U(1)

/*
 * Close a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_CLOSE
 * [in]     value[0].b	    File descriptor of open file.
 */
#define OPTEE_RPC_FS_CLOSE		U(2)

/*
 * Read from a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_READ
 * [in]     value[0].b	    File descriptor of open file
 * [in]     value[0].c	    Offset into file
 * [out]    memref[1]	    Buffer to hold returned data
 */
#define OPTEE_RPC_FS_READ		U(3)

/*
 * Write to a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_WRITE
 * [in]     value[0].b	    File descriptor of open file
 * [in]     value[0].c	    Offset into file
 * [in]     memref[1]	    Buffer holding data to be written
 */
#define OPTEE_RPC_FS_WRITE		U(4)

/*
 * Truncate a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_TRUNCATE
 * [in]     value[0].b	    File descriptor of open file
 * [in]     value[0].c	    Length of file.
 */
#define OPTEE_RPC_FS_TRUNCATE		U(5)

/*
 * Remove a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_REMOVE
 * [in]     memref[1]	    A string holding the file name
 */
#define OPTEE_RPC_FS_REMOVE		U(6)

/*
 * Rename a file
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_RENAME
 * [in]     value[0].b	    True if existing target should be removed
 * [in]     memref[1]	    A string holding the old file name
 * [in]     memref[2]	    A string holding the new file name
 */
#define OPTEE_RPC_FS_RENAME		U(7)

/*
 * Opens a directory for file listing
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_OPENDIR
 * [in]     memref[1]	    A string holding the name of the directory
 * [out]    value[2].a	    Handle to open directory
 */
#define OPTEE_RPC_FS_OPENDIR		U(8)

/*
 * Closes a directory handle
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_CLOSEDIR
 * [in]     value[0].b	    Handle to open directory
 */
#define OPTEE_RPC_FS_CLOSEDIR		U(9)

/*
 * Read next file name of directory
 *
 *
 * [in]     value[0].a	    OPTEE_RPC_FS_READDIR
 * [in]     value[0].b	    Handle to open directory
 * [out]    memref[1]	    A string holding the file name
 */
#define OPTEE_RPC_FS_READDIR		U(10)

/* End of definition of protocol for command OPTEE_RPC_CMD_FS */

/*
 * Definition of protocol for command OPTEE_RPC_CMD_SOCKET
 */

#define OPTEE_RPC_SOCKET_TIMEOUT_NONBLOCKING	U(0)
#define OPTEE_RPC_SOCKET_TIMEOUT_BLOCKING	U(0xffffffff)

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
#define OPTEE_RPC_SOCKET_OPEN	U(0)

/*
 * Close socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_CLOSE
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 */
#define OPTEE_RPC_SOCKET_CLOSE	U(1)

/*
 * Close all sockets
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_CLOSE_ALL
 * [in]     value[0].b	    TA instance id
 */
#define OPTEE_RPC_SOCKET_CLOSE_ALL U(2)

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
#define OPTEE_RPC_SOCKET_SEND	U(3)

/*
 * Receive data on socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_RECV
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 * [out]    memref[1]	    Buffer to receive
 * [in]     value[2].a	    Timeout ms or OPTEE_RPC_SOCKET_TIMEOUT_*
 */
#define OPTEE_RPC_SOCKET_RECV	U(4)

/*
 * Perform IOCTL on socket
 *
 * [in]     value[0].a	    OPTEE_RPC_SOCKET_IOCTL
 * [in]     value[0].b	    TA instance id
 * [in]     value[0].c	    Socket handle
 * [in/out] memref[1]	    Buffer
 * [in]     value[2].a	    Ioctl command
 */
#define OPTEE_RPC_SOCKET_IOCTL	U(5)

/* End of definition of protocol for command OPTEE_RPC_CMD_SOCKET */

/*
 * Definition of protocol for command OPTEE_RPC_CMD_SUPP_PLUGIN
 */

/*
 * Invoke tee-supplicant's plugin.
 *
 * [in]     value[0].a	OPTEE_RPC_SUPP_PLUGIN_INVOKE
 * [in]     value[0].b	uuid.d1
 * [in]     value[0].c	uuid.d2
 * [in]     value[1].a	uuid.d3
 * [in]     value[1].b	uuid.d4
 * [in]     value[1].c	cmd for plugin
 * [in]     value[2].a	sub_cmd for plugin
 * [out]    value[2].b  length of the outbuf (memref[3]), if out is needed.
 * [in/out] memref[3]	buffer holding data for plugin
 *
 * UUID serialized into octets:
 * b0  b1  b2  b3   b4  b5  b6  b7   b8  b9  b10  b11   b12  b13  b14  b15
 *       d1       |       d2       |        d3        |         d4
 *
 * The endianness of words d1, d2, d3 and d4 must be little-endian.
 * d1 word contains [b3 b2 b1 b0]
 * d2 word contains [b7 b6 b5 b4]
 * d3 word contains [b11 b10 b9 b8]
 * d4 word contains [b15 b14 b13 b12]
 */
#define OPTEE_RPC_SUPP_PLUGIN_INVOKE	U(0)

/* End of definition of protocol for command OPTEE_RPC_CMD_SUPP_PLUGIN */

#endif /*__OPTEE_RPC_CMD_H*/
