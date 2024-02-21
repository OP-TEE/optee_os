// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <kernel/semihosting.h>
#include <string.h>

/*
 * ARM and RISC-V have defined the standard way to perform
 * the semihosting operations.
 * - Operation codes and open modes are identical.
 * - The implementation of the low-level __do_semihosting() call is
 *   architecture-specific.
 * - Arm semihosting interface:
 *   https://developer.arm.com/documentation/dui0471/g/Semihosting/The-semihosting-interface
 * - RISC-V semihosting interface:
 *   https://github.com/riscv-non-isa/riscv-semihosting/blob/main/binary-interface.adoc
 */

/* An integer that specifies the file open mode */
enum semihosting_open_mode {
	SEMIHOSTING_OPEN_R = 0,
	SEMIHOSTING_OPEN_RB = 1,
	SEMIHOSTING_OPEN_RX = 2,
	SEMIHOSTING_OPEN_RXB = 3,
	SEMIHOSTING_OPEN_W = 4,
	SEMIHOSTING_OPEN_WB = 5,
	SEMIHOSTING_OPEN_WX = 6,
	SEMIHOSTING_OPEN_WXB = 7,
	SEMIHOSTING_OPEN_A = 8,
	SEMIHOSTING_OPEN_AB = 9,
	SEMIHOSTING_OPEN_AX = 10,
	SEMIHOSTING_OPEN_AXB = 11,
};

enum semihosting_sys_ops {
	/* Regular operations */
	SEMIHOSTING_SYS_OPEN = 0x01,
	SEMIHOSTING_SYS_CLOSE = 0x02,
	SEMIHOSTING_SYS_WRITEC = 0x03,
	SEMIHOSTING_SYS_WRITE = 0x05,
	SEMIHOSTING_SYS_READ = 0x06,
	SEMIHOSTING_SYS_READC = 0x07,
};

struct semihosting_param_t {
	uintptr_t param0;
	uintptr_t param1;
	uintptr_t param2;
};

/**
 * @brief Read one character byte from the semihosting host debug terminal
 *
 * @retval the character read from the semihosting host
 */
char semihosting_sys_readc(void)
{
	return __do_semihosting(SEMIHOSTING_SYS_READC, 0);
}

/**
 * @brief Write one character byte to the semihosting host debug terminal
 * @param c: the character to be written
 */
void semihosting_sys_writec(char c)
{
	__do_semihosting(SEMIHOSTING_SYS_WRITEC, (uintptr_t)&c);
}

/**
 * @brief Request the semihosting host to open a file on the host system
 * @param fname: the path or name of the file
 * @param flags: sys/fcntl.h standard flags to open the file with
 *
 * @retval nonzero if OK, or -1 if fails
 */
int semihosting_open(const char *fname, int flags)
{
	int semi_open_flags = 0;
	const int flags_mask = O_RDONLY | O_WRONLY | O_RDWR |
			       O_CREAT | O_TRUNC | O_APPEND;
	struct semihosting_param_t arg = { };

	/* Convert the flags to semihosting open. */
	switch (flags & flags_mask) {
	case O_RDONLY:				/* 'r' */
		semi_open_flags = SEMIHOSTING_OPEN_R;
		break;
	case O_WRONLY | O_CREAT | O_TRUNC:	/* 'w' */
		semi_open_flags = SEMIHOSTING_OPEN_W;
		break;
	case O_WRONLY | O_CREAT | O_APPEND:	/* 'a' */
		semi_open_flags = SEMIHOSTING_OPEN_A;
		break;
	case O_RDWR:				/* 'r+' */
		semi_open_flags = SEMIHOSTING_OPEN_RX;
		break;
	case O_RDWR | O_CREAT | O_TRUNC:	/* 'w+' */
		semi_open_flags = SEMIHOSTING_OPEN_WX;
		break;
	case O_RDWR | O_CREAT | O_APPEND:	/* 'a+' */
		semi_open_flags = SEMIHOSTING_OPEN_AX;
		break;
	default:
		return -1;
	}

	arg.param0 = (uintptr_t)fname;
	arg.param1 = semi_open_flags;
	arg.param2 = strlen(fname);

	return (int)__do_semihosting(SEMIHOSTING_SYS_OPEN, (uintptr_t)&arg);
}

/**
 * @brief Read data from a file on the semihosting host system
 * @param fd: a handle for a file previously opened
 * @param ptr: pointer to a buffer
 * @param len: the number of bytes to read to the buffer from the file
 *
 * @retval zero if OK, the same value as @len if fails, smaller value than @len
 * for partial success
 */
size_t semihosting_read(int fd, void *ptr, size_t len)
{
	struct semihosting_param_t arg = {
		.param0 = fd,
		.param1 = (uintptr_t)ptr,
		.param2 = len
	};

	return __do_semihosting(SEMIHOSTING_SYS_READ, (uintptr_t)&arg);
}

/**
 * @brief Write data into a file on the semihosting host system
 * @param fd: a handle for a file previously opened
 * @param ptr: pointer to a buffer
 * @param len: the number of bytes to be written from the buffer to the file
 *
 * @retval zero if OK, otherwise the number of bytes that are not written
 */
size_t semihosting_write(int fd, const void *ptr, size_t len)
{
	struct semihosting_param_t arg = {
		.param0 = fd,
		.param1 = (uintptr_t)ptr,
		.param2 = len
	};

	return __do_semihosting(SEMIHOSTING_SYS_WRITE, (uintptr_t)&arg);
}

/**
 * @brief Close a file on the semihosting host system
 * @param fd: a handle for a file previously opened
 *
 * @retval zero if OK, -1 if fails
 */
int semihosting_close(int fd)
{
	struct semihosting_param_t arg = {
		.param0 = fd,
	};

	return (int)__do_semihosting(SEMIHOSTING_SYS_CLOSE, (uintptr_t)&arg);
}
