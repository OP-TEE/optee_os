/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 1994-2009  Red Hat, Inc. All rights reserved.
 */

#ifndef _SYS_FCNTL_H_
#define _SYS_FCNTL_H_

#define	_FAPPEND	0x0008	/* append (writes guaranteed at the end) */
#define	_FCREAT		0x0200	/* open with file create */
#define	_FTRUNC		0x0400	/* open with truncation */

/*
 * Flag values for open(2) and fcntl(2)
 */
#define	O_RDONLY	0		/* +1 == FREAD */
#define	O_WRONLY	1		/* +1 == FWRITE */
#define	O_RDWR		2		/* +1 == FREAD|FWRITE */
#define	O_APPEND	_FAPPEND
#define	O_CREAT		_FCREAT
#define	O_TRUNC		_FTRUNC

#endif /* _SYS_FCNTL_H_ */
