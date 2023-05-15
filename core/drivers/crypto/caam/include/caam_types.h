/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020-2021 NXP
 *
 * CAAM driver data type definition.
 */

#ifndef __CAAM_TYPES_H__
#define __CAAM_TYPES_H__

#include <types_ext.h>

/*
 * Definition of a CAAM buffer type
 */
struct caambuf {
	uint8_t *data;	 /* Data buffer */
	paddr_t paddr;	 /* Physical address of the buffer */
	size_t length;	 /* Number of bytes in the data buffer */
	uint8_t nocache; /* =1 if buffer is not cacheable, 0 otherwise */
};

/*
 * Definition of a CAAM Block buffer. Buffer used to store
 * user source data to build a full algorithm block buffer
 */
struct caamblock {
	struct caambuf buf; /* Data buffer */
	size_t filled;	    /* Current length filled in the buffer */
	size_t max;	    /* Maximum size of the block */
};

/*
 * Definition of key size
 */
struct caamdefkey {
	uint8_t min; /* Minimum size */
	uint8_t max; /* Maximum size */
	uint8_t mod; /* Key modulus */
};

#endif /* __CAAM_TYPES_H__ */
