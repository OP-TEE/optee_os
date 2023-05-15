/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stdlib.h>

#define CRC32_INIT_VAL	(~0)
#define CRC32		crc32i

uint32_t crc32i(uint32_t crc, const char *buf, size_t len);

#endif /* CRC32_H */
