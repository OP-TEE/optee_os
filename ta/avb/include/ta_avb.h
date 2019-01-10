/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */

#ifndef __TA_AVB_H
#define __TA_AVB_H

#define TA_AVB_UUID { 0x023f8f1a, 0x292a, 0x432b, \
		      { 0x8f, 0xc4, 0xde, 0x84, 0x71, 0x35, 0x80, 0x67 } }

#define TA_AVB_MAX_ROLLBACK_LOCATIONS	256

/*
 * Gets the rollback index corresponding to the given rollback index slot.
 *
 * in	params[0].value.a:	rollback index slot
 * out	params[1].value.a:	upper 32 bits of rollback index
 * out	params[1].value.b:	lower 32 bits of rollback index
 */
#define TA_AVB_CMD_READ_ROLLBACK_INDEX	0

/*
 * Updates the rollback index corresponding to the given rollback index slot.
 *
 * Will refuse to update a slot with a lower value.
 *
 * in	params[0].value.a:	rollback index slot
 * in	params[1].value.a:	upper 32 bits of rollback index
 * in	params[1].value.b:	lower 32 bits of rollback index
 */
#define TA_AVB_CMD_WRITE_ROLLBACK_INDEX	1

/*
 * Gets the lock state of the device.
 *
 * out	params[0].value.a:	lock state
 */
#define TA_AVB_CMD_READ_LOCK_STATE	2

/*
 * Sets the lock state of the device.
 *
 * If the lock state is changed all rollback slots will be reset to 0
 *
 * in	params[0].value.a:	lock state
 */
#define TA_AVB_CMD_WRITE_LOCK_STATE	3

/*
 * Reads a persistent value corresponding to the given name.
 *
 * in	params[0].memref:	persistent value name
 * out	params[1].memref:	read persistent value buffer
 */
#define TA_AVB_CMD_READ_PERSIST_VALUE	4

/*
 * Writes a persistent value corresponding to the given name.
 *
 * in	params[0].memref:	persistent value name
 * in	params[1].memref:	persistent value buffer to write
 */
#define TA_AVB_CMD_WRITE_PERSIST_VALUE	5

/*
 * Provision public key data.
 *
 * The key can be provisioned only once.
 *
 * A key data provided from NW is serialized in this sequence:
 * +--------------+----------------------------+
 * | Name         | Number of bytes            |
 * +--------------+----------------------------+
 * | key_num_bits | 4 ("modulus size in bits") |
 * | n0inv        | 4 ("-1/n[0] (mod 2^32)")   |
 * | n            | key_num_bits / 8 (modulus) |
 * | rr           | key_num_bits / 8 (R^2)     |
 * +--------------+----------------------------+
 *
 * Public exponent is assumed to always be 65537.
 *
 * So, for example, for 4096 bit(default one) key representation we
 * need 1032 bytes (4 + 4 + 512 + 512) to store these values.
 *
 * in	params[0].memref:	serialized RSA public key data
 */

#define TA_AVB_CMD_PROVISION_PUBLIC_KEY	6
/*
 * Validates a public key data.
 *
 * For key data format check TA_AVB_CMD_PROVISION_PUBLIC_KEY
 *
 * in	params[0].memref:	serialized RSA public key data
 */
#define TA_AVB_CMD_VALIDATE_PUBLIC_KEY	7

#endif /*__TA_AVB_H*/
