/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef TOMCRYPT_ARM_NEON_H
#define TOMCRYPT_ARM_NEON_H

#include <tomcrypt_macros.h>

struct tomcrypt_arm_neon_state {
	ulong32 state;
};

/* Temporarily enables neon instructions */
void tomcrypt_arm_neon_enable(struct tomcrypt_arm_neon_state *state);
/* Disables neon instructions after a call to tomcrypt_arm_neon_enable() */
void tomcrypt_arm_neon_disable(struct tomcrypt_arm_neon_state *state);

#endif /*TOMCRYPT_ARM_NEON_H*/
