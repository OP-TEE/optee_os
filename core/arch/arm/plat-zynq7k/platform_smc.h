/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Wind River System
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
#ifndef PLATFORM_SMC_H
#define PLATFORM_SMC_H

#include <sm/optee_smc.h>

/*
 * Read SLCR (System Level Control Register)
 *
 * Call register usage:
 * a0	SMC Function ID, ZYNQ7K_SMC_SLCR_READ
 * a1	Register offset
 * a2-7	Not used
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1	Value read back
 * a2-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_EBADCMD on Invalid input offset:
 * a0	OPTEE_SMC_RETURN_EBADCMD
 * a1	Undefined value
 * a2-3	Not used
 * a4-7	Preserved
 */
#define ZYNQ7K_SMC_FUNCID_SLCR_READ  0x100
#define ZYNQ7K_SMC_SLCR_READ \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_OEM, ZYNQ7K_SMC_FUNCID_SLCR_READ)

/*
 * Write SLCR (System Level Control Register)
 *
 * Call register usage:
 * a0	SMC Function ID, ZYNQ7K_SMC_SLCR_READ
 * a1	Register offset
 * a2	Value to write
 * a3-7	Not used
 *
 * Normal return register usage:
 * a0	OPTEE_SMC_RETURN_OK
 * a1-3	Not used
 * a4-7	Preserved
 *
 * OPTEE_SMC_RETURN_EBADCMD on Invalid input offset:
 * a0	OPTEE_SMC_RETURN_EBADCMD
 * a1-3	Not used
 * a4-7	Preserved
 */
#define ZYNQ7K_SMC_FUNCID_SLCR_WRITE  0x101
#define ZYNQ7K_SMC_SLCR_WRITE \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_OEM, ZYNQ7K_SMC_FUNCID_SLCR_WRITE)

#endif /* PLATFORM_SMC_H */
