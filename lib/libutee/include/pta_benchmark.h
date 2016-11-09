/*
 * Copyright (c) 2017, Linaro Limited
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

#ifndef __PTA_BENCHMARK_H
#define __PTA_BENCHMARK_H

/*
 * Interface to the benchmark pseudo-TA, which is used for registering
 * timestamp buffers
 */

#define BENCHMARK_UUID \
		{ 0x0b9a63b0, 0xb4c6, 0x4c85, \
		{ 0xa2, 0x84, 0xa2, 0x28, 0xef, 0x54, 0x7b, 0x4e } }

/*
 * Benchmark PTA supported commands
 */
#define BENCHMARK_CMD(id)	(0xFA190000 | ((id) & 0xFFFF))
#define BENCHMARK_CMD_REGISTER_MEMREF	BENCHMARK_CMD(1)
#define BENCHMARK_CMD_GET_MEMREF		BENCHMARK_CMD(2)
#define BENCHMARK_CMD_UNREGISTER		BENCHMARK_CMD(3)

#endif /* __PTA_BENCHMARK_H */
