/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Linaro Limited
 *
 * The copyright in this software is being made available under the BSD License,
 * included below. This software may be subject to other third party and
 * contributor rights, including patent rights, and no such rights are granted
 * under this license.
 *
 * Copyright (c) 2018 Microsoft Corporation
 *
 * All rights reserved.
 *
 * BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FTPM_TA_H
#define FTPM_TA_H

/* This UUID is generated with uuidgen */
#define TA_FTPM_UUID { 0xBC50D971, 0xD4C9, 0x42C4, \
	{0x82, 0xCB, 0x34, 0x3F, 0xB7, 0xF3, 0x78, 0x96}}

/* The TAFs ID implemented in this TA */
#define TA_FTPM_SUBMIT_COMMAND  (0)
#define TA_FTPM_EMULATE_PPI     (1)

#endif /*FTPM_TA_H*/
