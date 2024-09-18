/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/***
*       TpmSal.h provides a set of #defines that allow SymCrypt to be built
*       in VS.
*
****/

#ifndef _TPM_SAL_H_
#define _TPM_SAL_H_

#ifndef _Out_writes_bytes_

#define _Out_writes_( cbData )
#define _Out_writes_bytes_( cbData )
#define _Out_writes_opt_( cbData )
#define _Out_writes_to_(n, c)
#define _In_reads_( cbBytes )
#define _In_reads_opt_( cbAuthData )
#define _In_reads_bytes_(size)
#define _Inout_updates_( nStates )
#define _Inout_updates_bytes_(size)
#define _Field_size_( size )
#define _Field_range_( min, max )
#define _Writable_elements_(c)
#define _Ret_writes_bytes_to_(n, c)

#define _Analysis_assume_(x)
#define _Analysis_noreturn_

#define _Use_decl_annotations_

#define __success(x)

#define __assume
#define __analysis_assume
#define _In_
#define _Out_
#define __in
#define __in_opt
#define __in_bcount(x)
#define __in_bcount_opt(x)
#define __in_ecount(x)
#define __in_ecount_opt(x)
#define __in_xcount(x)
#define __out
#define __out_ecount(x)
#define __out_ecount_opt(x)
#define __out_ecount_full(x)
#define __out_ecount_part(x, y)
#define __out_bcount(x)
#define __out_bcount_part_opt(x, y)
#define __out_bcount_full(x)
#define __out_xcount(x)
#define __out_xcount_opt(x)
#define __out_ecount_part(x, y)
#define __out_ecount_part_opt(x, y)
#define __out_opt
#define __inout_ecount(x)
#define __inout_bcount(x)
#define __bound
#define __inout
#define __inout_opt
#define __inout_ecount_opt(x)
#define __deref_out_ecount(x)
#define __deref_opt_out_ecount(x)
#define __field_ecount(x)
#define _Post_invalid_
#define _Pre_maybenull_
#define __checkReturn
#define _In_bytecount_(x)

#endif /* no SAL macros defined */

#ifndef _Interlocked_operand_

#define _Interlocked_operand_

#endif


#endif
