/* SPDX-License-Identifier: BSD-2-Clause */
/* TA call-site C-object capacity checks. Preserve the out-of-line ABI. */
#ifndef TEE_INTERNAL_API_FORTIFY_H
#define TEE_INTERNAL_API_FORTIFY_H

#if (defined(__GNUC__) || defined(__clang__)) && \
	!defined(__OPTEE_LIBUTEE_INTERNAL) && \
	!defined(__OPTEE_DISABLE_TA_API_FORTIFY) && \
	(!defined(__cplusplus) || __cplusplus >= 201103L)

#ifdef __cplusplus
#define __ta_auto auto
#else
#define __ta_auto __auto_type
#endif

/* Reject a known overlong output before entering libutee. */
#define __ta_fail() do { \
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS); \
	__builtin_unreachable(); \
} while (0)

#define __ta_check_bytes(p, captured, n) do { \
	size_t __ta_bos = __builtin_object_size((p), 1); \
	if (__ta_bos == (size_t)-1) \
		__ta_bos = __builtin_object_size((const void *)(captured), 1); \
	if (__ta_bos != (size_t)-1 && \
	    (size_t)(n) > __ta_bos) \
		__ta_fail(); \
} while (0)

#define __ta_check_words(p, captured, n) do { \
	size_t __ta_bos = __builtin_object_size((p), 1); \
	if (__ta_bos == (size_t)-1) \
		__ta_bos = __builtin_object_size((const void *)(captured), 1); \
	if (__ta_bos != (size_t)-1 && \
	    (size_t)(n) > __ta_bos / sizeof(uint32_t)) \
		__ta_fail(); \
} while (0)

/* The public GP 1.1 aliases remain object-like macros. Wrapping their
 * __GP11 symbols preserves function pointer uses of the public names.
 */
#if __OPTEE_CORE_API_COMPAT_1_1

#define __GP11_TEE_MemMove(dest, src, size) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (dest); \
	uint32_t __ta_arg2 = (size); \
	__ta_check_bytes((dest), __ta_arg0, __ta_arg2); \
	__GP11_TEE_MemMove(__ta_arg0, src, __ta_arg2); \
	}))

#define __GP11_TEE_MemFill(buff, x, size) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (buff); \
	uint32_t __ta_arg2 = (size); \
	__ta_check_bytes((buff), __ta_arg0, __ta_arg2); \
	__GP11_TEE_MemFill(__ta_arg0, x, __ta_arg2); \
	}))

#define __GP11_TEE_ReadObjectData(object, buffer, size, count) \
	(__extension__ ({ \
	__ta_auto __ta_arg1 = (buffer); \
	uint32_t __ta_arg2 = (size); \
	__ta_check_bytes((buffer), __ta_arg1, __ta_arg2); \
	__GP11_TEE_ReadObjectData(object, __ta_arg1, __ta_arg2, count); \
	}))

#define __GP11_TEE_GenerateRandom(randomBuffer, randomBufferLen) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (randomBuffer); \
	uint32_t __ta_arg1 = (randomBufferLen); \
	__ta_check_bytes((randomBuffer), __ta_arg0, __ta_arg1); \
	__GP11_TEE_GenerateRandom(__ta_arg0, __ta_arg1); \
	}))

#define __GP11_TEE_BigIntInitFMM(bigIntFMM, len) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (bigIntFMM); \
	uint32_t __ta_arg1 = (len); \
	__ta_check_words((bigIntFMM), __ta_arg0, __ta_arg1); \
	__GP11_TEE_BigIntInitFMM(__ta_arg0, __ta_arg1); \
	}))

#else /* Current API ABI */

#define TEE_MemMove(dest, src, size) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (dest); \
	size_t __ta_arg2 = (size); \
	__ta_check_bytes((dest), __ta_arg0, __ta_arg2); \
	TEE_MemMove(__ta_arg0, src, __ta_arg2); \
	}))

#define TEE_MemFill(buff, x, size) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (buff); \
	size_t __ta_arg2 = (size); \
	__ta_check_bytes((buff), __ta_arg0, __ta_arg2); \
	TEE_MemFill(__ta_arg0, x, __ta_arg2); \
	}))

#define TEE_ReadObjectData(object, buffer, size, count) \
	(__extension__ ({ \
	__ta_auto __ta_arg1 = (buffer); \
	size_t __ta_arg2 = (size); \
	__ta_check_bytes((buffer), __ta_arg1, __ta_arg2); \
	TEE_ReadObjectData(object, __ta_arg1, __ta_arg2, count); \
	}))

#define TEE_GenerateRandom(randomBuffer, randomBufferLen) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (randomBuffer); \
	size_t __ta_arg1 = (randomBufferLen); \
	__ta_check_bytes((randomBuffer), __ta_arg0, __ta_arg1); \
	TEE_GenerateRandom(__ta_arg0, __ta_arg1); \
	}))

#define TEE_BigIntInit(bigInt, len) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (bigInt); \
	size_t __ta_arg1 = (len); \
	__ta_check_words((bigInt), __ta_arg0, __ta_arg1); \
	TEE_BigIntInit(__ta_arg0, __ta_arg1); \
	}))

#define TEE_BigIntInitFMM(bigIntFMM, len) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (bigIntFMM); \
	size_t __ta_arg1 = (len); \
	__ta_check_words((bigIntFMM), __ta_arg0, __ta_arg1); \
	TEE_BigIntInitFMM(__ta_arg0, __ta_arg1); \
	}))

#endif /* __OPTEE_CORE_API_COMPAT_1_1 */

/* TEE_BigIntInit has no GP 1.1 public alias. */
#if __OPTEE_CORE_API_COMPAT_1_1

#define TEE_BigIntInit(bigInt, len) \
	(__extension__ ({ \
	__ta_auto __ta_arg0 = (bigInt); \
	size_t __ta_arg1 = (len); \
	__ta_check_words((bigInt), __ta_arg0, __ta_arg1); \
	TEE_BigIntInit(__ta_arg0, __ta_arg1); \
	}))
#endif

#endif /* compiler and build guard */
#endif /* TEE_INTERNAL_API_FORTIFY_H */
