#ifndef TEE_PROFILING_H
#define TEE_PROFILING_H

#include <tee_api_types.h>

#if defined(CFG_TA_GPROF_SUPPORT)
TEE_Result syscall_gprof_send(void *buf, size_t len, uint32_t *id);
#else
#define  syscall_gprof_send syscall_not_supported
#endif

#endif /* TEE_PROFILING_H */
