/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2016-2017, Linaro Limited
 * Copyright (c) 2020-2021, Arm Limited
 */

#ifndef KERNEL_THREAD_H
#define KERNEL_THREAD_H

#ifndef __ASSEMBLER__
#include <types_ext.h>
#include <compiler.h>
#include <mm/pgt_cache.h>
#endif
#include <util.h>
#include <kernel/thread_arch.h>

#define THREAD_FLAGS_COPY_ARGS_ON_RETURN	BIT(0)
#define THREAD_FLAGS_FOREIGN_INTR_ENABLE	BIT(1)
#define THREAD_FLAGS_EXIT_ON_FOREIGN_INTR	BIT(2)

#define THREAD_ID_0		0
#define THREAD_ID_INVALID	-1

#define THREAD_RPC_MAX_NUM_PARAMS	U(4)

#ifndef __ASSEMBLER__

struct thread_specific_data {
	TAILQ_HEAD(, ts_session) sess_stack;
	struct ts_ctx *ctx;
#ifdef CFG_CORE_FFA
	uint32_t rpc_target_info;
#endif
	uint32_t abort_type;
	uint32_t abort_descr;
	vaddr_t abort_va;
	unsigned int abort_core;
	struct thread_abort_regs abort_regs;
#ifdef CFG_CORE_DEBUG_CHECK_STACKS
	bool stackcheck_recursion;
#endif
	unsigned int syscall_recursion;
};

void thread_init_canaries(void);
void thread_init_primary(void);
void thread_init_per_cpu(void);

struct thread_core_local *thread_get_core_local(void);

/*
 * Sets the stacks to be used by the different threads. Use THREAD_ID_0 for
 * first stack, THREAD_ID_0 + 1 for the next and so on.
 *
 * Returns true on success and false on errors.
 */
bool thread_init_stack(uint32_t stack_id, vaddr_t sp);

/*
 * Initializes thread contexts. Called in thread_init_boot_thread() if
 * virtualization is disabled. Virtualization subsystem calls it for
 * every new guest otherwise.
 */
void thread_init_threads(void);

/*
 * Called by the init CPU. Sets temporary stack mode for all CPUs
 * (curr_thread = -1 and THREAD_CLF_TMP) and sets the temporary stack limit for
 * the init CPU.
 */
void thread_init_thread_core_local(void);
void thread_init_core_local_stacks(void);

#if defined(CFG_CORE_PAUTH)
void thread_init_thread_pauth_keys(void);
void thread_init_core_local_pauth_keys(void);
#else
static inline void thread_init_thread_pauth_keys(void) { }
static inline void thread_init_core_local_pauth_keys(void) { }
#endif

/*
 * Initializes a thread to be used during boot
 */
void thread_init_boot_thread(void);

/*
 * Clears the current thread id
 * Only supposed to be used during initialization.
 */
void thread_clr_boot_thread(void);

/*
 * Returns current thread id.
 */
short int thread_get_id(void);

/*
 * Returns current thread id, return -1 on failure.
 */
short int thread_get_id_may_fail(void);

/* Returns Thread Specific Data (TSD) pointer. */
struct thread_specific_data *thread_get_tsd(void);

/*
 * Sets foreign interrupts status for current thread, must only be called
 * from an active thread context.
 *
 * enable == true  -> enable foreign interrupts
 * enable == false -> disable foreign interrupts
 */
void thread_set_foreign_intr(bool enable);

/*
 * Restores the foreign interrupts status (in CPSR) for current thread, must
 * only be called from an active thread context.
 */
void thread_restore_foreign_intr(void);

/*
 * thread_get_exceptions() - return current exception mask
 */
uint32_t thread_get_exceptions(void);

/*
 * thread_set_exceptions() - set exception mask
 * @exceptions: exception mask to set
 *
 * Any previous exception mask is replaced by this exception mask, that is,
 * old bits are cleared and replaced by these.
 */
void thread_set_exceptions(uint32_t exceptions);

/*
 * thread_mask_exceptions() - Masks (disables) specified asynchronous exceptions
 * @exceptions	exceptions to mask
 * @returns old exception state
 */
uint32_t thread_mask_exceptions(uint32_t exceptions);

/*
 * thread_unmask_exceptions() - Unmasks asynchronous exceptions
 * @state	Old asynchronous exception state to restore (returned by
 *		thread_mask_exceptions())
 */
void thread_unmask_exceptions(uint32_t state);


static inline bool __nostackcheck thread_foreign_intr_disabled(void)
{
	return !!(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
}

/*
 * thread_enter_user_mode() - Enters user mode
 * @a0:		Passed in r/x0 for user_func
 * @a1:		Passed in r/x1 for user_func
 * @a2:		Passed in r/x2 for user_func
 * @a3:		Passed in r/x3 for user_func
 * @user_sp:	Assigned sp value in user mode
 * @user_func:	Function to execute in user mode
 * @is_32bit:   True if TA should execute in Aarch32, false if Aarch64
 * @exit_status0: Pointer to opaque exit staus 0
 * @exit_status1: Pointer to opaque exit staus 1
 *
 * This functions enters user mode with the argument described above,
 * @exit_status0 and @exit_status1 are filled in by thread_unwind_user_mode()
 * when returning back to the caller of this function through an exception
 * handler.
 *
 * @Returns what's passed in "ret" to thread_unwind_user_mode()
 */
uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3, unsigned long user_sp,
		unsigned long entry_func, bool is_32bit,
		uint32_t *exit_status0, uint32_t *exit_status1);

/*
 * thread_unwind_user_mode() - Unwinds kernel stack from user entry
 * @ret:	Value to return from thread_enter_user_mode()
 * @exit_status0: Exit status 0
 * @exit_status1: Exit status 1
 *
 * This is the function that exception handlers can return into
 * to resume execution in kernel mode instead of user mode.
 *
 * This function is closely coupled with thread_enter_user_mode() since it
 * need to restore registers saved by thread_enter_user_mode() and when it
 * returns make it look like thread_enter_user_mode() just returned. It is
 * expected that the stack pointer is where thread_enter_user_mode() left
 * it. The stack will be unwound and the function will return to where
 * thread_enter_user_mode() was called from.  Exit_status0 and exit_status1
 * are filled in the corresponding pointers supplied to
 * thread_enter_user_mode().
 */
void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
		uint32_t exit_status1);

/*
 * Returns the start address (bottom) of the stack for the current thread,
 * zero if there is no current thread.
 */
vaddr_t thread_stack_start(void);


/* Returns the stack size for the current thread */
size_t thread_stack_size(void);

/*
 * Returns the start (top, lowest address) and end (bottom, highest address) of
 * the current stack (thread, temporary or abort stack).
 * When CFG_CORE_DEBUG_CHECK_STACKS=y, the @hard parameter tells if the hard or
 * soft limits are queried. The difference between soft and hard is that for the
 * latter, the stack start includes some additional space to let any function
 * overflow the soft limit and still be able to print a stack dump in this case.
 */
bool get_stack_limits(vaddr_t *start, vaddr_t *end, bool hard);

static inline bool __nostackcheck get_stack_soft_limits(vaddr_t *start,
							vaddr_t *end)
{
	return get_stack_limits(start, end, false);
}

static inline bool __nostackcheck get_stack_hard_limits(vaddr_t *start,
							vaddr_t *end)
{
	return get_stack_limits(start, end, true);
}

bool thread_is_in_normal_mode(void);

/*
 * Returns true if previous exeception also was in abort mode.
 *
 * Note: it's only valid to call this function from an abort exception
 * handler before interrupts has been re-enabled.
 */
bool thread_is_from_abort_mode(void);

/**
 * Allocates data for payload buffers.
 *
 * @size:	size in bytes of payload buffer
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
struct mobj *thread_rpc_alloc_payload(size_t size);

/**
 * Free physical memory previously allocated with thread_rpc_alloc_payload()
 *
 * @mobj:	mobj that describes the buffer
 */
void thread_rpc_free_payload(struct mobj *mobj);

/**
 * Allocate data for payload buffers only shared with the non-secure kernel
 *
 * @size:	size in bytes of payload buffer
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
struct mobj *thread_rpc_alloc_kernel_payload(size_t size);

/**
 * Free physical memory previously allocated with
 * thread_rpc_alloc_kernel_payload()
 *
 * @mobj:	mobj that describes the buffer
 */
void thread_rpc_free_kernel_payload(struct mobj *mobj);

struct thread_param_memref {
	size_t offs;
	size_t size;
	struct mobj *mobj;
};

struct thread_param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

/*
 * Note that there's some arithmetics done on the value so it's important
 * to keep in IN, OUT, INOUT order.
 */
enum thread_param_attr {
	THREAD_PARAM_ATTR_NONE = 0,
	THREAD_PARAM_ATTR_VALUE_IN,
	THREAD_PARAM_ATTR_VALUE_OUT,
	THREAD_PARAM_ATTR_VALUE_INOUT,
	THREAD_PARAM_ATTR_MEMREF_IN,
	THREAD_PARAM_ATTR_MEMREF_OUT,
	THREAD_PARAM_ATTR_MEMREF_INOUT,
};

struct thread_param {
	enum thread_param_attr attr;
	union {
		struct thread_param_memref memref;
		struct thread_param_value value;
	} u;
};

#define THREAD_PARAM_MEMREF(_direction, _mobj, _offs, _size) \
	(struct thread_param){ \
		.attr = THREAD_PARAM_ATTR_MEMREF_ ## _direction, .u.memref = { \
		.mobj = (_mobj), .offs = (_offs), .size = (_size) } \
	}

#define THREAD_PARAM_VALUE(_direction, _a, _b, _c) \
	(struct thread_param){ \
		.attr = THREAD_PARAM_ATTR_VALUE_ ## _direction, .u.value = { \
		.a = (_a), .b = (_b), .c = (_c) } \
	}

/**
 * Does an RPC using a preallocated argument buffer
 * @cmd: RPC cmd
 * @num_params: number of parameters
 * @params: RPC parameters
 * @returns RPC return value
 */
uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
		struct thread_param *params);

/**
 * Allocate data for payload buffers.
 * Buffer is exported to user mode applications.
 *
 * @size:	size in bytes of payload buffer
 *
 * @returns	mobj that describes allocated buffer or NULL on error
 */
struct mobj *thread_rpc_alloc_global_payload(size_t size);

/**
 * Free physical memory previously allocated with
 * thread_rpc_alloc_global_payload()
 *
 * @mobj:	mobj that describes the buffer
 */
void thread_rpc_free_global_payload(struct mobj *mobj);

/*
 * enum thread_shm_type - type of non-secure shared memory
 * @THREAD_SHM_TYPE_APPLICATION - user space application shared memory
 * @THREAD_SHM_TYPE_KERNEL_PRIVATE - kernel private shared memory
 * @THREAD_SHM_TYPE_GLOBAL - user space and kernel shared memory
 */
enum thread_shm_type {
	THREAD_SHM_TYPE_APPLICATION,
	THREAD_SHM_TYPE_KERNEL_PRIVATE,
	THREAD_SHM_TYPE_GLOBAL,
};

/*
 * enum thread_shm_cache_user - user of a cache allocation
 * @THREAD_SHM_CACHE_USER_SOCKET - socket communication
 * @THREAD_SHM_CACHE_USER_FS - filesystem access
 * @THREAD_SHM_CACHE_USER_I2C - I2C communication
 *
 * To ensure that each user of the shared memory cache doesn't interfere
 * with each other a unique ID per user is used.
 */
enum thread_shm_cache_user {
	THREAD_SHM_CACHE_USER_SOCKET,
	THREAD_SHM_CACHE_USER_FS,
	THREAD_SHM_CACHE_USER_I2C,
};

/*
 * Returns a pointer to the cached RPC memory. Each thread and @user tuple
 * has a unique cache. The pointer is guaranteed to point to a large enough
 * area or to be NULL.
 */
void *thread_rpc_shm_cache_alloc(enum thread_shm_cache_user user,
				 enum thread_shm_type shm_type,
				 size_t size, struct mobj **mobj);

#endif /*__ASSEMBLER__*/

#endif /*KERNEL_THREAD_H*/
