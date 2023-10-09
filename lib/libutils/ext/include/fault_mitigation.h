/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */
#ifndef __FAULT_MITIGATION_H
#define __FAULT_MITIGATION_H

#include <assert.h>
#include <config.h>
#include <string.h>
#include <util.h>

#ifdef __KERNEL__
#include <kernel/panic.h>
#include <kernel/thread.h>
#else
#include <tee_api.h>
#endif

/*
 * Fault migitigation helpers to make successful Hardware Fault Attacks
 * harder to achieve. The paper [1] by Riscure gives background to the
 * problem.
 *
 * These helpers aim to make it hard for a single glitch attack to succeed
 * while the protected function or one of the ftmn_*() functions are
 * executed.
 *
 * To have something to work with we assume that a single glitch may affect
 * a few instructions in sequence to do nothing or to corrupt the content
 * of a few registers.
 *
 * Using the terminology from [1] we are implementing the following patterns:
 * 3 FAULT.VALUE.CHECK
 * 5 FAULT.DECISION.CHECK
 * 9 FAULT.FLOW.CONTROL
 *
 * Additionally are the following patterns also acknowledged with a few
 * comments:
 * 1. FAULT.CONSTANT.CODING
 *	Zero is normally a success code in OP-TEE so special functions are
 *	added to record anything but a zero result.
 * 8. FAULT.NESTED.CHECK
 *	The linked calls performed by for instance FTMN_CALL_FUNC() addresses
 *	this by relying on the called function to update a state in
 *	struct ftmn_func_arg which is checked when the function has returned.
 * 11. FAULT.PENALTY
 *	This is implicit since we're normally trying to protect things post
 *	boot and booting takes quite some time.
 *
 * [1] https://web.archive.org/web/20220616035354/https://www.riscure.com/uploads/2020/05/Riscure_Whitepaper_Fault_Mitigation_Patterns_final.pdf
 */

#include <stdint.h>
#include <stdbool.h>

/*
 * struct ftmn_check - track current checked state
 * @steps:	accumulated checkpoints
 * @res:	last stored result or return value
 *
 * While a function is executed it can update its state as a way of keeping
 * track of important passages inside the function. When the function
 * returns with for instance ftmn_return_res() it is checked that the
 * accumulated state matches the expected state.
 *
 * @res is xored with FTMN_DEFAULT_HASH in order to retrieve the saved
 * result or return value.
 */
struct ftmn_check {
	unsigned long steps;
	unsigned long res;
};

/*
 * struct ftmn_func_arg - track a called function
 * @hash:	xor bitmask
 * @res:	stored result xored with @hash
 *
 * When the call of a function is tracked @hash is initialized to hash of
 * caller xored with hash of called function. Before the called function
 * updates @res it first xors @hash with its own hash, which is supposed to
 * restore @hash to the hash of the calling function. This allows the
 * calling function to confirm that the correct function has been called.
 */
struct ftmn_func_arg {
	unsigned long hash;
	unsigned long res;
};

/*
 * struct ftmn - link a tracked call chain
 * @check:	local checked state
 * @arg:	argument for the next called tracked function
 * @saved_arg:	pointer to an optional argument passed to this function
 * @arg_pp:	cached return value from __ftmn_get_tsd_func_arg_pp()
 * @my_hash:	the hash of the calling function
 * @called_hash:the hash of the called function
 *
 * In order to maintain the linked call chain of tracked functions the
 * struct ftmn_func_arg passed to this function is saved in @saved_arg
 * before updating the argument pointer with @arg.
 */
struct ftmn {
	struct ftmn_check check;
	struct ftmn_func_arg arg;
	struct ftmn_func_arg *saved_arg;
	struct ftmn_func_arg **arg_pp;
	unsigned long my_hash;
	unsigned long called_hash;
};

/*
 * enum ftmn_incr - increase counter values
 *
 * Prime numbers to be used when increasing the accumulated state.
 * Different increase counters can be used to keep apart different
 * checkpoints.
 */
enum ftmn_incr {
	FTMN_INCR0 = 7873,
	FTMN_INCR1 = 7877,
	FTMN_INCR2 = 7879,
	FTMN_INCR3 = 7883,
	FTMN_INCR4 = 7901,
	FTMN_INCR5 = 7907,
	FTMN_INCR_RESERVED = 7919,
};

typedef int (*ftmn_memcmp_t)(const void *p1, const void *p2, size_t nb);

/* The default hash used when xoring the result in struct ftmn_check */
#ifdef __ILP32__
#define FTMN_DEFAULT_HASH	0x9c478bf6UL
#else
#define FTMN_DEFAULT_HASH	0xc478bf63e9500cb5UL
#endif

/*
 * FTMN_PANIC() - FTMN specific panic function
 *
 * This function is called whenever the FTMN function detects an
 * inconsistency. An inconsistency is able to occur if the system is
 * subject to a fault injection attack, in this case doing a panic() isn't
 * an extreme measure.
 */
#ifdef __KERNEL__
#define FTMN_PANIC()	panic();
#else
#define FTMN_PANIC()	TEE_Panic(0);
#endif

#define __FTMN_MAX_FUNC_NAME_LEN	256

#define __FTMN_FUNC_BYTE(f, o, l)	((o) < (l) ? (uint8_t)(f)[(o)] : 0)

#define __FTMN_GET_FUNC_U64(f, o, l) \
	(SHIFT_U64(__FTMN_FUNC_BYTE((f), (o), (l)), 0) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 1, (l)), 8) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 2, (l)), 16) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 3, (l)), 24) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 4, (l)), 32) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 5, (l)), 40) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 6, (l)), 48) | \
	 SHIFT_U64(__FTMN_FUNC_BYTE((f), (o) + 7, (l)), 56))

#define __FTMN_FUNC_HASH32(f, o, l) \
	(__FTMN_GET_FUNC_U64((f), (o), (l)) ^ \
	 __FTMN_GET_FUNC_U64((f), (o) + 8, (l)))

#define __FTMN_FUNC_HASH16(f, o, l) \
	(__FTMN_FUNC_HASH32((f), (o), (l)) ^ \
	 __FTMN_FUNC_HASH32((f), (o) + __FTMN_MAX_FUNC_NAME_LEN / 16, (l)))

#define __FTMN_FUNC_HASH8(f, o, l) \
	(__FTMN_FUNC_HASH16((f), (o), (l)) ^ \
	 __FTMN_FUNC_HASH16((f), (o) + __FTMN_MAX_FUNC_NAME_LEN / 8, (l)))

#define __FTMN_FUNC_HASH4(f, o, l) \
	(__FTMN_FUNC_HASH8((f), (o), (l)) ^ \
	 __FTMN_FUNC_HASH8((f), (o) + __FTMN_MAX_FUNC_NAME_LEN / 4, (l)))

#define __FTMN_FUNC_HASH2(f, l) \
	(__FTMN_FUNC_HASH4(f, 0, l) ^ \
	 __FTMN_FUNC_HASH4(f, __FTMN_MAX_FUNC_NAME_LEN / 2, l))

#ifdef __ILP32__
#define __FTMN_FUNC_HASH(f, l) \
	(unsigned long)(__FTMN_FUNC_HASH2((f), (l)) ^ \
		        (__FTMN_FUNC_HASH2((f), (l)) >> 32))
#else
#define __FTMN_FUNC_HASH(f, l)	(unsigned long)__FTMN_FUNC_HASH2((f), (l))
#endif

#define __ftmn_step_count_1(c0) ((c0) * FTMN_INCR0)
#define __ftmn_step_count_2(c0, c1) \
	(__ftmn_step_count_1(c0) + (c1) * FTMN_INCR1)
#define __ftmn_step_count_3(c0, c1, c2) \
	(__ftmn_step_count_2(c0, c1) + (c2) * FTMN_INCR2)
#define __ftmn_step_count_4(c0, c1, c2, c3)	\
	(__ftmn_step_count_3(c0, c1, c2) + (c3) * FTMN_INCR3)
#define __ftmn_step_count_5(c0, c1, c2, c3, c4)	\
	(__ftmn_step_count_4(c0, c1, c2, c3) + (c4) * FTMN_INCR4)
#define __ftmn_step_count_6(c0, c1, c2, c3, c4, c5)	\
	(__ftmn_step_count_5(c0, c1, c2, c3, c4) + (c5) * FTMN_INCR5)
#define ___ftmn_args_count(_0, _1, _2, _3, _4, _5, x, ...) x
#define __ftmn_args_count(...) \
	___ftmn_args_count(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define ___ftmn_step_count(count, ...)	__ftmn_step_count_ ## count(__VA_ARGS__)
#define __ftmn_step_count(count, ...)	___ftmn_step_count(count, __VA_ARGS__)

unsigned long ___ftmn_return_res(struct ftmn_check *check, unsigned long steps,
				 unsigned long res);
void ___ftmn_expect_state(struct ftmn_check *check, enum ftmn_incr incr,
			  unsigned long steps, unsigned long res);

void ___ftmn_callee_done(struct ftmn_func_arg *arg, unsigned long my_hash,
			 unsigned long res);
void ___ftmn_callee_done_not_zero(struct ftmn_func_arg *arg,
				  unsigned long my_hash,
				  unsigned long res);
void ___ftmn_callee_done_memcmp(struct ftmn_func_arg *arg,
				unsigned long my_hash, int res,
				ftmn_memcmp_t my_memcmp,
				const void *p1, const void *p2, size_t nb);
void ___ftmn_callee_done_check(struct ftmn_func_arg *arg, unsigned long my_hash,
			       struct ftmn_check *check, enum ftmn_incr incr,
			       unsigned long steps, unsigned long res);

void ___ftmn_callee_update_not_zero(struct ftmn_func_arg *arg,
				    unsigned long res);

void ___ftmn_set_check_res(struct ftmn_check *check, enum ftmn_incr incr,
			   unsigned long res);
void ___ftmn_set_check_res_not_zero(struct ftmn_check *check,
				    enum ftmn_incr incr,
				    unsigned long res);
void ___ftmn_set_check_res_memcmp(struct ftmn_check *check, enum ftmn_incr incr,
				  int res, ftmn_memcmp_t my_memcmp,
				  const void *p1, const void *p2, size_t nb);

void ___ftmn_copy_linked_call_res(struct ftmn_check *check, enum ftmn_incr incr,
				  struct ftmn_func_arg *arg, unsigned long res);


#ifndef __KERNEL__
extern struct ftmn_func_arg *__ftmn_global_func_arg;
#endif

static inline struct ftmn_func_arg **__ftmn_get_tsd_func_arg_pp(void)
{
#if defined(CFG_FAULT_MITIGATION) && defined(__KERNEL__)
	if (thread_get_id_may_fail() >= 0)
		return &thread_get_tsd()->ftmn_arg;
	else
		return &thread_get_core_local()->ftmn_arg;
#elif defined(CFG_FAULT_MITIGATION)
	return &__ftmn_global_func_arg;
#else
	return NULL;
#endif
}

static inline struct ftmn_func_arg *__ftmn_get_tsd_func_arg(void)
{
	struct ftmn_func_arg **pp = __ftmn_get_tsd_func_arg_pp();

	if (!pp)
		return NULL;

	return *pp;
}

static inline void __ftmn_push_linked_call(struct ftmn *ftmn,
					 unsigned long my_hash,
					 unsigned long called_hash)
{
	struct ftmn_func_arg **arg_pp = __ftmn_get_tsd_func_arg_pp();

	if (arg_pp) {
		ftmn->arg_pp = arg_pp;
		ftmn->my_hash = my_hash;
		ftmn->called_hash = called_hash;
		ftmn->saved_arg = *ftmn->arg_pp;
		*ftmn->arg_pp = &ftmn->arg;
		ftmn->arg.hash = my_hash;
	}
}

static inline void __ftmn_pop_linked_call(struct ftmn *ftmn)
{
	if (ftmn->arg_pp)
		*ftmn->arg_pp = ftmn->saved_arg;
}

static inline void __ftmn_copy_linked_call_res(struct ftmn *f,
					       enum ftmn_incr incr,
					       unsigned long res)
{
	if (f->arg_pp) {
		assert(f->arg.hash == (f->my_hash ^ f->called_hash));
		assert(&f->arg == *f->arg_pp);
		assert((f->arg.hash ^ f->arg.res) == res);
		___ftmn_copy_linked_call_res(&f->check, incr, &f->arg, res);
	}
}

static inline void __ftmn_calle_swap_hash(struct ftmn_func_arg *arg,
					  unsigned long my_old_hash,
					  unsigned long my_new_hash)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION) && arg)
		arg->hash ^= my_old_hash ^ my_new_hash;
}

static inline void __ftmn_callee_done(struct ftmn_func_arg *arg,
				      unsigned long my_hash, unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION) && arg)
		___ftmn_callee_done(arg, my_hash, res);
}

static inline void __ftmn_callee_done_not_zero(struct ftmn_func_arg *arg,
					       unsigned long hash,
					       unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION) && arg)
		___ftmn_callee_done_not_zero(arg, hash, res);
}

static inline int
__ftmn_callee_done_memcmp(struct ftmn_func_arg *arg, unsigned long hash,
			  ftmn_memcmp_t my_memcmp,
			  const void *p1, const void *p2, size_t nb)
{
	int res = my_memcmp(p1, p2, nb);

	if (IS_ENABLED(CFG_FAULT_MITIGATION) && arg)
		___ftmn_callee_done_memcmp(arg, hash, res, my_memcmp,
					   p1, p2, nb);

	return res;
}

static inline void __ftmn_callee_done_check(struct ftmn *ftmn,
					    unsigned long my_hash,
					    enum ftmn_incr incr,
					    unsigned long steps,
					    unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION))
		___ftmn_callee_done_check(__ftmn_get_tsd_func_arg(), my_hash,
					  &ftmn->check, incr, steps, res);
}

static inline void __ftmn_callee_update_not_zero(struct ftmn_func_arg *arg,
						 unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION) && arg)
		___ftmn_callee_update_not_zero(arg, res);
}

static inline void __ftmn_set_check_res(struct ftmn *ftmn, enum ftmn_incr incr,
				      unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION))
		___ftmn_set_check_res(&ftmn->check, incr, res);
}

static inline void __ftmn_set_check_res_not_zero(struct ftmn *ftmn,
					       enum ftmn_incr incr,
					       unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION))
		___ftmn_set_check_res_not_zero(&ftmn->check, incr, res);
}



/*
 * FTMN_FUNC_HASH() - "hash" a function name
 *
 * Function names are "hashed" into an unsigned long. The "hashing" is done
 * by xoring each 32/64 bit word of the function name producing a bit
 * pattern that should be mostly unique for each function. Only the first
 * 256 characters of the name are used when xoring as this is expected to
 * be optimized to be calculated when compiling the source code in order to
 * minimize the overhead.
 */
#define FTMN_FUNC_HASH(name)	__FTMN_FUNC_HASH(name, sizeof(name))

/*
 * FTMN_PUSH_LINKED_CALL() - push call into a linked call chain
 * @ftmn:		The local struct ftmn
 * @called_func_hash:	The hash of the called function
 *
 * Inserts a call into a linked call chain or starts a new call chain if
 * the passed struct ftmn_func_arg pointer was NULL.
 *
 * Each FTMN_PUSH_LINKED_CALL() is supposed to be matched by a
 * FTMN_POP_LINKED_CALL().
 */
#define FTMN_PUSH_LINKED_CALL(ftmn, called_func_hash) \
	__ftmn_push_linked_call((ftmn), FTMN_FUNC_HASH(__func__), \
				(called_func_hash))

/*
 * FTMN_SET_CHECK_RES_FROM_CALL() - copy the result from a linked call
 * @ftmn:	The struct ftmn used during the linked call
 * @incr:	Value to increase the checked state with
 * @res:	Returned result to be match against the saved/copied result
 *
 * This macro is called just after a checked linked function has returned.
 * The return value from the function is copied from the struct ftmn_func_arg
 * passed to the called function into the local checked state. The checked
 * state is increased with @incr. @res is checked against the saved result
 * of the called function.
 */
#define FTMN_SET_CHECK_RES_FROM_CALL(ftmn, incr, res) \
	__ftmn_copy_linked_call_res((ftmn), (incr), (res))

/*
 * FTMN_POP_LINKED_CALL() - remove a call from a linked call chain
 * @ftmn:	The local struct ftmn
 *
 * Supposed to match a call to FTMN_PUSH_LINKED_CALL()
 */
#define FTMN_POP_LINKED_CALL(ftmn) __ftmn_pop_linked_call((ftmn))

/*
 * FTMN_CALL_FUNC() - Do a linked call to a function
 * @res:	Variable to be assigned the result of the called function
 * @ftmn:	The local struct ftmn
 * @incr:	Value to increase the checked state with
 * @func:	Function to be called
 * @...:	Arguments to pass to @func
 *
 * This macro can be used to make a linked call to another function, the
 * callee. This macro depends on the callee to always update the struct
 * ftmn_func_arg (part of struct ftmn) even when returning an error.
 *
 * Note that in the cases where the callee may skip updating the struct
 * ftmn_func_arg this macro cannot be used as
 * FTMN_SET_CHECK_RES_FROM_CALL() would cause a panic due to mismatching
 * return value and saved result.
 */
#define FTMN_CALL_FUNC(res, ftmn, incr, func, ...) \
	do { \
		FTMN_PUSH_LINKED_CALL((ftmn), FTMN_FUNC_HASH(#func)); \
		(res) = func(__VA_ARGS__); \
		FTMN_SET_CHECK_RES_FROM_CALL((ftmn), (incr), (res)); \
		FTMN_POP_LINKED_CALL((ftmn)); \
	} while (0)

/*
 * FTMN_CALLEE_DONE() - Record result of callee
 * @res:	Result or return value
 *
 * The passed result will be stored in the struct ftmn_func_arg struct
 * supplied by the caller. This function must only be called once by the
 * callee.
 *
 * Note that this function is somewhat dangerous as any passed value will
 * be stored so if the value has been tampered with there is no additional
 * redundant checks to rely on.
 */
#define FTMN_CALLEE_DONE(res) \
	__ftmn_callee_done(__ftmn_get_tsd_func_arg(), \
			   FTMN_FUNC_HASH(__func__), (res))
/*
 * FTMN_CALLEE_DONE_NOT_ZERO() - Record non-zero result of callee
 * @res:	Result or return value
 *
 * The passed result will be stored in the struct ftmn_func_arg struct
 * supplied by the caller. This function must only be called once by the
 * callee.
 *
 * Note that this function is somewhat dangerous as any passed value will
 * be stored so if the value has been tampered with there is no additional
 * redundant checks to rely on. However, there are extra checks against
 * unintentionally storing a zero which often is interpreted as a
 * successful return value.
 */
#define FTMN_CALLEE_DONE_NOT_ZERO(res) \
	__ftmn_callee_done_not_zero(__ftmn_get_tsd_func_arg(), \
				    FTMN_FUNC_HASH(__func__), (res))

/*
 * FTMN_CALLEE_DONE_CHECK() - Record result of callee with checked state
 * @ftmn:	The local struct ftmn
 * @incr:	Value to increase the checked state with
 * @exp_steps:	Expected recorded checkpoints
 * @res:	Result or return value
 *
 * The passed result will be stored in the struct ftmn_func_arg struct
 * supplied by the caller. This function must only be called once by the
 * callee.
 *
 * @res is double checked against the value stored in local checked state.
 * @exp_steps is checked against the locate checked state. The local
 * checked state is increased by @incr.
 */
#define FTMN_CALLEE_DONE_CHECK(ftmn, incr, exp_steps, res) \
	__ftmn_callee_done_check((ftmn), FTMN_FUNC_HASH(__func__), \
				 (incr), (exp_steps), (res))

/*
 * FTMN_CALLEE_DONE_MEMCMP() - Record result of memcmp() in a callee
 * @my_memcmp:		Function pointer of custom memcmp()
 * @p1:			Pointer to first buffer
 * @p2:			Pointer to second buffer
 * @nb:			Number of bytes
 *
 * The result from the mem compare is saved in the local checked state.
 * This function must only be called once by the callee.
 */
#define FTMN_CALLEE_DONE_MEMCMP(my_memcmp, p1, p2, nb) \
	__ftmn_callee_done_memcmp(__ftmn_get_tsd_func_arg(), \
				  FTMN_FUNC_HASH(__func__), (my_memcmp), \
				  (p1), (p2), (nb))

/*
 * FTMN_CALLEE_UPDATE_NOT_ZERO() - Update the result of a callee with a
 *				   non-zero value
 * @res:	Result or return value
 *
 * The passed result will be stored in the struct ftmn_func_arg struct
 * supplied by the caller. This function can be called any number of times
 * by the callee, provided that one of the FTMN_CALLEE_DONE_XXX() functions
 * has been called first.
 *
 * Note that this function is somewhat dangerous as any passed value will
 * be stored so if the value has been tampered with there is no additional
 * redundant checks to rely on. However, there are extra checks against
 * unintentionally storing a zero which often is interpreted as a
 * successful return value.
 */
#define FTMN_CALLEE_UPDATE_NOT_ZERO(res) \
	__ftmn_callee_update_not_zero(__ftmn_get_tsd_func_arg(), res)

/*
 * FTMN_CALLEE_SWAP_HASH() - Remove old hash and add new hash
 * @my_old_hash:	The old hash to remove
 *
 * This macro replaces the old expected function hash with the hash of the
 * current function.
 *
 * If a function is called using an alias the caller uses the hash of the
 * alias not the real function name. This hash is recoded in the field
 * "hash" in struct ftmn_func_arg which can be found with
 * __ftmn_get_tsd_func_arg().
 *
 * The FTMN_CALLE_* functions only work with the real function name so the
 * old hash must be removed and replaced with the new for the calling
 * function to be able to verify the result.
 */
#define FTMN_CALLEE_SWAP_HASH(my_old_hash) \
	__ftmn_calle_swap_hash(__ftmn_get_tsd_func_arg(), \
			       (my_old_hash), FTMN_FUNC_HASH(__func__))

/*
 * FTMN_SET_CHECK_RES() - Records a result in local checked state
 * @ftmn:	The local struct ftmn
 * @incr:	Value to increase the checked state with
 * @res:	Result or return value
 *
 * Note that this function is somewhat dangerous as any passed value will
 * be stored so if the value has been tampered with there is no additional
 * redundant checks to rely on.
 */
#define FTMN_SET_CHECK_RES(ftmn, incr, res) \
	__ftmn_set_check_res((ftmn), (incr), (res))

/*
 * FTMN_SET_CHECK_RES_NOT_ZERO() - Records a non-zero result in local checked
 *				   state
 * @ftmn:	The local struct ftmn
 * @incr:	Value to increase the checked state with
 * @res:	Result or return value
 *
 * Note that this function is somewhat dangerous as any passed value will
 * be stored so if the value has been tampered with there is no additional
 * redundant checks to rely on. However, there are extra checks against
 * unintentionally storing a zero which often is interpreted as a
 * successful return value.
 */
#define FTMN_SET_CHECK_RES_NOT_ZERO(ftmn, incr, res) \
	__ftmn_set_check_res_not_zero((ftmn), (incr), (res))

static inline int ftmn_set_check_res_memcmp(struct ftmn *ftmn,
					    enum ftmn_incr incr,
					    ftmn_memcmp_t my_memcmp,
					    const void *p1, const void *p2,
					    size_t nb)
{
	int res = my_memcmp(p1, p2, nb);

	if (IS_ENABLED(CFG_FAULT_MITIGATION))
		___ftmn_set_check_res_memcmp(&ftmn->check, incr, res,
					     my_memcmp, p1, p2, nb);

	return res;
}

/*
 * FTMN_STEP_COUNT() - Calculate total step count
 *
 * Takes variable number of arguments, up to a total of 6. Where arg0
 * is the number of times the counter has been increased by FTMN_INCR0,
 * arg1 FTMN_INCR1 and so on.
 */
#define FTMN_STEP_COUNT(...)	\
	__ftmn_step_count(__ftmn_args_count(__VA_ARGS__), __VA_ARGS__)

/*
 * ftmn_checkpoint() - Add a checkpoint
 * @ftmn:	The local struct ftmn
 * @incr:	Value to increase the checked state with
 *
 * Adds a checkpoint by increasing the internal checked state. This
 * can be checked at a later point in the calling function, for instance
 * with ftmn_return_res().
 */
static inline void ftmn_checkpoint(struct ftmn *ftmn, enum ftmn_incr incr)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION)) {
		/*
		 * The purpose of the barriers is to prevent the compiler
		 * from optimizing this increase to some other location
		 * in the calling function.
		 */
		barrier();
		ftmn->check.steps += incr;
		barrier();
	}
}

/*
 * ftmn_expect_state() - Check expected state
 * @ftmn:	The local struct ftmn
 * @incr:	Value to increase the checked state with
 * @steps:	Expected accumulated steps
 * @res:	Expected saved result or return value
 *
 * This is a more advanced version of ftmn_checkpoint() which before
 * increasing the accumulated steps first checks the accumulated steps and
 * saved result or return value.
 */
static inline void ftmn_expect_state(struct ftmn *ftmn,
				     enum ftmn_incr incr, unsigned long steps,
				     unsigned long res)
{
	if (IS_ENABLED(CFG_FAULT_MITIGATION)) {
		assert((ftmn->check.res ^ FTMN_DEFAULT_HASH) == res);
		assert(ftmn->check.steps == steps);

		___ftmn_expect_state(&ftmn->check, incr, steps, res);
	}
}

/*
 * ftmn_return_res() - Check and return result
 * @ftmn:	The local struct ftmn
 * @steps:	Expected accumulated steps
 * @res:	Expected saved result or return value
 *
 * Checks that the internal accumulated state matches the supplied @steps
 * and that the saved result or return value matches the supplied one.
 *
 * Returns @res.
 */
static inline unsigned long ftmn_return_res(struct ftmn *ftmn,
					    unsigned long steps,
					    unsigned long res)
{
	/*
	 * We're expecting that the compiler does a tail call optimization
	 * allowing ___ftmn_return_res() to have full control over the
	 * returned value. Thus trying to reduce the window where the
	 * return value can be tampered with.
	 */
	if (IS_ENABLED(CFG_FAULT_MITIGATION)) {
		assert((ftmn->check.res ^ FTMN_DEFAULT_HASH) == res);
		assert(ftmn->check.steps == steps);

		return ___ftmn_return_res(&ftmn->check, steps, res);
	}
	return res;
}
#endif /*__FAULT_MITIGATION_H*/
