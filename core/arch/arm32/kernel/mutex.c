/*
 * Copyright (c) 2014, Linaro Limited
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
#include <kernel/mutex.h>
#include <kernel/tz_proc.h>
#include <kernel/panic.h>
#include <kernel/tee_common_unpg.h>
#include <trace.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/tee_rpc.h>
#include <mm/core_mmu.h>
#include <sm/teesmc.h>
#include <bitstring.h>
#include <arm32.h>

/*
 * Mutex design:
 * The internals of a mutex is protected with a spinlock which is only held
 * for a brief time while accessing the internals of the mutex.
 *
 * A bitfield is used to allocate a handle (index of a not set bit) for a
 * mutex to identify it to normal world.
 *
 * If mutex_lock() doesn't get the mutex immediately it will cause the
 * thread to sleep in normal world. The sleeping is performed on a mutex
 * handle and a tick value.  A thread sleeps in normal world until it's
 * awakened by another thread telling it to wakeup. In case the "sleeper"
 * is very slow to enter the sleep state in normal world the "waker" may
 * attempt to wake up a "sleeper" before there is anyone, this is what the
 * tick value is for. The "waker" will write its tick value into the wait
 * structure (which int this case will be higher that what the "sleeper"
 * had), if the "sleeper" finds a larger tick value than its own it will
 * not sleep.  Instead the "sleeper" will assume that the mutex is
 * available to take now.
 */

static bitstr_t bit_decl(mutex_handle_db, MUTEX_MAX_NUMBER_OF);
static unsigned mutex_handle_db_spin_lock;

static uint32_t itr_disable(void)
{
	uint32_t cpsr = read_cpsr();
	const uint32_t itrs = CPSR_A | CPSR_I | CPSR_F;

	write_cpsr(cpsr & ~itrs);
	return cpsr & itrs;
}

static void itr_enable(uint32_t itr_status)
{
	uint32_t cpsr = read_cpsr();

	write_cpsr(cpsr | itr_status);
}

static int mutex_handle_get(void)
{
	int handle;

	bit_ffc(mutex_handle_db, MUTEX_MAX_NUMBER_OF, &handle);
	if (handle != -1)
		bit_set(mutex_handle_db, handle);

	if (handle == -1)
		panic();
	return handle;
}

static void mutex_handle_put(int handle)
{
	bool bit_was_set;

	if (handle == -1) /* Uninitialized mutex */
		return;

	TEE_ASSERT(handle < MUTEX_MAX_NUMBER_OF);

	bit_was_set = bit_test(mutex_handle_db, handle);
	if (bit_was_set)
		bit_clear(mutex_handle_db, handle);

	TEE_ASSERT(bit_was_set);
}

static void mutex_check_init(struct mutex *m)
{
	uint32_t old_itr_status;

	if (m->handle != -1)
		return;

	old_itr_status = itr_disable();
	cpu_spin_lock(&mutex_handle_db_spin_lock);

	if (m->handle == -1)
		m->handle = mutex_handle_get();

	cpu_spin_unlock(&mutex_handle_db_spin_lock);
	itr_enable(old_itr_status);
}

void mutex_init(struct mutex *m)
{
	*m = (struct mutex)MUTEX_INITIALIZER;
	mutex_check_init(m);
}

static void mutex_wait_cmd(uint32_t cmd, int handle, uint32_t tick)
{
	struct tee_ta_session *sess = NULL;
	struct teesmc32_arg *arg;
	struct teesmc32_param *params;
	const size_t num_params = 2;
	paddr_t pharg = 0;

	tee_ta_get_current_session(&sess);
	if (sess)
		tee_ta_set_current_session(NULL);

	pharg = thread_rpc_alloc_arg(TEESMC32_GET_ARG_SIZE(num_params));

	/*
	 * If allocation fails, spin on the mutex, maybe there's another
	 * thread that will release the mutex. The only other option is to
	 * panic.
	 */

	if (!pharg)
		goto exit;

	if (!TEE_ALIGNMENT_IS_OK(pharg, struct teesmc32_arg))
		goto exit;

	if (core_pa2va(pharg, &arg))
		goto exit;

	arg->cmd = TEE_RPC_WAIT_MUTEX;
	arg->ret = TEE_ERROR_GENERIC;
	arg->num_params = num_params;
	params = TEESMC32_GET_PARAMS(arg);
	params[0].attr = TEESMC_ATTR_TYPE_VALUE_INPUT;
	params[1].attr = TEESMC_ATTR_TYPE_VALUE_INPUT;
	params[0].u.value.a = cmd;
	params[1].u.value.a = handle;
	params[1].u.value.b = tick;

	thread_rpc_cmd(pharg);
exit:
	thread_rpc_free_arg(pharg);
	if (sess)
		tee_ta_set_current_session(sess);
}

void mutex_lock(struct mutex *m)
{
	bool did_sleep = false;

	mutex_check_init(m);

	while (true) {
		enum mutex_value old_value;
		uint32_t old_itr_status;
		uint32_t tick = 0;
		int handle = -1;

		old_itr_status = itr_disable();
		cpu_spin_lock(&m->spin_lock);

		if (did_sleep)
			m->num_waiters--;

		old_value = m->value;
		if (old_value == MUTEX_VALUE_LOCKED) {
			m->num_waiters++;
			m->tick++;
			tick = m->tick;
			handle = m->handle;
		} else
			m->value = MUTEX_VALUE_LOCKED;


		cpu_spin_unlock(&m->spin_lock);
		itr_enable(old_itr_status);

		if (old_value == MUTEX_VALUE_UNLOCKED)
			return; /* We have the lock */

		/*
		 * Someone else is holding the lock, wait in normal world
		 * for the lock to become available.
		 */
		DMSG("thread: %u sleeping", thread_get_id());
		did_sleep = true;
		mutex_wait_cmd(TEE_WAIT_MUTEX_SLEEP, handle, tick);
	}
}

void mutex_unlock(struct mutex *m)
{
	uint32_t old_itr_status;
	size_t num_waiters;
	int handle;
	uint32_t tick;

	old_itr_status = itr_disable();
	cpu_spin_lock(&m->spin_lock);

	TEE_ASSERT(m->value == MUTEX_VALUE_LOCKED);
	TEE_ASSERT(m->handle != -1);

	m->value = MUTEX_VALUE_UNLOCKED;
	num_waiters = m->num_waiters;

	if (num_waiters) {
		m->tick++;
		handle = m->handle;
		tick = m->tick;
	}

	cpu_spin_unlock(&m->spin_lock);
	itr_enable(old_itr_status);

	if (num_waiters) {
		DMSG("thread: %u waking someone", thread_get_id());
		mutex_wait_cmd(TEE_WAIT_MUTEX_WAKEUP, handle, tick);
	}
}

bool mutex_trylock(struct mutex *m)
{
	uint32_t old_itr_status;
	enum mutex_value old_value;

	old_itr_status = itr_disable();
	cpu_spin_lock(&m->spin_lock);

	old_value = m->value;
	if (old_value == MUTEX_VALUE_UNLOCKED)
		m->value = MUTEX_VALUE_LOCKED;

	cpu_spin_unlock(&m->spin_lock);
	itr_enable(old_itr_status);

	return old_value == MUTEX_VALUE_UNLOCKED;
}

void mutex_destroy(struct mutex *m)
{
	int handle;
	uint32_t old_itr_status;

	/*
	 * Caller guarantees that no one will try to take the mutex so
	 * there's no need to take the spinlock before accessing it.
	 */

	TEE_ASSERT(m->value == MUTEX_VALUE_UNLOCKED);
	TEE_ASSERT(!m->num_waiters);

	handle = m->handle;
	m->handle = -1;
	mutex_wait_cmd(TEE_WAIT_MUTEX_DELETE, handle, 0);

	old_itr_status = itr_disable();
	cpu_spin_lock(&mutex_handle_db_spin_lock);

	mutex_handle_put(handle);

	cpu_spin_unlock(&mutex_handle_db_spin_lock);
	itr_enable(old_itr_status);
}
