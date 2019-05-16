/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019, Linaro Limited
 */

#ifndef __KERNEL_FTRACE_H
#define __KERNEL_FTRACE_H

#include <kernel/tee_ta_manager.h>
#include <user_ta_header.h>

struct elf_load_state;

/*
 * ta_fbuf_init() - Initialize TA ftrace buffer
 * @load_addr:	user TA load address
 * @s:		user TA session
 * @state:	elf state for TA executable
 */
#ifdef CFG_TA_FTRACE_SUPPORT
void ta_fbuf_init(vaddr_t load_addr, struct tee_ta_session *s,
		  struct elf_load_state *state);
#else
static inline void ta_fbuf_init(vaddr_t load_addr __unused,
				struct tee_ta_session *s __unused,
				struct elf_load_state *state __unused)
{
}
#endif

/*
 * ta_fbuf_dump() - Dump TA ftrace buffer to normal world
 * @s:		user TA session
 */
#ifdef CFG_TA_FTRACE_SUPPORT
void ta_fbuf_dump(struct tee_ta_session *s);
#else
static inline void ta_fbuf_dump(struct tee_ta_session *s __unused)
{
}
#endif

/*
 * ftrace_ta_map_lr() - Get original lr in case modified by ftrace
 * @lr:		pointer to lr
 */
#ifdef CFG_TA_FTRACE_SUPPORT
void ftrace_ta_map_lr(uint64_t *lr);
#else
static inline void ftrace_ta_map_lr(uint64_t *lr __unused)
{
}
#endif

#endif /* __KERNEL_FTRACE_H */
