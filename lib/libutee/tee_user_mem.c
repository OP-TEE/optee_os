/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <compiler.h>
#include <utee_defines.h>
#include <sys/queue.h>
#include <tee_api.h>
#include <util.h>
#include "tee_user_mem.h"
#include "utee_misc.h"

#ifdef CFG_NO_USER_MALLOC_GARBAGE

void *tee_user_mem_alloc(size_t len, uint32_t hint)
{
	uint8_t *p;

	switch (hint) {
	case TEE_MALLOC_FILL_ZERO:
	case TEE_USER_MEM_HINT_NO_FILL_ZERO:
		break;
	default:
		EMSG("Invalid alloc hint [%X]", (unsigned int)hint);
		return NULL;
	}

	p = utee_malloc(len);
	if (p == NULL)
		return NULL;

	if (hint == TEE_MALLOC_FILL_ZERO)
		memset(p, 0, len);
#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
	if (hint == (typeof(hint)) TEE_USER_MEM_HINT_NO_FILL_ZERO)
		memset(p, 0xBB, len);
#endif
	return p;
}

void *tee_user_mem_realloc(void *buffer, size_t len)
{
	return utee_realloc(buffer, len);
}

void tee_user_mem_free(void *buffer)
{
	utee_free(buffer);
}

void tee_user_mem_mark_heap(void)
{
}

size_t tee_user_mem_check_heap(void)
{
	return 0;
}

#else /* CFG_NO_USER_MALLOC_GARBAGE */

/*
 * Manage and track the memory allocation in the libc heap of the user side (TA)
 * Register all allocations and the current TA Provide a garbage api to delete
 * all allocations of a given TA.
 */

/*
 * ARTIST is a magic number to be compliant to a allocation/free of 0 size.
 */
static const void *ARTIST = (void *)0x10;

/*
 * Link list definition for tracking the memory activity.
 */
struct user_mem_elem {
	TAILQ_ENTRY(user_mem_elem) link;
	size_t len;
	uint32_t hint;
};
TAILQ_HEAD(user_mem_head, user_mem_elem) user_mem_head =
TAILQ_HEAD_INITIALIZER(user_mem_head);

/*
 * Debug tools.
 */
#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
struct tee_user_mem_stats {
	int nb_alloc;
	size_t size;
};
static void tee_user_mem_status(struct tee_user_mem_stats *stats);

/* Extra size of memory to add canary line check */
static const size_t CANARY_LINE_SIZE = 1;
#else
static const size_t CANARY_LINE_SIZE;
#endif

/*
 * Accessors from an element of the list and its attribute.
 */
static inline void *buf_addr(const struct user_mem_elem *e)
{
	return (uint8_t *)e + sizeof(struct user_mem_elem);
}

static inline size_t buf_size(const struct user_mem_elem *e)
{
	return e->len - sizeof(struct user_mem_elem) - CANARY_LINE_SIZE;
}

static inline void *elem_addr(const void *buffer)
{
	return (uint8_t *)buffer - sizeof(struct user_mem_elem);
}

/*
 * Check if a given buffer address has been allocated with this tool.
 */
static int is_buffer_valid(void *buffer)
{
	struct user_mem_elem *e;

	TAILQ_FOREACH(e, &user_mem_head, link) {
		if (buf_addr(e) == buffer)
			return 1;
	}
	return 0;
}

#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
/*
 * Common print of an element.
 */
#if (TRACE_LEVEL > 0)
static void print_buf(int tl, const char *func, int line, const char *prefix,
		      const struct user_mem_elem *e)
{
	trace_printf(NULL, 0, tl, true,
		    "%s:%d: %slink:[%p], buf:[%p:%zu]\n",
		    func, line, prefix, (void *)e, buf_addr(e), buf_size(e));
}

#define PB(trace_level, prefix, elem) { print_buf(trace_level, __func__, \
					  __LINE__, prefix, elem); }
#else
#define PB(trace_level, prefix, elem) (void)0
#endif /* TRACE_LEVEL */

/*
 * Heap mark to track leak.
 *
 * Can't use OS21 partition api to be compatible with TZ.
 *
 * Can't use generic mallinfo to dump the libc heap because the tee core
 * use also this heap.
 *
 * So use a simple static var which is updated on tee_user_mem_ operations.
 */
static size_t heap_level;

/*
 * global stats to summarize memory activities cross TA's.
 */
static struct tee_user_mem_stats global_stats;

static void heap_inc(size_t size)
{
	INMSG("%zu", size);
	heap_level += size;

	global_stats.nb_alloc++;
	global_stats.size += size;
	OUTMSG("%zu", global_stats.size);
}

static void heap_dec(size_t size)
{
	INMSG("%zu %zu", heap_level, size);
	heap_level -= size;

	global_stats.nb_alloc--;
	global_stats.size -= size;
	OUTMSG("%zu", global_stats.size);
}

/*
 * Check integrity of the buffer and the list.
 */
static int check_elem_end(struct user_mem_elem *e)
{
	uint8_t *cp = (uint8_t *)e;

	/*
	 * The following check detects storing off the end of the allocated
	 * space in the buffer by comparing the end of buffer checksum with the
	 * address of the buffer.
	 */
	if ((cp[e->len - CANARY_LINE_SIZE] !=
	     ((((uintptr_t) cp) & 0xFF) ^ 0xC5))) {
		PB(TRACE_ERROR, "Corrupted: ", e);
		return 0;
	}

	return 1;
}

static int check_elem(struct user_mem_elem *ap)
{
	struct user_mem_elem *e;

	/* Validate queue links */
	if (!ap)
		return 0;

	if ((uintptr_t)ap & 0x3) {
		EMSG("corrupted allocations");
		TEE_Panic(0);
	}

	e = TAILQ_NEXT(ap, link);
	if (e != NULL && TAILQ_PREV(e, user_mem_head, link) != ap) {
		PB(TRACE_ERROR, "Orphaned: ", e);
		return 0;
	}

	e = TAILQ_PREV(ap, user_mem_head, link);
	if (e != NULL && TAILQ_NEXT(e, link) != ap) {
		PB(TRACE_ERROR, "Orphaned: ", e);
		return 0;
	}

	return check_elem_end(ap);
}

/* In debug mode, trap PC element are corrupted. */
static int is_mem_coherent(void)
{
	struct user_mem_elem *e;

	TAILQ_FOREACH(e, &user_mem_head, link) {
		if (!check_elem(e)) {
			assert(0);
			return 0;
		}
	}
	return 1;
}

#else /* CFG_TEE_CORE_USER_MEM_DEBUG */
static void heap_inc(size_t size  __unused)
{
}

static void heap_dec(size_t size  __unused)
{
}

#define PB(trace_level, prefix, elem) do {} while (0)
#endif /* CFG_TEE_CORE_USER_MEM_DEBUG */

/*
 *  API methods
 */

/*
 * Allocate buffer, enqueing on the orphaned buffer tracking list.
 */
void *tee_user_mem_alloc(size_t len, uint32_t hint)
{
	uint8_t *cp;
	void *buf = NULL;
	size_t total_len =
	    len + sizeof(struct user_mem_elem) + CANARY_LINE_SIZE;


	INMSG("%zu 0x%" PRIx32, len, hint);

	if ((int)len < 0) {
		OUTMSG("0x0");
		return NULL;
	}

	if (len == 0) {
		OUTMSG("%p", ARTIST);
		return (void *)ARTIST;
	}

	/* Check hint */
	switch (hint) {
	case TEE_MALLOC_FILL_ZERO:
	case TEE_USER_MEM_HINT_NO_FILL_ZERO:
		break;
	default:
		EMSG("Invalid alloc hint [0x%" PRIx32 "]", hint);
		OUTMSG("0x0");
		return NULL;
	}

	cp = utee_malloc(total_len);
	if (cp != NULL) {
		struct user_mem_elem *e = (struct user_mem_elem *)(void *)cp;
		e->len = total_len;
		e->hint = hint;
		heap_inc(total_len);

		/* Enqueue buffer on allocated list */
		TAILQ_INSERT_TAIL(&user_mem_head, e, link);

#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
		/* Emplace end-clobber detector at end of buffer */
		cp[total_len - CANARY_LINE_SIZE] =
		    (((uintptr_t) cp) & 0xFF) ^ 0xC5;
#endif

		PB(TRACE_FLOW, "Allocate: ", (void *)e);

		buf = buf_addr(e);

		if (hint == TEE_MALLOC_FILL_ZERO)
			memset(buf, 0, len);
#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
		else if (hint == (typeof(hint)) TEE_USER_MEM_HINT_NO_FILL_ZERO)
			/* Fill buffer with init pattern */
			memset(buf, 0xBB, len);
#endif
	}

	OUTMSG("[%p]", buf);
	return buf;
}

/*
 * Adjust the size of a previously allocated buffer. Because of the need to
 * maintain our control storage, tee_user_mem_realloc() must always allocate a
 * new block and copy the data in the old block. This may result in programs
 * which make heavy use of realloc() running much slower than normally.
 */
void *tee_user_mem_realloc(void *buffer, size_t len)
{
	size_t olen;
	void *buf;
	struct user_mem_elem *e;

	INMSG("[%p:%d]", buffer, (int)len);

	if ((int)len < 0) {
		OUTMSG("0x0");
		return NULL;
	}

	/* If the old block pointer
	 *  - is NULL,
	 *  - or was allocated with a zero size,
	 *  - or invalid buffer
	 * treat realloc() as a malloc().  */
	if (buffer == NULL || buffer == ARTIST || !is_buffer_valid(buffer)) {
		buf = tee_user_mem_alloc(len, DEFAULT_TEE_MALLOC_HINT);
		OUTMSG("%p", buf);
		return buf;
	}

	/*
	 * If the old and new sizes are the same, be a nice guy and just return
	 * the buffer passed in.
	 */
	e = (struct user_mem_elem *)elem_addr(buffer);
	olen = buf_size(e);
	if (len == olen) {
		OUTMSG("[%p]", buffer);
		return buffer;
	}

	/*
	 * Sizes differ. Allocate a new buffer of the requested size. If we
	 * can't obtain such a buffer, return NULL from realloc() and leave the
	 * buffer in ptr intact.
	 */
	buf = tee_user_mem_alloc(len, e->hint);
	if (buf != NULL) {
		memcpy(buf, buffer, MIN(len, olen));

		/* All done.  Free and dechain the original buffer. */
		tee_user_mem_free(buffer);
	}

	OUTMSG("[%p]", buf);
	return buf;
}

/*
 * Update free pool availability. free is never called except through this
 * interface. free(x) is defined to generate a call to this routine.
 */
void tee_user_mem_free(void *buffer)
{
	uint8_t *cp;
	struct user_mem_elem *e;

	INMSG("[%p]", buffer);

	/* It is OK to free NULL */
	if (buffer == NULL || buffer == ARTIST)
		return;

	/* Check if the buffer is valid */
	if (!is_buffer_valid(buffer)) {
		EMSG("unknown freed buffer [%p]", buffer);
		return;
	}

	cp = elem_addr(buffer);
	e = (struct user_mem_elem *)(void *)cp;

	PB(TRACE_FLOW, "Free: ", (void *)e);

#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
	if (!check_elem(e)) {
		EMSG("corrupted allocation");
		TEE_Panic(0);
	}
#endif

	TAILQ_REMOVE(&user_mem_head, e, link);

	heap_dec(e->len);

#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
	/*
	 * Now we wipe the contents of the just-released buffer with "designer
	 * garbage" (Duff  Kurland's  phrase) of alternating bits.  This is
	 * intended to ruin the day for any miscreant who attempts to access
	 * data through a pointer into storage that's been previously released.
	 */
	memset(cp, 0xAA, e->len);
#endif

	utee_free(cp);

	OUTMSG();
}

#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
/*
 * Accessors to mark the heap.
 */
void tee_user_mem_mark_heap(void)
{
	INMSG();
	/* Reset the marker */
	heap_level = 0;
	OUTMSG();
}

/*
 * Accessors to check the heap and the whole list.
 * Return 0 means no leak and link list is valid.
 * Return >0 return nb bytes of leak.
 */
size_t tee_user_mem_check_heap(void)
{
	int res = 0;
	INMSG("%zu", heap_level);

	if (heap_level) {
		EMSG("ta heap has changed of [%zu]", heap_level);
		OUTMSG("%zu", heap_level);
		return heap_level;
	}

	res = !is_mem_coherent();

	OUTMSG("%d", res);
	return res;
}

/*
 * Dump the stats and elements of the memory activity.
 */
void tee_user_mem_status(struct tee_user_mem_stats *stats)
{
	struct user_mem_elem *e;
	if (stats != NULL)
		memcpy(stats, &global_stats, sizeof(struct tee_user_mem_stats));

	if (global_stats.nb_alloc > 0) {
		IMSG("Nb alloc:\t[%d]", global_stats.nb_alloc);
		IMSG("Size:\t[%zu]", global_stats.size);
	}

	TAILQ_FOREACH(e, &user_mem_head, link) {
		PB(TRACE_ERROR, "", e);
	}
}
#else
void tee_user_mem_mark_heap(void)
{
}

size_t tee_user_mem_check_heap(void)
{
	return 0;
}
#endif /* CFG_TEE_CORE_USER_MEM_DEBUG */

/*
 * Free memory allocated from a specific TA.
 */
void tee_user_mem_garbage(void)
{
#if (CFG_TEE_CORE_USER_MEM_DEBUG == 1)
	tee_user_mem_status(NULL);
#endif

	while (TAILQ_FIRST(&user_mem_head) != NULL)
		tee_user_mem_free(buf_addr(TAILQ_FIRST(&user_mem_head)));
}

#endif /* CFG_NO_USER_MALLOC_GARBAGE */
