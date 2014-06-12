/*
 * Parts of this file are copied from
 * http://www.fourmilab.ch/smartall/ and restructured to suit our needs.
 * Smartall is released as:
 *
 * This software is in the public domain. Permission to use, copy, modify,
 * and distribute this software and its documentation for any purpose and
 * without fee is hereby granted, without any conditions or restrictions.
 * This software is provided "as is" without express or implied warranty.
 */

/*
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL ST BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Following switch are for debug purpose:
 * #define ENABLE_MDBG
 * #define MDBG_REALLOC_ENABLED
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <kernel/tee_core_trace.h>
#include <sys/queue.h>

#ifdef TEE_USE_DLMALLOC
#include "dlmalloc.h"
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* mdbg routines only rely on malloc and free */
#ifdef TEE_USE_DLMALLOC
#define EFFECTIVE_FREE      dlfree
#define EFFECTIVE_MALLOC    dlmalloc
#elif defined TEE_USE_BASIC_MALLOC
#define EFFECTIVE_FREE      basic_free
#define EFFECTIVE_MALLOC    basic_malloc
#endif

#ifdef TEE_USE_BASIC_MALLOC
/*
 * Very basic malloc pool from heap. Used for TZ bringup.
 */
#define HEAPSIZE (1024 * 1024)
char _heap_address[HEAPSIZE];
uint32_t _heap_offset;

static void *basic_malloc(size_t size)
{
	const int align = 8;
	void *pt = _heap_address + _heap_offset;
	_heap_offset += align * ((size + (align - 1)) / align);
	if (_heap_offset > HEAPSIZE)
		return 0;	/* malloc error */
	return pt;
}

static void basic_free(void *p)
{
	/* no effective free */
}
#endif

/*
 * ENABLE_MDBG - redirects malloc familly calls to track requesters
 *
 * Handle malloc, free and realloc.
 */
#ifdef ENABLE_MDBG

struct mdbg_elem {
	TAILQ_ENTRY(mdbg_elem) link;
	size_t len;
	const char *fname;
	uint16_t line;
	bool ignore;
	/*
	uint8_t data[len - sizeof(struct mdbg_elem)];
	uint8_t magic;
	*/
};

TAILQ_HEAD(mdbg_head, mdbg_elem) mdbg_head = TAILQ_HEAD_INITIALIZER(mdbg_head);

static bool bufimode; /* Buffers not tracked when True - Initialized to False*/

/* Allocate buffer, enqueing on the orphaned buffer tracking list.  */
static void *mdbg_buf_alloc(const char *fname, int lineno, size_t nbytes)
{
	uint8_t *cp;
	void *buf = NULL;

	/*
	 * Note: Unix MALLOC actually permits a zero length to be passed and
	 * allocates a valid block with zero user bytes. Such a block can later
	 * be expanded with realloc(). We disallow this based on the belief
	 * that it's better to make a special case and allocate one byte in the
	 * rare case this is desired than to miss all the erroneous occurrences
	 * where buffer length calculation code results in a zero.
	 */

	assert(nbytes > 0);

	nbytes += sizeof(struct mdbg_elem) + 1;
	cp = EFFECTIVE_MALLOC(nbytes);
	if (cp != NULL) {
		struct mdbg_elem *e = (struct mdbg_elem *)(void *)cp;

		/* Enqueue buffer on allocated list */
		TAILQ_INSERT_TAIL(&mdbg_head, e, link);
		e->len = nbytes;
		e->fname = fname;
		e->line = (uint16_t) lineno;
		e->ignore = bufimode;
		/* Emplace end-clobber detector at end of buffer */
		cp[nbytes - 1] = (((uintptr_t) cp) & 0xFF) ^ 0xC5;
		/* Increment to user data start */
		buf = cp + sizeof(struct mdbg_elem);
	}
	return buf;
}

static bool mdbg_check_buf_end(struct mdbg_elem *e)
{
	uint8_t *cp = (uint8_t *)e;

	/*
	 * The following check detects storing off the end of the allocated
	 * space in the buffer by comparing the end of buffer checksum with the
	 * address of the buffer.
	 */
	if ((cp[e->len - 1] != ((((uintptr_t) cp) & 0xFF) ^ 0xC5)))
		return false;

	return true;
}

static bool mdbg_check_buf(struct mdbg_elem *ap)
{
	struct mdbg_elem *e;

	/* Validate queue links */
	if (ap == NULL)
		return false;

	e = TAILQ_NEXT(ap, link);
	if (e != NULL && TAILQ_PREV(e, mdbg_head, link) != ap)
		return false;

	e = TAILQ_PREV(ap, mdbg_head, link);
	if (e != NULL && TAILQ_NEXT(e, link) != ap)
		return false;

	return mdbg_check_buf_end(ap);
}

/*
 * Update free pool availability. free is never called except through this
 * interface. free(x) is defined to generate a call to this routine.
 */
void mdbg_free(void *fp)
{
	uint8_t *cp;
	struct mdbg_elem *e;

	/* It is OK to free NULL */
	if (fp == NULL)
		return;

	cp = (uint8_t *)fp - sizeof(struct mdbg_elem);
	assert(((uintptr_t) cp & 0x3) == 0);
	e = (struct mdbg_elem *)(void *)cp;

	assert(mdbg_check_buf(e));

	TAILQ_REMOVE(&mdbg_head, e, link);

	/*
	 * Now we wipe the contents of the just-released buffer with "designer
	 * garbage" (Duff  Kurland's  phrase) of alternating bits.  This is
	 * intended to ruin the day for any miscreant who attempts to access
	 * data through a pointer into storage that's been previously released.
	 */
	memset(cp, 0xAA, e->len);

	EFFECTIVE_FREE(cp);
}

/* Allocate buffer. NULL is returned if no memory was available. */
void *mdbg_malloc(const char *fname, int lineno, size_t nbytes)
{
	void *buf;

	buf = mdbg_buf_alloc(fname, lineno, nbytes);
	if (buf != NULL) {
		/*
		 * To catch sloppy code that assumes  buffers  obtained  from
		 * malloc() are  zeroed,  we  preset  the buffer contents to
		 * "designer garbage" consisting of alternating bits.
		 */
		memset(buf, 0x55, nbytes);
	}
	return buf;
}

#ifdef MDBG_REALLOC_ENABLED
/*
 * Adjust the size of a previously allocated buffer. Because of the need to
 * maintain our control storage, mdbg_realloc must always allocate a new
 * block and copy the data in the old block. This may result in programs
 * which make heavy use of realloc() running much slower than normally.
 */
void *mdbg_realloc(const char *fname, int lineno, void *ptr, size_t size)
{
	size_t osize;
	void *buf;
	struct mdbg_elem *e;

	assert(size > 0 && ((uintptr_t) ptr & 0x3) == 0);

	/* If the old block pointer is NULL, treat realloc() as a malloc().  */
	if (ptr == NULL)
		return mdbg_malloc(fname, lineno, size);

	/*
	 * If the old and new sizes are the same, be a nice guy and just return
	 * the buffer passed in.
	 */
	e = (struct mdbg_elem *)(void *)((uint8_t *)ptr -
					 sizeof(struct mdbg_elem));
	osize = e->len - sizeof(struct mdbg_elem) - 1;
	if (size == osize)
		return ptr;

	/*
	 * Sizes differ. Allocate a new buffer of the requested size. If we
	 * can't obtain such a buffer, return NULL from realloc() and leave the
	 * buffer in ptr intact.
	 */
	buf = mdbg_malloc(fname, lineno, size);
	if (buf != NULL) {
		memcpy(buf, ptr, MIN(size, osize));

		/* All done.  Free and dechain the original buffer. */
		mdbg_free(ptr);
	}
	return buf;
}
#endif /* MDBG_REALLOC_ENABLED */

/* Allocate an array and clear it to zero.  */
void *mdbg_calloc(const char *fname, int lineno, size_t nelem, size_t elsize)
{
	void *buf;

	buf = mdbg_buf_alloc(fname, lineno, nelem * elsize);
	if (buf != NULL)
		memset(buf, 0, nelem * elsize);
	return buf;
}

static void mdbg_print_buf(int bufdump, const char *stat_str,
			   struct mdbg_elem *e)
{
	size_t memsize = e->len - (sizeof(struct mdbg_elem) + 1);
	static const char unknown[] = "unknown";
	const char *fname = e->fname;

	if (fname == NULL)
		fname = unknown;

	DMSG("%s buffer: %d bytes %s:%d", stat_str, memsize, fname, e->line);

	if (bufdump > 1) {
		void *buf = ((uint8_t *)e) + sizeof(struct mdbg_elem);

		HEX_PRINT_BUF(buf, memsize);
	}
}

/* Print orphaned buffers (and dump them if bufdumP is true). */
void mdbg_dump(int bufdump)
{
	struct mdbg_elem *e;

#ifdef MDBG_PRINT_LEAKS
	DMSG("Checking for %sbuffers", bufdump == 0 ? "Orphaned " : "");
#endif

	TAILQ_FOREACH(e, &mdbg_head, link) {
		if (!mdbg_check_buf(e)) {
			mdbg_print_buf(bufdump, "Clobbered", e);
			break;
		}
#ifdef MDBG_PRINT_LEAKS
		if (bufdump > 0 || !e->ignore)
			mdbg_print_buf(bufdump,
				       e->ignore ? "Ignore" : "Orphaned", e);
#endif
	}
}

/*
 * Orphaned buffer detection can be disabled (for such items as buffers
 * allocated during initialisation) by calling mdbg_static(1). Normal
 * orphaned buffer detection can be re-enabled with mdbg_static(0). Note
 * that all the other safeguards still apply to buffers allocated when
 * mdbg_static(1) mode is in effect.
 */
enum mdbg_mode mdbg_set_mode(enum mdbg_mode mode)
{
	enum mdbg_mode old_mode;

	if (bufimode)
		old_mode = MDBG_MODE_STATIC;
	else
		old_mode = MDBG_MODE_DYNAMIC;

	if (mode == MDBG_MODE_STATIC)
		bufimode = true;
	else
		bufimode = false;

	return old_mode;
}

/* Trap PC with message if mdbg traces are corrupted */
void mdbg_check(void)
{
	struct mdbg_elem *e;

	TAILQ_FOREACH(e, &mdbg_head, link) {
		if (!mdbg_check_buf(e)) {
			mdbg_print_buf(0, "Clobbered", e);
			assert(0);
		}
	}
}

#else /* ENABLE_MDBG */

/*
 * case MDBG is not used: wrap each malloc service to the right handler.
 */
void free(void *ptr)
{
	EFFECTIVE_FREE(ptr);
}

void *malloc(size_t size)
{
	return EFFECTIVE_MALLOC(size);
}

void *calloc(size_t nmemb, size_t size)
{
#ifdef TEE_USE_DLMALLOC
	return dlcalloc(nmemb, size);
#else
	size_t l = nmemb * size;
	void *p = malloc(l);

	if (p != NULL)
		memset(p, 0, l);
	return p;
#endif
}

void *realloc(void *ptr, size_t size)
{
#ifdef TEE_USE_DLMALLOC
	return dlrealloc(ptr, size);
#else
	assert(0);
	return NULL;
#endif
}

/******************************************************************************/

/*
 * Other standard mem alloc APIs, if supported!
 */
#ifdef TEE_USE_DLMALLOC		/* these are only supported by dlmalloc */
void *memalign(size_t a, size_t l)
{
	unsigned long i, j;

	/* check a is a power of 2 */
	for (i = 1, j = 0; i; i <<= 1) {
		if (i & a)
			j++;
	}
	if (j != 1)
		return NULL;

	return dlmemalign(a, l);
}

void *valloc(size_t l)
{
	if (l) {
		EMSG("- assert: valloc from dlmalloc is not yet tested -");
		assert(0);
	}
	return dlvalloc(l);
}

void *pvalloc(size_t l)
{
	if (l) {
		EMSG("- assert: pvalloc from dlmalloc is not yet tested -");
		assert(0);
	}
	return dlpvalloc(l);
}
#endif /* TEE_USE_DLMALLOC */

#ifdef TEE_USE_DLMALLOC
/*
 * brk for dlmalloc to get memory chunks.
 */
struct dlmalloc_area {
	void *start;
	void *end;
	void *brk;
};
static struct dlmalloc_area dla = {
	.start = (void *)-1,
};

void *sbrk(ptrdiff_t size)
{
	void *cur;

	if ((dla.start == (void *)-1) ||
	    ((unsigned long)dla.brk + size < (unsigned long)dla.start) ||
	    ((unsigned long)dla.brk + size > (unsigned long)dla.end)) {
		return (void *)-1;
	}

	/* update brk for next request */
	cur = dla.brk;
	dla.brk = (void *)((unsigned long)dla.brk + size);

	/* if releasing memory, insure clear content for next time */
	if (size < 0)
		memset(dla.brk, 0, -size);

	return cur;
}

static void dlmalloc_init(void *start, size_t size);

static void dlmalloc_init(void *start, size_t size)
{
	/*
	 * TODO: map the malloc pool
	 * Thi is not currently required as malloc pool is already mapped
	 * at boot time from core_mmu.c/core_init_mmu().
	 * But sooner, we shall map it at run time.
	 */

	memset(start, 0, size);
	dla.brk = start;
	dla.start = start;
	dla.end = (void *)((unsigned long)start + size);
}
#endif /* TEE_USE_DLMALLOC */

/*
 * Malloc support init routine
 */
void malloc_init(void *start, size_t size)
{
#ifdef TEE_USE_DLMALLOC
	dlmalloc_init(start, size);
#endif
}

#endif /* !ENABLE_MDBG */
