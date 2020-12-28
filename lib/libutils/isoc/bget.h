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

    Interface definitions for bget.c, the memory management package.

*/


#ifndef _
#ifdef PROTOTYPES
#define  _(x)  x		      /* If compiler knows prototypes */
#else
#define  _(x)  ()                     /* It it doesn't */
#endif /* PROTOTYPES */
#endif

#define BGET_HDR_QUANTUM    (2 * sizeof(long))

typedef long bufsize;
struct bpoolset;

void	bpool	    _((void *buffer, bufsize len, struct bpoolset *poolset));
void   *bget	    _((bufsize align, bufsize hdr_size, bufsize size, struct bpoolset *poolset));
void   *bgetz	    _((bufsize align, bufsize hdr_size, bufsize size, struct bpoolset *poolset));
void   *bgetr	    _((void *buffer, bufsize align, bufsize hdr_size, bufsize newsize,
		       struct bpoolset *poolset));
void	brel	    _((void *buf, struct bpoolset *poolset, int wipe));
void	bectl	    _((int (*compact)(bufsize sizereq, int sequence),
		       void *(*acquire)(bufsize size),
		       void (*release)(void *buf), bufsize pool_incr,
		       struct bpoolset *poolset));
void	bstats	    _((bufsize *curalloc, bufsize *totfree, bufsize *maxfree,
		       long *nget, long *nrel, struct bpoolset *poolset));
void	bstatse     _((bufsize *pool_incr, long *npool, long *npget,
		       long *nprel, long *ndget, long *ndrel,
		       struct bpoolset *poolset));
void	bufdump     _((void *buf));
void	bpoold	    _((void *pool, int dumpalloc, int dumpfree));
int	bpoolv	    _((void *pool));

#if !defined(__KERNEL__) && !defined(__LDELF__) && defined(CFG_TA_BGET_TEST)
int bget_main_test(void *(*malloc_func)(size_t), void (*free_func)(void *));
#endif
