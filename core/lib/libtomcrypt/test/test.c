#include <tomcrypt_test.h>
#include "tomcrypt_mpa.h"
#include <time.h>
#include <stdlib.h>


#define LTC_VARIABLE_NUMBER         (50)
#define LTC_MAX_BITS_PER_VARIABLE   (2048)

static uint32_t mempool_u32[ mpa_scratch_mem_size_in_U32(LTC_VARIABLE_NUMBER, LTC_MAX_BITS_PER_VARIABLE) ];
static mpa_scratch_mem pool;

void __init(const uint32_t number_of_variable, const uint32_t bits_per_variable) {
	if ((number_of_variable * bits_per_variable) > (LTC_VARIABLE_NUMBER * LTC_MAX_BITS_PER_VARIABLE)) {
		fprintf(stderr, "Requested Memory is greater than available !!\n");
		exit(EXIT_FAILURE);
	}
	pool = (mpa_scratch_mem_base *) &mempool_u32;
	init_mpa_tomcrypt(pool);
	mpa_init_scratch_mem(pool, sizeof(mempool_u32), bits_per_variable);
	//	__mpa_init_random(0xdeadbeef);
}

static int __check_memory(void) {
	int idx;
	mpa_num_base* tvar;

	idx = 0;
	tvar =(void*)pool->m;
	while (tvar->alloc == 0 && idx < pool->nrof_vars) {
		tvar = (void*)&pool->m[idx * mpa_StaticTempVarSizeInU32(pool->bit_size)];
		idx++;
	}
	return (idx == pool->nrof_vars) ? CRYPT_OK : CRYPT_MEM;
}

#define CHECK_MEM do { \
		err = __check_memory(); \
		if (x) exit(EXIT_FAILURE);  \
}while(0)

int main(void)
{
	int x, err = CRYPT_OK;

	reg_algs();
	__init(40, 2048);

	printf("\nunit_test....."), fflush(stdout); x = unit_test();        printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\nstore_test...."); fflush(stdout); x = store_test();       printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\ncipher_test..."); fflush(stdout); x = cipher_hash_test(); printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\nmodes_test...."); fflush(stdout); x = modes_test();       printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\nmac_test......"); fflush(stdout); x = mac_test();         printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\npkcs_1_test..."); fflush(stdout); x = pkcs_1_test();      printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\nder_test......"); fflush(stdout); x = der_tests();        printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\nrsa_test......"); fflush(stdout); x = rsa_test();         printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	__init(90, 2*521);
	printf("\necc_test......"); fflush(stdout); x = ecc_tests();        printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	__init(40, 2048);
	printf("\ndsa_test......"); fflush(stdout); x = dsa_test();         printf(x ? "failed" : "passed");if (x) exit(EXIT_FAILURE);
	CHECK_MEM;
	printf("\n");
	return err;
}

/* $Source: /cvs/libtom/libtomcrypt/demos/test.c,v $ */
/* $Revision: 1.28 $ */
/* $Date: 2006/05/25 10:50:08 $ */
