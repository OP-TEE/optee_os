// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 *
 * Brief   CAAM Global Controller.
 */
#include <caam_common.h>
#include <caam_hal_cfg.h>
#include <caam_hal_clk.h>
#include <caam_hal_ctrl.h>
#ifdef CFG_CRYPTO_HASH_HW
#include <caam_hash.h>
#endif
#include <caam_jr.h>
#include <caam_pwr.h>
#include <caam_rng.h>
#include <caam_utils_mem.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <tee_api_types.h>

/* Crypto driver initialization */
static TEE_Result crypto_driver_init(void)
{
	TEE_Result retresult = TEE_ERROR_GENERIC;
	enum CAAM_Status retstatus = CAAM_FAILURE;
	struct caam_jrcfg jrcfg = { 0 };

	/* Enable the CAAM Clock */
	caam_hal_clk_enable(true);

	retstatus = caam_hal_cfg_get_conf(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_NOT_SUPPORTED;
		goto exit_init;
	}

	/* Initialize the CAAM Controller */
	caam_hal_ctrl_init(jrcfg.base);

	/* Initialize the Job Ring to be used */
	retstatus = caam_jr_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the RNG Module */
	retstatus = caam_rng_init(jrcfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

#ifdef CFG_CRYPTO_HASH_HW
	/* Initialize the Hash Module */
	retstatus = caam_hash_init(jrcfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}
#endif /* CFG_CRYPTO_HASH_HW */

	/* Everything is OK, register the Power Management handler */
	caam_pwr_init();

	retresult = TEE_SUCCESS;

exit_init:
	/*
	 * Configure Job Rings to NS World
	 * If the Driver Crypto is not used (CFG_CRYPTO_DRIVER = n)
	 * JR0 is freed to be Non-Secure
	 */
	if (jrcfg.base)
		caam_hal_cfg_setup_nsjobring(jrcfg.base);

	if (retresult != TEE_SUCCESS) {
		EMSG("CAAM Driver initialization (0x%x)", retresult);
		panic();
	}

	return retresult;
}

driver_init(crypto_driver_init);

/* Crypto driver late initialization to complete on-going CAAM operation */
static TEE_Result init_caam_late(void)
{
	enum CAAM_Status ret = CAAM_BUSY;

	ret = caam_jr_complete();

	if (ret == CAAM_BUSY) {
		EMSG("CAAM initialization failed");
		panic();
	}

	return TEE_SUCCESS;
}

driver_init_late(init_caam_late);
