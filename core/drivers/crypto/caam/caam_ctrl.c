// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2021, 2023 NXP
 *
 * Brief   CAAM Global Controller.
 */
#include <assert.h>
#include <caam_acipher.h>
#include <caam_cipher.h>
#include <caam_common.h>
#include <caam_hal_cfg.h>
#include <caam_hal_clk.h>
#include <caam_hal_ctrl.h>
#include <caam_hash.h>
#include <caam_jr.h>
#include <caam_key.h>
#include <caam_blob.h>
#include <caam_mp.h>
#include <caam_pwr.h>
#include <caam_rng.h>
#include <caam_sm.h>
#include <drivers/imx_snvs.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <tee_api_types.h>

/*
 * If the CAAM DMA only supports 32 bits physical addresses, OPTEE must
 * be located within the 32 bits address space.
 */
#ifndef CFG_CAAM_64BIT
static_assert((CFG_TZDRAM_START + CFG_TZDRAM_SIZE) < UINT32_MAX);
#endif

/* Crypto driver initialization */
static TEE_Result crypto_driver_init(void)
{
	TEE_Result retresult = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_jrcfg jrcfg = {};

	/* Enable the CAAM Clock */
	caam_hal_clk_enable(true);

	/* Set OTP as master key if the platform is closed */
	if (snvs_is_device_closed()) {
		retresult = imx_snvs_set_master_otpmk();
		if (retresult && retresult != TEE_ERROR_NOT_IMPLEMENTED)
			goto exit_init;
	}

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

	/* Initialize the Hash Module */
	retstatus = caam_hash_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the MATH Module */
	retstatus = caam_math_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the RSA Module */
	retstatus = caam_rsa_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the Cipher Module */
	retstatus = caam_cipher_init(jrcfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the HMAC Module */
	retstatus = caam_hmac_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the BLOB Module */
	retstatus = caam_blob_mkvb_init(jrcfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the CMAC Module */
	retstatus = caam_cmac_init(jrcfg.base);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the ECC Module */
	retstatus = caam_ecc_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the DH Module */
	retstatus = caam_dh_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the DSA Module */
	retstatus = caam_dsa_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the Manufacturing Protection Module */
	retstatus = caam_mp_init(jrcfg.base);
	if (retstatus != CAAM_NO_ERROR && retstatus != CAAM_NOT_SUPPORTED) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the secure memory */
	retstatus = caam_sm_init(&jrcfg);
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Initialize the KEY Module */
	retstatus = caam_key_init();
	if (retstatus != CAAM_NO_ERROR) {
		retresult = TEE_ERROR_GENERIC;
		goto exit_init;
	}

	/* Everything is OK, register the Power Management handler */
	caam_pwr_init();

	/*
	 * Configure Job Rings to NS World
	 * If the Driver Crypto is not used CFG_NXP_CAAM_RUNTIME_JR is not
	 * enable, hence relax the JR used for the CAAM configuration to
	 * the Non-Secure
	 */
	if (jrcfg.base)
		caam_hal_cfg_setup_nsjobring(&jrcfg);

	retresult = TEE_SUCCESS;
exit_init:
	if (retresult != TEE_SUCCESS) {
		EMSG("CAAM Driver initialization (0x%" PRIx32 ")", retresult);
		panic();
	}

	return retresult;
}

early_init(crypto_driver_init);

/* Crypto driver late initialization to complete on-going CAAM operations */
static TEE_Result init_caam_late(void)
{
	enum caam_status ret = CAAM_BUSY;

	ret = caam_jr_complete();

	if (ret != CAAM_NO_ERROR) {
		EMSG("CAAM initialization failed");
		panic();
	}

	return TEE_SUCCESS;
}

early_init_late(init_caam_late);
