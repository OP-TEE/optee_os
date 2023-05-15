// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <fsl_sss_se05x_apis.h>
#include <global_platf.h>
#include <se050.h>
#include <se05x_const.h>
#include <se05x_tlv.h>
#include <smCom.h>
#include <string.h>
#include <util.h>

/* Force the output until the P&T stack fixes its verbosity */
#define LOG_MAU8_I(msg, buf, len) nLog_au8("Info", 0xff, msg, buf, len)
#define LOG_I(format, ...) nLog("Info", 0xff, format, ##__VA_ARGS__)
#define LOG_E(format, ...) nLog("Info", NX_LEVEL_ERROR, format, ##__VA_ARGS__)
#define LOG_MAU8_E(msg, buf, len) \
	nLog_au8("Info", NX_LEVEL_ERROR, msg, buf, len)

static sss_status_t jcop4_get_id(void *ctx, bool display)
{
	char jcop_platform_id[17] = { 0 };
	smStatus_t ret = SM_OK;
	unsigned char cmd[] = {
		0x80, /* CLA '80' / '00' GlobalPlatform / ISO / IEC	*/
		0xCA, /* INS 'CA' GET DATA(IDENTIFY)			*/
		0x00, /* P1 '00' High order tag value			*/
		0xFE, /* P2 'FE' Low order tag value - proprietary data	*/
		0x02, /* Lc '02' Length of data field			*/
		0xDF,
		0x28, /* Data 'DF28' Card identification data		*/
		0x00  /* Le '00' Length of response data		*/
	};
	struct msg_rsp {
		uint8_t vTag_value_proprietary_data;
		uint8_t vLength_of_following_data;
		uint8_t vTag_card_identification_data[0x02];
		uint8_t vLength_of_card_identification_data;
		uint8_t vTag_configuration_ID;
		uint8_t vLength_configuration_ID;
		uint8_t vConfiguration_ID[0x0C];
		uint8_t vTag_patch_ID;
		uint8_t vLength_patch_ID;
		uint8_t vPatch_ID[0x08];
		uint8_t vTag_platform_build_ID1;
		uint8_t vLength_platform_build_ID;
		uint8_t vPlatform_build_ID[0x18];
		uint8_t vTag_FIPS_mode;
		uint8_t vLength_FIPS_mode;
		uint8_t vFIPS_mode;
		uint8_t vTag_pre_perso_state;
		uint8_t vLength_pre_perso_state;
		uint8_t vBit_mask_of_pre_perso_state;
		uint8_t vTag_ROM_ID;
		uint8_t vLength_ROM_ID;
		uint8_t vROM_ID[0x08];
		uint8_t vStatus_Word_SW_[0x02];
	} rsp = { 0 };
	uint8_t *p = (uint8_t *)&rsp;
	uint32_t len = sizeof(struct msg_rsp);
	uint16_t dummy = sizeof(struct msg_rsp);

	ret = GP_Select(ctx, p, 0, p, &dummy);
	if (ret != SM_OK) {
		LOG_E("Could not select ISD.");
		return kStatus_SSS_Fail;
	}

	ret = smCom_TransceiveRaw(ctx, cmd, sizeof(cmd), p, &len);
	if (ret != SM_OK || len != sizeof(rsp)) {
		LOG_MAU8_E("Error reading JCOP ID", p, sizeof(rsp));
		return kStatus_SSS_Fail;
	}

	memcpy(se050_ctx.se_info.oefid, &rsp.vConfiguration_ID[2], 2);
	if (!display)
		return kStatus_SSS_Success;

	LOG_I("SE050 JCOP4 Information:");
	LOG_I("%s = 0x%02X", "Tag value - proprietary data 0xFE",
	      rsp.vTag_value_proprietary_data);
	LOG_I("%s = 0x%02X", "Length of following data 0x45",
	      rsp.vLength_of_following_data);
	LOG_MAU8_I("Tag card identification data",
		   rsp.vTag_card_identification_data,
		   sizeof(rsp.vTag_card_identification_data));
	LOG_I("%s = 0x%02X", "Length of card identification data",
	      rsp.vLength_of_card_identification_data);
	LOG_I("%s = 0x%02X", "Tag configuration ID (Must be 0x01)",
	      rsp.vTag_configuration_ID);
	LOG_I("%s = 0x%02X", "Length configuration ID 0x0C",
	      rsp.vLength_configuration_ID);
	LOG_MAU8_I("Configuration ID",
		   rsp.vConfiguration_ID, sizeof(rsp.vConfiguration_ID));
	LOG_MAU8_I("OEF ID", &rsp.vConfiguration_ID[2], 2);
	LOG_I("%s = 0x%02X", "Tag patch ID (Must be 0x02)", rsp.vTag_patch_ID);
	LOG_I("%s = 0x%02X", "Length patch ID 0x08", rsp.vLength_patch_ID);
	LOG_MAU8_I("Patch ID", rsp.vPatch_ID, sizeof(rsp.vPatch_ID));
	LOG_I("%s = 0x%02X", "Tag platform build ID1 (Must be 0x03)",
	      rsp.vTag_platform_build_ID1);
	LOG_I("%s = 0x%02X", "Length platform build ID 0x18",
	      rsp.vLength_platform_build_ID);
	LOG_MAU8_I("Platform build ID",
		   rsp.vPlatform_build_ID, sizeof(rsp.vPlatform_build_ID));
	memcpy(jcop_platform_id, rsp.vPlatform_build_ID, 16);

	LOG_I("%s = %s", "JCOP Platform ID", jcop_platform_id);
	LOG_I("%s = 0x%02X", "Tag FIPS mode (Must be 0x05)",
	      rsp.vTag_FIPS_mode);
	LOG_I("%s = 0x%02X", "Length FIPS mode 0x01", rsp.vLength_FIPS_mode);
	LOG_I("%s = 0x%02X", "FIPS mode var", rsp.vFIPS_mode);
	LOG_I("%s = 0x%02X", "Tag pre-perso state (Must be 0x07)",
	      rsp.vTag_pre_perso_state);
	LOG_I("%s = 0x%02X", "Length pre-perso state 0x01",
	      rsp.vLength_pre_perso_state);
	LOG_I("%s = 0x%02X", "Bit mask of pre-perso state var",
	      rsp.vBit_mask_of_pre_perso_state);

	LOG_I("%s = 0x%02X", "Tag ROM ID (Must be 0x08)", rsp.vTag_ROM_ID);
	LOG_I("%s = 0x%02X", "Length ROM ID 0x08", rsp.vLength_ROM_ID);
	LOG_MAU8_I("ROM ID", rsp.vROM_ID, sizeof(rsp.vROM_ID));
	LOG_MAU8_I("Status Word (SW)", rsp.vStatus_Word_SW_,
		   sizeof(rsp.vStatus_Word_SW_));

	return kStatus_SSS_Success;
}

#define ITEM(__x)  {					\
		.name  = #__x,				\
		.val = (kSE05x_AppletConfig_##__x),	\
	}

static void show_config(uint16_t cfg)
{
	struct items {
		uint16_t val;
		const char *name;
	} features[] = {
		ITEM(ECDAA), ITEM(ECDSA_ECDH_ECDHE), ITEM(EDDSA), ITEM(DH_MONT),
		ITEM(HMAC), ITEM(RSA_PLAIN), ITEM(RSA_CRT), ITEM(AES),
		ITEM(DES), ITEM(PBKDF), ITEM(TLS), ITEM(MIFARE), ITEM(I2CM),
	};
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(features); i++) {
		LOG_I("\t%s%s", cfg & features[i].val ? "with\t" : "without\t",
		      features[i].name);
	}
}

static sss_status_t applet_get_id(sss_se05x_session_t *session, bool display)
{
	SE05x_Result_t result = kSE05x_Result_NA;
	smStatus_t ret = SM_OK;
	uint8_t uid[SE050_MODULE_UNIQUE_ID_LEN] = { 0 };
	size_t uidLen = sizeof(uid);
	uint8_t applet_version[7] = { 0 };
	size_t applet_versionLen = sizeof(applet_version);

	ret = Se05x_API_CheckObjectExists(&session->s_ctx,
					  kSE05x_AppletResID_UNIQUE_ID,
					  &result);
	if (ret != SM_OK)
		return kStatus_SSS_Fail;

	ret = Se05x_API_ReadObject(&session->s_ctx,
				   kSE05x_AppletResID_UNIQUE_ID, 0,
				   (uint16_t)uidLen, uid, &uidLen);
	if (ret != SM_OK)
		return kStatus_SSS_Fail;

	/*
	 * VersionInfo is a 7 - byte value consisting of:
	 * - 1 - byte Major applet version
	 * - 1 - byte Minor applet version
	 * - 1 - byte patch applet version
	 * - 2 - byte AppletConfig, indicating the supported applet features
	 * - 2-byte Secure Box version: major version (MSB) concatenated with
	 *   minor version (LSB).
	 */
	ret = Se05x_API_GetVersion(&session->s_ctx, applet_version,
				   &applet_versionLen);
	if (ret != SM_OK) {
		LOG_E("Failed Se05x_API_GetVersion");
		return kStatus_SSS_Fail;
	}

	memcpy(se050_ctx.se_info.applet, applet_version, 3);
	if (!display)
		return kStatus_SSS_Success;

	LOG_MAU8_I("Applet ID", uid, uidLen);

	LOG_I("Applet Major = %d", applet_version[0]);
	LOG_I("Applet Minor = %d", applet_version[1]);
	LOG_I("Applet patch = %d", applet_version[2]);
	LOG_I("AppletConfig = %02X%02X", applet_version[3], applet_version[4]);
	show_config(applet_version[3] << 8 | applet_version[4]);
	LOG_I("Internal = %02X%02X", applet_version[5], applet_version[6]);

	return kStatus_SSS_Success;
}

sss_status_t se050_get_se_info(sss_se05x_session_t *session, bool display)
{
	sss_status_t ret = kStatus_SSS_Fail;
	__maybe_unused uint32_t oefid = 0;

	if (session) {
		ret = applet_get_id(session, display);
		if (ret != kStatus_SSS_Success) {
			EMSG("Can't retrieve Applet information");
			return ret;
		}

		ret = jcop4_get_id(session->s_ctx.conn_ctx, display);
		if (ret != kStatus_SSS_Success) {
			EMSG("Can't retrieve JCOP information");
			return ret;
		}

#ifdef CFG_CORE_SE05X_OEFID
		/* validate the requested OEFID against the runtime detected */
		oefid = SHIFT_U32(se050_ctx.se_info.oefid[0], 8) |
			SHIFT_U32(se050_ctx.se_info.oefid[1], 0);

		if (oefid != CFG_CORE_SE05X_OEFID) {
			EMSG("OEFID configuration error, 0x%x != 0x%"PRIx32,
			     CFG_CORE_SE05X_OEFID, oefid);
			return kStatus_SSS_Fail;
		}
#endif
		return kStatus_SSS_Success;
	}

	return kStatus_SSS_Fail;
}
