// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/tme/tme_intf.h>
#include <inttypes.h>
#include <trace.h>

#include "provision.h"

/*
 * Ask the security processor to commit the image versions it recorded during
 * authentication into the anti-rollback fuses. This is irreversible and the
 * security processor tracks that it happened, so it must be requested once
 * per boot, at the point where the boot is considered good.
 */
TEE_Result provision_commit_rollback(void)
{
	TEE_Result res = tme_update_rollback_version();

	if (res != TEE_SUCCESS)
		EMSG("Anti-rollback update failed: %#"PRIx32, res);
	else
		IMSG("Anti-rollback state committed");

	return res;
}
