/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORMINFODEFS_H
#define PLATFORMINFODEFS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Generate a platform version number.
 */
#define PLATFORMINFO_VERSION(major, minor) (((major) << 16) | (minor))

/*
 * SMEM format versions. Each adds fields at the end of
 * struct platforminfo_smem; PLATFORMINFO_SMEM_SIZE_Vn is the minimum item
 * size to read through version n. Check both format and size before
 * reading a version-gated field.
 */

/* chip_id, chip_version */
#define PLATFORMINFO_FORMAT_V1	1U
#define PLATFORMINFO_SMEM_SIZE_V1 \
	(offsetof(struct platforminfo_smem, chip_version) + sizeof(uint32_t))

/* chip_family, raw_device_family, raw_device_number */
#define PLATFORMINFO_FORMAT_V12	12U
#define PLATFORMINFO_SMEM_SIZE_V12 \
	(offsetof(struct platforminfo_smem, raw_device_number) + \
	 sizeof(uint32_t))

/* num_parts, disabled_features_array_offset */
#define PLATFORMINFO_FORMAT_V14	14U
#define PLATFORMINFO_SMEM_SIZE_V14 \
	(offsetof(struct platforminfo_smem, disabled_features_array_offset) + \
	 sizeof(uint32_t))

/* part_instances_offset, num_part_instances */
#define PLATFORMINFO_FORMAT_V23	23U
#define PLATFORMINFO_SMEM_SIZE_V23 \
	(offsetof(struct platforminfo_smem, num_part_instances) + \
	 sizeof(uint32_t))

/* Per-instance entry; array located at part_instances_offset (format >= 23) */
struct part_instances {
	uint16_t part;			/* enum chipinfo_part value */
	uint8_t instance;		/* 0-based instance index */
	uint8_t disabled;		/* Non-zero if instance is fused off */
	uint32_t disabled_features;	/* Per-feature bitmask */
};

/*
 * Length of the build ID buffer in struct platforminfo_smem.
 */
#define PLATFORMINFO_SMEM_BUILD_ID_LENGTH 32

/*
 * Length of the chip name buffer in struct platforminfo_smem.
 */
#define PLATFORMINFO_CHIP_NAME_MAX_LENGTH 32

/*
 * Maximum number of PMIC devices in struct platforminfo_smem.
 */
#define PLATFORMINFO_SMEM_MAX_PMIC_DEVICES 3

/*
 * SMEM structure for PMIC information.
 */
struct platforminfo_smem_pmic {
	/* PMIC device model type, for Badger matches the revision id subtype */
	uint32_t pmic_model;
	/* PMIC version, same format as platform version */
	uint32_t pmic_version;
};

/*
 * Structure for the shared memory location which is used to store
 * platform, chip, build, and PMIC information.
 */
struct platforminfo_smem {
	uint32_t format;		/* Format of the structure */
	uint32_t chip_id;		/* Chip ID */
	uint32_t chip_version;		/* Chip version */
	char build_id[PLATFORMINFO_SMEM_BUILD_ID_LENGTH]; /* Build ID */
	uint32_t raw_chip_id;		/* Raw chip ID */
	uint32_t raw_chip_version;	/* Raw chip version */
	uint32_t platform_type;		/* Platform type */
	uint32_t platform_version;	/* Platform version */
	uint32_t fusion;		/* TRUE if Fusion; FALSE otherwise */
	uint32_t platform_subtype;	/* Platform subtype */
	/*
	 * DEPRECATED. May not contain the full list; use the array at
	 * pmic_array_offset instead.
	 */
	struct platforminfo_smem_pmic
		pmic_info[PLATFORMINFO_SMEM_MAX_PMIC_DEVICES];
	uint32_t foundry_id;		/* Chip foundry ID */
	uint32_t chip_serial;		/* Chip serial number */
	uint32_t num_pmics;		/* Number of PMICs in array */
	/* Offset to array of struct platforminfo_smem_pmic */
	uint32_t pmic_array_offset;
	uint32_t chip_family;		/* Chip family */
	uint32_t raw_device_family;	/* Raw device family */
	uint32_t raw_device_number;	/* Raw device number */
	uint32_t qfprom_chip_id;	/* QFPROM chip ID */
	char chip_id_str[PLATFORMINFO_CHIP_NAME_MAX_LENGTH]; /* Chip name */
	/* Number of clusters used by the disabled-CPUs query */
	uint32_t num_clusters;
	/* Offset to uint32 array of disabled CPU clusters */
	uint32_t cluster_array_offset;
	/* Number of parts in the disabled-features array */
	uint32_t num_parts;
	/* Offset to uint32 array of disabled parts */
	uint32_t disabled_features_array_offset;
	/* 0 if not supported, non-zero if supported */
	uint32_t modem_supported;
	uint32_t feature_code;		/* Feature code enum for this device */
	uint32_t p_code;		/* PCode for this device */
	/* Offset of the part name strings for the current chip */
	uint32_t part_name_map_offset;
	/* Number of part name strings */
	uint32_t num_part_name_mappings;
	uint32_t oem_variant_id;	/* OEM variant ID */
	uint32_t num_kvps;		/* Number of KVPs */
	uint32_t kvps_offset;		/* Offset of the KVPs */
	/* Number of clusters with at least one enabled core */
	uint32_t num_functional_clusters;
	uint32_t boot_cluster;		/* Boot cluster index */
	uint32_t boot_core;		/* Boot core index */
	uint32_t raw_package_type;	/* Raw package type */
	/* Offset to uint32 array of partial features */
	uint32_t partial_features_array_offset;
	/* Offset to uint32 array of CPU cores per cluster */
	uint32_t cpu_cores_array_offset;
	/* Offset to array of struct part_instances */
	uint32_t part_instances_offset;
	/* Length of the part-instance array */
	uint32_t num_part_instances;
};

#endif /* PLATFORMINFODEFS_H */
