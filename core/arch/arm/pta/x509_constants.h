/*
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef X509_CONSTANTS_H_
#define X509_CONSTANTS_H_

/* ========== Object identifiers (OID) ========== */

/* organizationalUnitName OID (X.520 DN component) */
extern const unsigned long unitName_oid[];
/* organizationName OID (X.520 DN component) */
extern const unsigned long organizationName_oid[];
/* commonName(X.520 DN component) */
extern const unsigned long commonName_oid[];

/* RSA oids */
extern const unsigned long rsaEncryption[];
extern const unsigned long sha1RSAEnc_oid[];
extern const unsigned long sha224RSAEnc_oid[];
extern const unsigned long sha256RSAEnc_oid[];
extern const unsigned long sha384RSAEnc_oid[];
extern const unsigned long sha512RSAEnc_oid[];

/* ECDSA oids */
extern const unsigned long id_ecPublicKey[];
extern const unsigned long ecdsaSHA224_oid[];
extern const unsigned long ecdsaSHA256_oid[];
extern const unsigned long ecdsaSHA384_oid[];
extern const unsigned long ecdsaSHA512_oid[];
extern const unsigned long secp192r1_oid[];
extern const unsigned long secp224r1_oid[];
extern const unsigned long secp256r1_oid[];
extern const unsigned long secp384r1_oid[];
extern const unsigned long secp521r1_oid[];


/* Extension oids */
/* extension/subjectKeyId, used for root cert */
extern const unsigned long subjKeyId_oid[];
/* extensions/Key Usage, used for root and attest cert */
extern const unsigned long keyUsage_oid[];
/* extensions/basicConstraints, used for root cert */
extern const unsigned long basicConst_oid[];
/* extensions/CRL Distribution Points, used for root and attest (in future) */
extern const unsigned long crlDistPoint_oid[];
extern const unsigned long authorityKeyId_oid[];
/* extensions/"attestation" */
extern const unsigned long attestation_oid[];

/* ========== STRINGS ========== */

extern const char *rootUnitNameRSA;
extern const char *rootUnitNameECC;
extern const char *rootName;
extern const char *attestationName;

#ifndef ULONG
#define ULONG unsigned long
#endif
/* ========== INTEGERS ========== */
extern ULONG version;    /* x509 version of cert. v3 used. */
extern const ULONG versionTag; /* tag value for version field. */
extern const ULONG serialNumber; /* defined by https://source.android.com/security/keystore/attestation#tbscertificate-sequence */
extern const ULONG km_version; /* keymaster version */

/* ========== BOOLEANs and ENUMs ========== */
extern const int bool_T;
extern const int bool_F;

extern const ULONG secLvl_SW;
extern const ULONG secLvl_TE;

/* ========== Predefined encoded values ========== */
extern const unsigned char attestKeyUsageSign[];
extern const unsigned char attestKeyUsageEncr[];
extern const unsigned char attestKeyUsageZero[];
extern const unsigned char attestKeyUsageAll[];


#endif /* X509_CONSTANTS_H_ */
