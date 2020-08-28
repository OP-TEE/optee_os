/*
* Copyright 2019 NXP
* All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/


/* NIST/X9.62/SECG curve over a 192 bit prime field */
PROCESS_ECC_CURVE(prime192v1);

/* NIST/SECG curve over a 224 bit prime field */
PROCESS_ECC_CURVE(secp224r1);

/* NIST/SECG curve over a 384 bit prime field */
PROCESS_ECC_CURVE(secp384r1);

/* X9.62/SECG curve over a 256 bit prime field */
PROCESS_ECC_CURVE(prime256v1);

/* NIST/SECG curve over a 521 bit prime field */
PROCESS_ECC_CURVE(secp521r1);

/* RFC 5639 curve over a 160 bit prime field */
PROCESS_ECC_CURVE(brainpoolP160r1);

/* RFC 5639 curve over a 160 bit prime field */
PROCESS_ECC_CURVE(brainpoolP160t1);

/* RFC 5639 curve over a 192 bit prime field */
PROCESS_ECC_CURVE(brainpoolP192r1);

/* RFC 5639 curve over a 192 bit prime field */
PROCESS_ECC_CURVE(brainpoolP192t1);

/* RFC 5639 curve over a 224 bit prime field */
PROCESS_ECC_CURVE(brainpoolP224r1);

/* RFC 5639 curve over a 224 bit prime field */
PROCESS_ECC_CURVE(brainpoolP224t1);

/* RFC 5639 curve over a 256 bit prime field */
PROCESS_ECC_CURVE(brainpoolP256r1);

/* RFC 5639 curve over a 256 bit prime field */
PROCESS_ECC_CURVE(brainpoolP256t1);

/* RFC 5639 curve over a 320 bit prime field */
PROCESS_ECC_CURVE(brainpoolP320r1);

/* RFC 5639 curve over a 320 bit prime field */
PROCESS_ECC_CURVE(brainpoolP320t1);

/* RFC 5639 curve over a 384 bit prime field */
PROCESS_ECC_CURVE(brainpoolP384r1);

/* RFC 5639 curve over a 384 bit prime field */
PROCESS_ECC_CURVE(brainpoolP384t1);

/* RFC 5639 curve over a 512 bit prime field */
PROCESS_ECC_CURVE(brainpoolP512r1);

/* RFC 5639 curve over a 512 bit prime field */
PROCESS_ECC_CURVE(brainpoolP512t1);

/* SECG curve over a 160 bit prime field */
PROCESS_ECC_CURVE(secp160k1);

/* SECG curve over a 192 bit prime field */
PROCESS_ECC_CURVE(secp192k1);

/* SECG curve over a 224 bit prime field */
PROCESS_ECC_CURVE(secp224k1);

/* SECG curve over a 256 bit prime field */
PROCESS_ECC_CURVE(secp256k1);

/* BN curve 256 bits */
PROCESS_ECC_CURVE(tpm_bm_p256);

#if 0
/* clang-format off */
/* SECG/WTLS curve over a 112 bit prime field */
PROCESS_ECC_CURVE(secp112r1);

/* SECG curve over a 112 bit prime field */
PROCESS_ECC_CURVE(secp112r2);

/* SECG curve over a 128 bit prime field */
PROCESS_ECC_CURVE(secp128r1);

/* SECG curve over a 128 bit prime field */
PROCESS_ECC_CURVE(secp128r2);

/* SECG curve over a 160 bit prime field */
PROCESS_ECC_CURVE(secp160r1);

/* SECG/WTLS curve over a 160 bit prime field */
PROCESS_ECC_CURVE(secp160r2);



/* X9.62 curve over a 192 bit prime field */
PROCESS_ECC_CURVE(prime192v2);

/* X9.62 curve over a 192 bit prime field */
PROCESS_ECC_CURVE(prime192v3);

/* X9.62 curve over a 239 bit prime field */
PROCESS_ECC_CURVE(prime239v1);

/* X9.62 curve over a 239 bit prime field */
PROCESS_ECC_CURVE(prime239v2);

/* X9.62 curve over a 239 bit prime field */
PROCESS_ECC_CURVE(prime239v3);


/* SECG curve over a 113 bit binary field */
PROCESS_ECC_CURVE(sect113r1);

/* SECG curve over a 113 bit binary field */
PROCESS_ECC_CURVE(sect113r2);

/* SECG/WTLS curve over a 131 bit binary field */
PROCESS_ECC_CURVE(sect131r1);

/* SECG curve over a 131 bit binary field */
PROCESS_ECC_CURVE(sect131r2);

/* NIST/SECG/WTLS curve over a 163 bit binary field */
PROCESS_ECC_CURVE(sect163k1);

/* SECG curve over a 163 bit binary field */
PROCESS_ECC_CURVE(sect163r1);

/* NIST/SECG curve over a 163 bit binary field */
PROCESS_ECC_CURVE(sect163r2);

/* SECG curve over a 193 bit binary field */
PROCESS_ECC_CURVE(sect193r1);

/* SECG curve over a 193 bit binary field */
PROCESS_ECC_CURVE(sect193r2);

/* NIST/SECG/WTLS curve over a 233 bit binary field */
PROCESS_ECC_CURVE(sect233k1);

/* NIST/SECG/WTLS curve over a 233 bit binary field */
PROCESS_ECC_CURVE(sect233r1);

/* SECG curve over a 239 bit binary field */
PROCESS_ECC_CURVE(sect239k1);

/* NIST/SECG curve over a 283 bit binary field */
PROCESS_ECC_CURVE(sect283k1);

/* NIST/SECG curve over a 283 bit binary field */
PROCESS_ECC_CURVE(sect283r1);

/* NIST/SECG curve over a 409 bit binary field */
PROCESS_ECC_CURVE(sect409k1);

/* NIST/SECG curve over a 409 bit binary field */
PROCESS_ECC_CURVE(sect409r1);

/* NIST/SECG curve over a 571 bit binary field */
PROCESS_ECC_CURVE(sect571k1);

/* NIST/SECG curve over a 571 bit binary field */
PROCESS_ECC_CURVE(sect571r1);

/* X9.62 curve over a 163 bit binary field */
PROCESS_ECC_CURVE(c2pnb163v1);

/* X9.62 curve over a 163 bit binary field */
PROCESS_ECC_CURVE(c2pnb163v2);

/* X9.62 curve over a 163 bit binary field */
PROCESS_ECC_CURVE(c2pnb163v3);

/* X9.62 curve over a 176 bit binary field */
PROCESS_ECC_CURVE(c2pnb176v1);

/* X9.62 curve over a 191 bit binary field */
PROCESS_ECC_CURVE(c2tnb191v1);

/* X9.62 curve over a 191 bit binary field */
PROCESS_ECC_CURVE(c2tnb191v2);

/* X9.62 curve over a 191 bit binary field */
PROCESS_ECC_CURVE(c2tnb191v3);

/* X9.62 curve over a 208 bit binary field */
PROCESS_ECC_CURVE(c2pnb208w1);

/* X9.62 curve over a 239 bit binary field */
PROCESS_ECC_CURVE(c2tnb239v1);

/* X9.62 curve over a 239 bit binary field */
PROCESS_ECC_CURVE(c2tnb239v2);

/* X9.62 curve over a 239 bit binary field */
PROCESS_ECC_CURVE(c2tnb239v3);

/* X9.62 curve over a 272 bit binary field */
PROCESS_ECC_CURVE(c2pnb272w1);

/* X9.62 curve over a 304 bit binary field */
PROCESS_ECC_CURVE(c2pnb304w1);

/* X9.62 curve over a 359 bit binary field */
PROCESS_ECC_CURVE(c2tnb359v1);

/* X9.62 curve over a 368 bit binary field */
PROCESS_ECC_CURVE(c2pnb368w1);

/* X9.62 curve over a 431 bit binary field */
PROCESS_ECC_CURVE(c2tnb431r1);

/* WTLS curve over a 113 bit binary field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls1);

/* NIST/SECG/WTLS curve over a 163 bit binary field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls3);

/* SECG curve over a 113 bit binary field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls4);

/* X9.62 curve over a 163 bit binary field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls5);

/* SECG/WTLS curve over a 112 bit prime field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls6);

/* SECG/WTLS curve over a 160 bit prime field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls7);

/* WTLS curve over a 112 bit prime field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls8);

/* WTLS curve over a 160 bit prime field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls9);

/* NIST/SECG/WTLS curve over a 233 bit binary field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls10);

/* NIST/SECG/WTLS curve over a 233 bit binary field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls11);

/* WTLS curve over a 224 bit prime field */
PROCESS_ECC_CURVE(wap_wsg_idm_ecid_wtls12);

/*
    IPSec/IKE/Oakley curve #3 over a 155 bit binary field.
    Not suitable for ECDSA.
    Questionable extension field! */
PROCESS_ECC_CURVE(Oakley_EC2N_3);

/*
    IPSec/IKE/Oakley curve #4 over a 185 bit binary field.
    Not suitable for ECDSA.
    Questionable extension field! */
PROCESS_ECC_CURVE(Oakley_EC2N_4);


/* clang-format on */

#endif
