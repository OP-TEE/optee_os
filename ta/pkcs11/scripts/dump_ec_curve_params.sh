#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause

EC_CURVES="prime192v1 secp224r1 prime256v1 secp384r1 secp521r1"

echo "/*"
echo " * DER encoded EC parameters generated with script:"
echo " *   ta/pkcs11/scripts/dump_ec_params.sh"
echo " */"
echo ""

for EC_CURVE in ${EC_CURVES} ; do
	echo "static const uint8_t ${EC_CURVE}_name_der[] = {"
	openssl ecparam -name ${EC_CURVE} -param_enc named_curve | \
		openssl asn1parse -noout -out /dev/stdout | \
		hexdump -v -e '/8 "\t"' -e '/1 "0x%02x, " ' -e '/8 "\n"' | \
		sed 's/0x  ,//g'
	echo "};"
	echo ""
done

for EC_CURVE in ${EC_CURVES} ; do
	echo "static const uint8_t ${EC_CURVE}_oid_der[] = {"
	openssl ecparam -name ${EC_CURVE} -param_enc explicit | \
		openssl asn1parse -noout -out /dev/stdout | \
		hexdump -v -e '/8 "\t"' -e '/1 "0x%02x, " ' -e '/8 "\n"' | \
		sed 's/0x  ,//g'
	echo "};"
	echo ""
done
