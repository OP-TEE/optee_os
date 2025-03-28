#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

SHOW_DETAILS=1
ERRORS=""
basepath="$(dirname $(dirname $(readlink -f "$0")))"

details () [[ ${SHOW_DETAILS} -ne 0 ]]

verify_enum () {
  PREFIX=$1
  SYMBOL_LIST="$(grep PKCS11\_$PREFIX\_ ${basepath}/include/pkcs11_ta.h | cut -f2 | cut '-d ' -f1)"
  details && echo -e "\e[4m${PREFIX}\e[0m"
  details && echo ""
  details && echo -e "symbol\tuses\tstatus"
  for symbol in $SYMBOL_LIST ; do
    details && echo -n "$symbol"
    COUNT="$(grep ${symbol} ${basepath}/src/* | wc -l)"
    details && echo -n -e "\t${COUNT}\t"
    PRESENT="$(grep PKCS11_ID.*\($symbol.*\) ${basepath}/src/pkcs11_helpers.c | wc -l)"
    if [ ${PRESENT} -ne 0 ] ; then
      details && echo -e "\e[32mOK\e[0m"
    elif [ $COUNT -eq 0 ] ; then
      details && echo -e "\e[33mmissing but unused\e[0m"
    else
      details && echo -e "\e[31mMISSING!\e[0m"
      ERRORS+=" ${symbol}"
    fi
  done
  details && echo ""
}

verify_define () {
  PREFIX=$1
  SYMBOL_LIST="$(grep PKCS11\_$PREFIX\_ ${basepath}/include/pkcs11_ta.h | grep ^#define | cut '-d ' -f2 | cut -f1)"
  details && echo -e "\e[4m${PREFIX}\e[0m"
  details && echo ""
  details && echo -e "symbol\tuses\tstatus"
  for symbol in $SYMBOL_LIST ; do
    details && echo -n "$symbol"
    COUNT="$(grep ${symbol} ${basepath}/src/* | wc -l)"
    details && echo -n -e "\t${COUNT}\t"
    PRESENT="$(grep PKCS11_ID.*\($symbol.*\) ${basepath}/src/pkcs11_helpers.c | wc -l)"
    if [ ${PRESENT} -ne 0 ] ; then
      details && echo -e "\e[32mOK\e[0m"
    elif [ $COUNT -eq 0 ] ; then
      details && echo -e "\e[33mmissing but unused\e[0m"
    else
      details && echo -e "\e[31mMISSING!\e[0m"
      ERRORS+=" ${symbol}"
    fi
  done
  details && echo ""
}

usage() {
  SCR=$(basename "$0")
  echo "Usage: $SCR		Verify that helpers are up to date"
  echo "       $SCR --quiet	Only print errors"
  echo "       $SCR --help		This help"
  echo ""
  echo "Verification checks that all PKCS11_* enums or defines from \
include/pkcs11_ta.h are either present in src/pkcs11_helpers.c or not used at \
all."
  exit 1
}

while [[ $# -gt 0 ]]; do
  arg="$1"
  shift

  case $arg in
    -q|--quiet)
      SHOW_DETAILS=0
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "error: invalid argument: ${arg}" 1>&2
      exit 1
  esac
done

# check that symbols exists
verify_enum CKA
verify_define CKFS
verify_define CKFT
verify_define CKFSS
verify_enum CKS
verify_enum CKR
verify_enum CKO
verify_enum CKK

if [ -n "${ERRORS}" ] ; then
  SCR=$(basename "$0")
  for symbol in $ERRORS ; do
    echo "${SCR}: error: missing symbol ${symbol} in ${basepath}/src/pkcs11_helpers.c" 1>&2
  done
  exit 1
fi

exit 0
