#!/bin/bash

# $0
# $1 -> directory
# $2 -> cipher OpenSSL
# $3 -> cipher cmc-crypto
# $4 -> key
# $5 -> need reminder 0 ('1' or '0')

fatal() {
	echo "FAILED $2"
	exit $1
}

if [ -d "$1" ]; then
	DIRECTORY="$1"
else
	echo "Directory '$1' does not exist"
	exit 1
fi

KEY=$(xxd -p -c 256 "$4")
IV=$(xxd -p -c 256 "$DIRECTORY/iv.bin")

OUT_OPENSSL="$DIRECTORY/data-$2-openssl.bin"
OUT_CMCCRYPTO="$DIRECTORY/data-$3-cmc-crypto.bin"
OUTPLAIN_CMCCRYPTO="$DIRECTORY/data-$3-cmc-crypto.plain.bin"

echo -n "Testing $2... "

if [[ "$5" -ne "0" ]]; then
	LENGTH=$(stat -c %s "$DIRECTORY/data.bin")
	REMAINDER=$((LENGTH % 16))

	if [[ "$REMAINDER" -ne 0 ]]; then
		echo "SKIPPED: not-%16-compliant data"
		exit 0
	fi
fi

if [[ "$3" =~ ^AES-ECB ]]; then
	NEED_IV=0
else
	NEED_IV=1
fi

if [[ "$3" =~ PKCS#7 ]]; then
	NEED_PAD=1
else
	NEED_PAD=0
fi

# ENC with OpenSSL
openssl enc "-$2" -K $KEY -in "$DIRECTORY/data.bin" -out "$OUT_OPENSSL" \
	$( [[ "$NEED_PAD" -eq 0 ]] && echo -n "-nopad" ) \
	$( [[ "$NEED_IV" -eq 1 ]] && echo -n "-iv $IV" )

OPENSSL_RET=$?
[ "$OPENSSL_RET" -eq 0 ] || exit $OPENSSL_RET 

# ENC with cmc-crypto
./cmc-crypto e "$3" "$4" "$DIRECTORY/data.bin" "$OUT_CMCCRYPTO" \
	$( [[ "$NEED_IV" -eq 1 ]] && echo -n "$DIRECTORY/iv.bin" )

CMCCRYPTO_RET=$?
[ "$CMCCRYPTO_RET" -eq 0 ] || exit $CMCCRYPTO_RET 

# DEC with cmc-crypto
./cmc-crypto d "$3" "$4" "$OUT_CMCCRYPTO" "$OUTPLAIN_CMCCRYPTO" \
	$( [[ "$NEED_IV" -eq 1 ]] && echo -n "$DIRECTORY/iv.bin" )

CMCCRYPTO_RET=$?
[ "$CMCCRYPTO_RET" -eq 0 ] || exit $CMCCRYPTO_RET 

# Check ENC-DEC with cmc-crypto are ok
diff "$DIRECTORY/data.bin" "$OUTPLAIN_CMCCRYPTO" > /dev/null

[ $? -eq 0 ] || fatal 1 "cmc-crypto: enc-dec failed"

# Check OpenSSL and cmc-crypto have produced the same output
diff "$OUT_OPENSSL" "$OUT_CMCCRYPTO"

[ $? -eq 0 ] || fatal 1 "cmc-crypto and openssl have produced different results"

echo "OK" 
