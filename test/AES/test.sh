#!/bin/bash

# $0
# $1 -> directory

if [ -d "$1" ]; then
	DIR="$1"
else
	echo "Directory '$1' does not exist"
	exit 1
fi

HERE="$(dirname "$0")"
i=0

safe_exit_sigint() {
	echo ""
	echo "TEST COUNT: $i"
	exit 0
}

trap safe_exit_sigint SIGINT

for ((i = 1; i > 0; i++)); do
	$HERE/create_test_data.sh "$DIR"
	TESTER="$HERE/do_one_test.sh"

	# AES-ECB (no padding)
	$TESTER "$DIR" "aes-128-ecb" "AES-ECB" "$DIR/key128.bin" 1 || exit $?
	$TESTER "$DIR" "aes-192-ecb" "AES-ECB" "$DIR/key192.bin" 1 || exit $?
	$TESTER "$DIR" "aes-256-ecb" "AES-ECB" "$DIR/key256.bin" 1 || exit $?

	# AES-ECB (PKCS#7 padding)
	$TESTER "$DIR" "aes-128-ecb" "AES-ECB-PKCS#7" "$DIR/key128.bin" 0 || exit $?
	$TESTER "$DIR" "aes-192-ecb" "AES-ECB-PKCS#7" "$DIR/key192.bin" 0 || exit $?
	$TESTER "$DIR" "aes-256-ecb" "AES-ECB-PKCS#7" "$DIR/key256.bin" 0 || exit $?

	# AES-CBC (no padding)
	$TESTER "$DIR" "aes-128-cbc" "AES-CBC" "$DIR/key128.bin" 1 || exit $?
	$TESTER "$DIR" "aes-192-cbc" "AES-CBC" "$DIR/key192.bin" 1 || exit $?
	$TESTER "$DIR" "aes-256-cbc" "AES-CBC" "$DIR/key256.bin" 1 || exit $?

	# AES-CBC (PKCS#7 padding)
	$TESTER "$DIR" "aes-128-cbc" "AES-CBC-PKCS#7" "$DIR/key128.bin" 0 || exit $?
	$TESTER "$DIR" "aes-192-cbc" "AES-CBC-PKCS#7" "$DIR/key192.bin" 0 || exit $?
	$TESTER "$DIR" "aes-256-cbc" "AES-CBC-PKCS#7" "$DIR/key256.bin" 0 || exit $?

	# AES-OFB (no padding needed)
	$TESTER "$DIR" "aes-128-ofb" "AES-OFB" "$DIR/key128.bin" 0 || exit $?
	$TESTER "$DIR" "aes-192-ofb" "AES-OFB" "$DIR/key192.bin" 0 || exit $?
	$TESTER "$DIR" "aes-256-ofb" "AES-OFB" "$DIR/key256.bin" 0 || exit $?
done
