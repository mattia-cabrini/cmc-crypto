#!/bin/bash

if [ -d "$1" ]; then
	DIRECTORY="$1"
else
	echo "Directory '$1' does not exist"
	exit 1
fi

# Remove existing data
rm -f "$1"/*.bin

# Creating new data
head /dev/urandom -c 16 > "$1/iv.bin"
head /dev/urandom -c 16 > "$1/key128.bin"
head /dev/urandom -c 24 > "$1/key192.bin"
head /dev/urandom -c 32 > "$1/key256.bin"

C="$(cat /dev/urandom | tr -cd '0-9' | head -c 2)"

if [[ "$C" = "00" ]]; then
	# ZERO data
	printf "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 \
		> "$1/data.bin"
	echo "Created '$1/data.bin', with length $(stat -c %s "$1/data.bin"), ZERO"
else
	LENGTH=$(cat /dev/urandom | tr -cd '0-9' | head -c 3)
	head /dev/urandom -c $LENGTH > "$1/data.bin"
	echo "Created '$1/data.bin', with length $(stat -c %s "$1/data.bin")"
fi
