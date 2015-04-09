#!/bin/sh

echo "$0: $$"

while true; do
	echo "+" > /sys/kernel/debug/rfindertest/hello
	sleep 0.01s
done
