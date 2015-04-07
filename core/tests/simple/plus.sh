#!/bin/sh

echo "plus: $$"

for i in `seq 200`
do
   echo "+" > /sys/kernel/debug/rfindertest/hello
   sleep 0.005s
done
