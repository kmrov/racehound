#!/bin/sh

echo "plus: $$"

for i in `seq 1000`
do
   echo "+" > /sys/kernel/debug/rfindertest/hello
   sleep 0.01s
done
