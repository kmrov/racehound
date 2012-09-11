#!/bin/sh

for i in 1..100
do
   echo "+" > /sys/kernel/debug/rfindertest/hello
   sleep 0.1s
done
