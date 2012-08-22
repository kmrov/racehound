rmmod hello
rmmod rfinderm
# rm /dev/hello1
# rm /dev/hello2 
insmod rfinderm.ko
insmod hello.ko
# mknod /dev/hello1 c 250 0
# mknod /dev/hello2 c 249 0
