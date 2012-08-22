MODULE_NAME := racehound

# [NB] If you have something.h and something.c, you need to change this 
# Makefile in 3 places to add the code from these files to the module
# built this way:
#  - MODULE_SOURCES:   add something.c here
#  - MODULE_HEADERS:   add something.h here
#  - $(MODULE_NAME)-y: add something.o here

# ARCH_DIR subdirectory contains necessary files for both x86 and x86-64.
ARCH_DIR := arch/x86
ARCH_INCLUDE_DIR := $(ARCH_DIR)/include/kedr/asm

# This auxiliary file will be generated during the build (x86 instruction 
# tables as C code).
INAT_TABLES_FILE := inat-tables.h

ifeq ($(KERNELRELEASE),)
# 'Out-of-kernel' part

MODULE_SOURCES := \
	rhound.c 	\
	functions.c 	\
	bp.c \
	sections.c

# This is only to specify build dependencies
MODULE_HEADERS := \
	functions.h	\
	bp.h \
	sections.h

# This is only to specify build dependencies
INSN_ANALYZER_FILES := \
	$(ARCH_DIR)/lib/x86-opcode-map.txt	\
	$(ARCH_DIR)/lib/inat.c			\
	$(ARCH_DIR)/lib/insn.c			\
	$(ARCH_DIR)/tools/gen-insn-attr-x86.awk	\
	$(ARCH_INCLUDE_DIR)/inat.h		\
	$(ARCH_INCLUDE_DIR)/inat_types.h	\
	$(ARCH_INCLUDE_DIR)/insn.h

KBUILD_DIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)

all: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SOURCES) $(MODULE_HEADERS) $(INSN_ANALYZER_FILES)
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules
	
install:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) modules_install 

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) clean
	rm -f $(ARCH_DIR)/lib/$(INAT_TABLES_FILE)

.PHONY: all clean install

else
# KBuild part. 
# It is used by the kernel build system to actually build the module.
ccflags-y :=  -I$(src) -I$(src)/$(ARCH_DIR)/include -I$(obj)/$(ARCH_DIR)/lib

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-y := \
	rhound.o \
	functions.o	\
	sections.o	\
	bp.o \
	$(ARCH_DIR)/lib/inat.o \
	$(ARCH_DIR)/lib/insn.o

$(obj)/$(ARCH_DIR)/lib/inat.o: $(obj)/$(ARCH_DIR)/lib/$(INAT_TABLES_FILE) $(src)/$(ARCH_DIR)/lib/inat.c

# Note "LC_ALL=C" before awk, it is necessary. Without it, the awk script 
# will report semantic error in the input file on some systems. This is 
# probably due to some locale-related issues that affect separator characters,
# string parsing, etc.
$(obj)/$(ARCH_DIR)/lib/$(INAT_TABLES_FILE): $(src)/$(ARCH_DIR)/lib/x86-opcode-map.txt 
	LC_ALL=C awk -f $(src)/$(ARCH_DIR)/tools/gen-insn-attr-x86.awk $< > $@

endif
