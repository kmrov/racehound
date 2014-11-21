/* lines2insns - determine the positions of machine instructions 
 * corresponding to memory accesses in the given source locations.
 * 
 * See 'lines2insns --help' for usage details. */
/* ========================================================================
 * Copyright (C) 2014, NTC IT ROSA
 *
 * Author: 
 *      Eugene A. Shatokhin
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 ======================================================================== */

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include <getopt.h>

#include <libelf.h>

#include <kedr/asm/insn.h>

#include "config_lines2insns.h"
/* ====================================================================== */

#define APP_USAGE \
 "Usage:\n" \
 "\t" APP_NAME " [options] <module_file> < <source_locations> " \
 "> <insn_locations>\n" \
 "Execute \'" APP_NAME " --help\' for more information.\n\n"

#define APP_HELP \
 APP_NAME " [options] <module_file_with_debug_info>\n\n" \
 APP_NAME " reads the list of source locations for a kernel or a given\n" \
 "kernel module from stdin and outputs the list of machine instructions\n" \
 "corresponding to these locations that may access memory to stdout.\n\n" \
 "" \
 "Each input line must have the following format:\n\n" \
 "<path_to_source_file>:<line_no>:<column_no>[:{read|write}]\n\n" \
 "" \
 "Examples:\n\n" \
 "examples/sample_target/cfake.c:173:20:read\n" \
 "test.c:144:2\n" \
 "test2/test2.c:55:6:write\n\n" \
 "" \
 APP_NAME " reads the list of sections and debug info from the given\n" \
 "<module_file_with_debug_info> (it may be *.ko file for a kernel module\n" \
 "or vmlinu* for the kernel proper).\n" \
 "" \
 "The tool outputs the list of the corresponding machine instructions\n" \
 "in the following format, one per line:\n\n" \
 "[<module>:]{init|core}+0xoffset\n\n" \
 "" \
 "'init' and 'core' are the two main areas of the loaded kernel or\n" \
 "module. 'core' contains all *.text* sections, without gaps, in the\n" \
 "order they appear in the ELF file (*.ko or vmlinu*). 'init' contains\n" \
 "all *.init.text* sections, also in that order.\n\n" \
 "If the given file is a module, its name (without .ko) followed by\n" \
 "a colon will be output first. No such prefix will be output for the\n" \
 "kernel proper or the built-in modules.\n\n" \
 "" \
 "Example:\n\n" \
 "$ echo 'my_driver/main.c:126:16' | " APP_NAME " my_driver.ko\n" \
 "my_driver:core+0x568\n" \
 "my_driver:core+0x575\n\n" \
 "" \
 "Options:\n\n" \
 "" \
 "--help\n\t" \
 "Show this help and exit.\n\n" \
 "" \
 "--with-stack\n\t" \
 "By default, %esp/%rsp-based memory accesses are not output. This option\n\t" \
 "tells " APP_NAME " to output such instructions too.\n" \
 "" \
 "--with-locked\n\t" \
 "By default, locked operations are not output. This option tells\n\t" \
 APP_NAME " to output such instructions too.\n" \
 "" \
 "-v, --verbose\n\t" \
 "Output more messages to stderr about what is being done.\n"
/* ====================================================================== */
 
using namespace std;
/* ====================================================================== */

/* See the command-line options. */
static bool with_stack = false;
static bool with_locked = false;
static bool verbose = false;
/* ====================================================================== */

static void
show_usage()
{
	cerr << APP_USAGE;
}

static void
show_help()
{
	cerr << APP_HELP;
}

/* Process the command line arguments. Returns true if successful, false 
 * otherwise. */
static bool
process_args(int argc, char *argv[])
{
	int c;
	string module_dir = ".";
	
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"with-stack", no_argument, NULL, 's'},
		{"with-locked", no_argument, NULL, 'l'},
		{"verbose", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};
	
	while (true) {
		int index = 0;
		c = getopt_long(argc, argv, "v", long_options, &index);
		if (c == -1)
			break;  /* all options have been processed */
		
		switch (c) {
		case 0:
			break;
		case 'h':
			show_help();
			exit(EXIT_SUCCESS);
			break;
		case 's':
			with_stack = true;
			break;
		case 'l':
			with_locked = true;
			break;
		case 'v':
			verbose = true;
			break;
		case '?':
			/* Unknown option, getopt_long() should have already 
			printed an error message. */
			return false;
		default: 
			assert(false); /* Should not get here. */
		}
	}
	
	if (optind == argc) {
		cerr << "Please specify the file of the kernel or module." 
			<< endl;
		return false;
	}

	return true;
}
/* ====================================================================== */

// TODO: implement

int
main(int argc, char *argv[])
{
	if (argc == 1) {
		show_usage();
		return EXIT_FAILURE;
	}
	
	if (elf_version(EV_CURRENT) == EV_NONE) {
		cerr << "Failed to initialize libelf: " << elf_errmsg(-1) 
			<< endl;
		return EXIT_FAILURE;
	}
	
	if (!process_args(argc, argv))
		return EXIT_FAILURE;
	
	//<>
	cout << (void *)&insn_get_length << endl;
	cout << "With stack: " << with_stack << endl;
	cout << "With locked: " << with_locked << endl;
	cout << "Verbose: " << verbose << endl;
	//<>
	return 0;
}
