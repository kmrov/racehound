About
-----

GCC plugin "ma_lines" finds the locations in the source code where memory 
is read from or written to and outputs these locations 
(file:line[:access_type]) to a given file.

The plugin operates during the compilation of the kernel and/or modules.

'access_type' is 'read' or 'write' depending on how memory is accessed in 
that line of the source code. If 'access_type' is omitted, both reads and 
writes are possible.

"ma_lines" only outputs the locations where "potentially global" data are
accessed (that is, the data GCC does not consider function-local).

How to use
----------

Add 
-fplugin=<path_to_ma_lines.so> -fplugin-arg-ma_lines-file=<path_to_output_file>
to the compiler options for the source files of your choice. Then build the
kernel or module as usual.

For the kernel and the modules, there are two places where to add these 
options in Kbuild or Makefile:

* ccflags-y - this way, "ma_lines" will be used for all source files 
compiled in the current directory.

Example:

ccflags-y += \
    -fplugin=/usr/local/lib/RaceHound/ma_lines.so \
    -fplugin-arg-ma_lines-file=/tmp/ma_lines-ext4.list

* CFLAGS_<src_file>.o - "ma_lines" will be used when compiling <src_file>.c
only (along with the files it #includes).

Example:

CFLAGS_r8169.o += \
    -fplugin=/usr/local/lib/RaceHound/ma_lines.so \
    -fplugin-arg-ma_lines-file=/tmp/ma_lines-r8169.list
-------------------

The output file(s) will contain one record per line (possibly with 
duplicates). For example:

/home/builder/drivers/net/ethernet/realtek/r8169.c:2038:write
/home/builder/drivers/net/ethernet/realtek/r8169.c:2040:read
/home/builder/drivers/net/ethernet/realtek/r8169.c:2040:write
/home/builder/drivers/net/ethernet/realtek/r8169.c:2043:read
/home/builder/include/uapi/linux/ethtool.h:117:write
/home/builder/include/uapi/linux/ethtool.h:118:write
/home/builder/drivers/net/ethernet/realtek/r8169.c:2099:write
-------------------

