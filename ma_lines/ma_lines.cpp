/* Some of the functions here are based on the implementation of 
 * ThreadSanitizer from GCC 4.9 (gcc/tsan.c). */

#include <assert.h>
#include <string.h>
#include <gcc-plugin.h>
#include <plugin-version.h>

#include "common_includes.h"

#include <stdio.h>
#include <sys/file.h>

#include <iostream>
#include <fstream>
#include <string>
#include <set>

#include <common/util.h>
/* ====================================================================== */

#if BUILDING_GCC_VERSION <= 4008
#define ENTRY_BLOCK_PTR_FOR_FN(FN)	ENTRY_BLOCK_PTR_FOR_FUNCTION(FN)
#define EXIT_BLOCK_PTR_FOR_FN(FN)	EXIT_BLOCK_PTR_FOR_FUNCTION(FN)
#endif

/* ====================================================================== */

/* Use this to mark the functions to be exported from this plugin. The 
 * remaining functions will not be visible from outside of this plugin even
 * if they are not static (-fvisibility=hidden GCC option is used to achieve
 * this). */
#define PLUGIN_EXPORT __attribute__ ((visibility("default")))
/* ====================================================================== */

#ifdef __cplusplus
extern "C" {
#endif

/* This symbol is needed for GCC to know the plugin is GPL-compatible. */
PLUGIN_EXPORT int plugin_is_GPL_compatible;

/* Plugin initialization function, the only function to be exported */
PLUGIN_EXPORT int
plugin_init(struct plugin_name_args *plugin_info,
	    struct plugin_gcc_version *version);

#ifdef __cplusplus
}
#endif
/* ====================================================================== */

/* The file to dump the info about interesting source locations to. Can be 
 * specified as an argument to the plugin:
 * -fplugin-arg-ma_lines-file=<path_to_output_file> */
static std::string out_file = "./dump_memory_accesses.list";
/* ====================================================================== */

/* These memory/string operations may be replaced by their implementation
 * in assembly in the code. The reads/writes they perform may be needed to 
 * track. */
static std::string _funcs[] = {
	"strstr",
	"strspn",
	"strsep",
	"strrchr",
	"strpbrk",
	"strnstr",
	"strnlen",
	"strnicmp",
	"strncpy",
	"strncmp",
	"strnchr",
	"strncat",
	"strncasecmp",
	"strlen",
	"strlcpy",
	"strlcat",
	"strcspn",
	"strcpy",
	"strcmp",
	"strchr",
	"strcat",
	"strcasecmp",
	"memset",
	"memcpy",
	"memcmp",
	"memscan",
	"memmove",
	"memchr",
	"__memcpy",
};
static std::set<std::string> special_functions(
	&_funcs[0], &_funcs[0] + sizeof(_funcs) / sizeof(_funcs[0]));
/* ====================================================================== */

static void
output_ma_location(gimple stmt, EAccessType ma_type)
{
	int ret;
	
	location_t loc = gimple_location(stmt);
	const char *src = LOCATION_FILE(loc);
	unsigned int line = LOCATION_LINE(loc);
	/* No need to output the column, it seems to be ignored in debug
	 * info. */
	
	if (src == NULL) {
		fprintf(stderr, 
"[ma_lines] Path to the source file is missing, skipping the statement.\n");
		return;
	}
	
	FILE *out = fopen(out_file.c_str(), "a");
	if (out == NULL) {
		fprintf(stderr, 
	"[ma_lines] Failed to open file \"%s\".\n", out_file.c_str());
		return;
	}
	
	int fd = fileno(out);
	if (fd == -1) {
		fprintf(stderr, "[ma_lines] Internal error.\n");
		goto end;
	}
	
	/* Lock the output file in case GCC processes 2 or more files at the
	 * same time. */
	ret = flock(fd, LOCK_EX);
	if (ret != 0) {
		fprintf(stderr, 
			"[ma_lines] Failed to lock the output file.\n");
		goto end;
	}
	
	/* Another instance of this plugin might have written to the file 
	 * after we have opened it but before we have got the lock.
	 * We need to set the current position in the file to its end again.
	 */
	ret = fseek(out, 0, SEEK_END);
	if (ret != 0) {
		fprintf(stderr, 
			"[ma_lines] Failed to seek to the end of file.\n");
		goto unlock;
	}
	
	fprintf(out, "%s:%u", src, line);
	if (ma_type == AT_READ) {
		fprintf(out, ":read\n");
	}
	else if (ma_type == AT_WRITE) {
		fprintf(out, ":write\n");
	}
	else /* AT_BOTH and all other values */ {
		fprintf(out, "\n");
	}

unlock:
	ret = flock(fd, LOCK_UN);
	if (ret != 0) {
		fprintf(stderr, 
			"[ma_lines] Failed to unlock the output file.\n");
	}
end:
	fclose(out);
}

/* Report source locations for the calls to the functions of interest (those
 * that might be replaced with their implementation in assembly, like 
 * memcpy(), etc. */
static void
process_function_call(gimple_stmt_iterator *gsi)
{
	gimple stmt = gsi_stmt(*gsi);
	tree fndecl = gimple_call_fndecl(stmt);
	
	if (!fndecl) { 
		/* Indirect call, nothing to do. */
		return;
	}

	const char *name = IDENTIFIER_POINTER(DECL_NAME(fndecl));
	if (special_functions.find(name) != special_functions.end()) {
		output_ma_location(stmt, AT_BOTH);
	}
}

static void
process_expr(gimple_stmt_iterator gsi, tree expr, bool is_write)
{
	gimple stmt = gsi_stmt(gsi);
	HOST_WIDE_INT size = int_size_in_bytes(TREE_TYPE (expr));
	if (size < 1)
		return;

	/* TODO: Check how this works when bit fields are accessed, update 
	 * if needed (~ report touching the corresponding bytes as a 
	 * whole?) */
	HOST_WIDE_INT bitsize;
	HOST_WIDE_INT bitpos;
	tree offset;
	enum machine_mode mode;
	int volatilep = 0;
	int unsignedp = 0;
	tree base = get_inner_reference(
		expr, &bitsize, &bitpos, &offset, &mode, &unsignedp, 
		&volatilep, false);

	/* [?] Looks like (gcc/passes.def) IPA passes come after "einline" 
	 * pass, so we may need another pass to use the results of IPA 
	 * analysis. This is because most of the instrumentation is done 
	 * here before "einline" pass. */
	if (DECL_P(base)) {
		struct pt_solution pt;
		memset(&pt, 0, sizeof(pt));
		pt.escaped = 1;
		pt.ipa_escaped = flag_ipa_pta != 0;
		pt.nonlocal = 1;
		if (!pt_solution_includes(&pt, base)) {
			//<>
			//fprintf(stderr, "[DBG] The decl does not escape.\n");
			//<>
			return;
		}
		if (!is_global_var(base) && !may_be_aliased(base)) {
			//<>
			//fprintf(stderr, "[DBG] Neither global nor may be aliased.\n");
			//<>
			return;
		}
	}

	if (TREE_READONLY (base) || 
	   (TREE_CODE (base) == VAR_DECL && DECL_HARD_REGISTER (base))) {
		//<>
		//fprintf(stderr, "[DBG] Read-only or register variable.\n");
		//<>
		return;
	}

	// TODO: bit field access. How to handle it properly?
	if (bitpos % (size * BITS_PER_UNIT) ||
	    bitsize != size * BITS_PER_UNIT) {
		return;
	}

	output_ma_location(stmt, (is_write ? AT_WRITE : AT_READ));
}

static void
process_gimple(gimple_stmt_iterator *gsi)
{
	gimple stmt;
	stmt = gsi_stmt(*gsi);
	
	if (is_gimple_call(stmt)) {
		process_function_call(gsi);
	}
	else if (is_gimple_assign(stmt) && !gimple_clobber_p(stmt)) {
		if (gimple_store_p(stmt)) {
			tree lhs = gimple_assign_lhs(stmt);
			process_expr(*gsi, lhs, true);
		}
		if (gimple_assign_load_p(stmt)) {
			tree rhs = gimple_assign_rhs1(stmt);
			process_expr(*gsi, rhs, false);
		}
	}
}

/* The main function of the pass. Called for each function to be processed.
 */
static unsigned int
do_execute()
{
	//<>
	/*fprintf(stderr, "[DBG] Processing function \"%s\".\n",
		current_function_name());*/
	//<>
	
	basic_block bb;
	gimple_stmt_iterator gsi;
	
	FOR_EACH_BB_FN (bb, cfun) {
		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); 
		     gsi_next(&gsi)) {
			process_gimple(&gsi);
		}
	}
	return 0;
}
/* ====================================================================== */

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data my_pass_data = {
#else
static struct gimple_opt_pass my_pass = {
	.pass = {
#endif
		.type = 	GIMPLE_PASS,
		.name = 	"racehound_ma_lines",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags = OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate	= false,
		.has_execute	= true,
#else
		.gate = 	NULL,
		.execute =	do_execute, /* main function of the pass */
		.sub = 		NULL,
		.next = 	NULL,
		.static_pass_number = 0,
#endif
		.tv_id = 	TV_NONE,
		.properties_required = PROP_ssa | PROP_cfg,
		.properties_provided = 0,
		.properties_destroyed = 0,
		.todo_flags_start = 0,
		.todo_flags_finish = TODO_verify_all | TODO_update_ssa
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class my_pass : public gimple_opt_pass {
public:
	my_pass() 
	  : gimple_opt_pass(my_pass_data, g) 
	{}
	unsigned int execute() { return do_execute(); }
}; /* class my_pass */
}  /* anon namespace */
#endif

static struct opt_pass *make_my_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new my_pass();
#else
	return &my_pass.pass;
#endif
}
/* ====================================================================== */

int
plugin_init(struct plugin_name_args *plugin_info,
	    struct plugin_gcc_version *version)
{
	struct register_pass_info pass_info;
	
	if (!plugin_default_version_check(version, &gcc_version))
		return 1;
	
	pass_info.pass = make_my_pass();
	pass_info.reference_pass_name = "ssa";
	/* consider only the 1st occasion of the reference pass */
	pass_info.ref_pass_instance_number = 1;
	pass_info.pos_op = PASS_POS_INSERT_AFTER;
	
	if (plugin_info->argc > 0) {
		struct plugin_argument *arg = &plugin_info->argv[0];
		if (strcmp(arg->key, "file") == 0)
			out_file = arg->value;
	}
	
	/* Register the pass */
	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
			  NULL, &pass_info);
	return 0;
}
/* ====================================================================== */
