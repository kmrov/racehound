/* Common #include files 
 * TODO: Leave only the needed ones. */
#ifndef COMMON_INCLUDES_1814_INCLUDED
#define COMMON_INCLUDES_1814_INCLUDED

#include "plugin.h"
#include "bversion.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "line-map.h"
#include "input.h"
#include "tree.h"

#include "tree-inline.h"
#include "version.h"
#include "rtl.h"
#include "tm_p.h"
#include "flags.h"
#include "hard-reg-set.h"
#include "output.h"
#include "except.h"
#include "function.h"
#include "toplev.h"
#include "basic-block.h"
#include "intl.h"
#include "ggc.h"
#include "timevar.h"

#include "params.h"
#include "pointer-set.h"
#include "debug.h"
#include "target.h"
#include "langhooks.h"
#include "cfgloop.h"
#include "cgraph.h"
#include "opts.h"

#if BUILDING_GCC_VERSION >= 4007
#include "tree-pretty-print.h"
#include "gimple-pretty-print.h"
#include "c-tree.h"
#endif

#if BUILDING_GCC_VERSION <= 4008
#include "tree-flow.h"
#else
#include "tree-cfgcleanup.h"
#endif

#include "diagnostic.h"
#include "tree-dump.h"
#include "tree-pass.h"
#include "predict.h"
//#include "ipa-utils.h"

#if BUILDING_GCC_VERSION >= 4009
#include "varasm.h"
#include "stor-layout.h"
#include "internal-fn.h"
#include "gimple-expr.h"
#include "context.h"
#include "tree-ssa-alias.h"
#include "stringpool.h"
#include "tree-ssanames.h"
#include "print-tree.h"
#include "tree-eh.h"
#include "tree-nested.h"
#include "gimplify.h"
#endif

#include "gimple.h"

#if BUILDING_GCC_VERSION >= 4009
#include "tree-ssa-operands.h"
#include "tree-phinodes.h"
#include "tree-cfg.h"
#include "gimple-iterator.h"
#include "gimple-ssa.h"
#include "ssa-iterators.h"
#endif

#include "vec.h"

#endif /*COMMON_INCLUDES_1814_INCLUDED*/
