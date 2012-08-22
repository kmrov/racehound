#!/bin/awk -f
# gen-insn-attr-x86.awk: Instruction attribute table generator
# Written by Masami Hiramatsu <mhiramat@redhat.com>
#
# Handling of register usage information was implemented by 
#   Eugene A. Shatokhin <spectre@ispras.ru>, 2011
#
# Usage: awk -f gen-insn-attr-x86.awk x86-opcode-map.txt > inat-tables.c

# Awk implementation sanity check
function check_awk_implement() {
    if (sprintf("%x", 0) != "0")
        return "Your awk has a printf-format problem."
    return ""
}

# Clear working vars
function clear_vars() {
    delete table
    delete lptable2
    delete lptable1
    delete lptable3
    eid = -1 # escape id
    gid = -1 # group id
    aid = -1 # AVX id
    tname = ""
    
    # Addressing method and operand type attributes
    attr_am[1] = null
    attr_am[2] = null
    attr_ot[1] = null
    attr_ot[2] = null
}

BEGIN {
    # Implementation error checking
    awkchecked = check_awk_implement()
    if (awkchecked != "") {
        print "Error: " awkchecked > "/dev/stderr"
        print "Please try to use gawk." > "/dev/stderr"
        exit 1
    }

    # Setup generating tables
    print "/* x86 opcode map generated from x86-opcode-map.txt */"
    print "/* Do not change this code. */\n"
    ggid = 1
    geid = 1
    gaid = 0
    delete etable
    delete gtable
    delete atable

    opnd_expr = "^[A-Za-z/]"
    ext_expr = "^\\("
    sep_expr = "^\\|$"
    group_expr = "^Grp[0-9A-Za-z]+"

    imm_expr = "^[IJAO][a-z]"
    imm_flag["Ib"] = "INAT_MAKE_IMM(INAT_IMM_BYTE)"
    imm_flag["Jb"] = "INAT_MAKE_IMM(INAT_IMM_BYTE)"
    imm_flag["Iw"] = "INAT_MAKE_IMM(INAT_IMM_WORD)"
    imm_flag["Id"] = "INAT_MAKE_IMM(INAT_IMM_DWORD)"
    imm_flag["Iq"] = "INAT_MAKE_IMM(INAT_IMM_QWORD)"
    imm_flag["Ap"] = "INAT_MAKE_IMM(INAT_IMM_PTR)"
    imm_flag["Iz"] = "INAT_MAKE_IMM(INAT_IMM_VWORD32)"
    imm_flag["Jz"] = "INAT_MAKE_IMM(INAT_IMM_VWORD32)"
    imm_flag["Iv"] = "INAT_MAKE_IMM(INAT_IMM_VWORD)"
    imm_flag["Ob"] = "INAT_MOFFSET"
    imm_flag["Ov"] = "INAT_MOFFSET"

    modrm_expr = "^([CDEGMNPQRSUVW/][a-z]+|NTA|T[012])"
    force64_expr = "\\([df]64\\)"
    rex_expr = "^REX(\\.[XRWB]+)*"
    fpu_expr = "^ESC" # TODO

    lprefix1_expr = "\\(66\\)"
    lprefix2_expr = "\\(F3\\)"
    lprefix3_expr = "\\(F2\\)"
    max_lprefix = 4

    vexok_expr = "\\(VEX\\)"
    vexonly_expr = "\\(oVEX\\)"

    prefix_expr = "\\(Prefix\\)"
    prefix_num["Operand-Size"] = "INAT_PFX_OPNDSZ"
    prefix_num["REPNE"] = "INAT_PFX_REPNE"
    prefix_num["REP/REPE"] = "INAT_PFX_REPE"
    prefix_num["LOCK"] = "INAT_PFX_LOCK"
    prefix_num["SEG=CS"] = "INAT_PFX_CS"
    prefix_num["SEG=DS"] = "INAT_PFX_DS"
    prefix_num["SEG=ES"] = "INAT_PFX_ES"
    prefix_num["SEG=FS"] = "INAT_PFX_FS"
    prefix_num["SEG=GS"] = "INAT_PFX_GS"
    prefix_num["SEG=SS"] = "INAT_PFX_SS"
    prefix_num["Address-Size"] = "INAT_PFX_ADDRSZ"
    prefix_num["2bytes-VEX"] = "INAT_PFX_VEX2"
    prefix_num["3bytes-VEX"] = "INAT_PFX_VEX3"
    
    # The instruction tables may contain only a part of the data concerning 
    # register usage, i.e. the data that can be obtained using the opcode
    # only. 
    # For some instructions, the tables may specify more registers that
    # these instructions actually use. This should not make much harm 
    # though. The register usage info is used when looking for a free 
    # register during code instrumentation. So it is safer to mark more
    # registers as used.
    regs_expr = "Regs:"
    regs_flag["AX"] = "INAT_USES_REG_AX"
    regs_flag["CX"] = "INAT_USES_REG_CX"
    regs_flag["DX"] = "INAT_USES_REG_DX"
    regs_flag["BX"] = "INAT_USES_REG_BX"
    regs_flag["SP"] = "INAT_USES_REG_SP"
    regs_flag["BP"] = "INAT_USES_REG_BP"
    regs_flag["SI"] = "INAT_USES_REG_SI"
    regs_flag["DI"] = "INAT_USES_REG_DI"
    
    # Types of memory access 
    mem_expr = "Mem:"
    mem_flag["R"]  = "INAT_MEM_CAN_READ"
    mem_flag["W"]  = "INAT_MEM_CAN_WRITE"
    mem_flag["RW"] = "INAT_MEM_CAN_READ | INAT_MEM_CAN_WRITE"
    
    # For now, operand attributes are processed only for the operands
    # specified in Mod R/M byte and also if xSI and xDI based addressing
    # is used.
    opnd_attr_expr = "^[ACDEFGIJMNOPQRSUVWXY][a-z]*"
    
    # Flags for the addressing method (how to interpret a given operand)
    amethod_flag["A"] = "INAT_AMETHOD_A"
    amethod_flag["C"] = "INAT_AMETHOD_C"
    amethod_flag["D"] = "INAT_AMETHOD_D"
    amethod_flag["E"] = "INAT_AMETHOD_E"
    amethod_flag["F"] = "INAT_AMETHOD_F"
    amethod_flag["G"] = "INAT_AMETHOD_G"
    amethod_flag["I"] = "INAT_AMETHOD_I"
    amethod_flag["J"] = "INAT_AMETHOD_J"
    amethod_flag["M"] = "INAT_AMETHOD_M"
    amethod_flag["N"] = "INAT_AMETHOD_N"
    amethod_flag["O"] = "INAT_AMETHOD_O"
    amethod_flag["P"] = "INAT_AMETHOD_P"
    amethod_flag["Q"] = "INAT_AMETHOD_Q"
    amethod_flag["R"] = "INAT_AMETHOD_R"
    amethod_flag["S"] = "INAT_AMETHOD_S"
    amethod_flag["U"] = "INAT_AMETHOD_U"
    amethod_flag["V"] = "INAT_AMETHOD_V"
    amethod_flag["W"] = "INAT_AMETHOD_W"
    amethod_flag["X"] = "INAT_AMETHOD_X"
    amethod_flag["Y"] = "INAT_AMETHOD_Y"
    
    # Flags for operand types (useful to determine operand size)
    opnd_type_flag["a"]  = "INAT_OPTYPE_A"
    opnd_type_flag["b"]  = "INAT_OPTYPE_B"
    opnd_type_flag["c"]  = "INAT_OPTYPE_C"
    opnd_type_flag["d"]  = "INAT_OPTYPE_D"
    opnd_type_flag["dq"] = "INAT_OPTYPE_DQ"
    opnd_type_flag["p"]  = "INAT_OPTYPE_P"
    opnd_type_flag["pd"] = "INAT_OPTYPE_PD"
    opnd_type_flag["pi"] = "INAT_OPTYPE_PI"
    opnd_type_flag["ps"] = "INAT_OPTYPE_PS"
    opnd_type_flag["q"]  = "INAT_OPTYPE_Q"
    opnd_type_flag["s"]  = "INAT_OPTYPE_S"
    opnd_type_flag["sd"] = "INAT_OPTYPE_SD"
    opnd_type_flag["ss"] = "INAT_OPTYPE_SS"
    opnd_type_flag["si"] = "INAT_OPTYPE_SI"
    opnd_type_flag["v"]  = "INAT_OPTYPE_V"
    opnd_type_flag["w"]  = "INAT_OPTYPE_W"
    opnd_type_flag["y"]  = "INAT_OPTYPE_Y"
    opnd_type_flag["z"]  = "INAT_OPTYPE_Z"
    
    clear_vars()
}

function semantic_error(msg) {
    print "Semantic error at " NR ": " msg > "/dev/stderr"
    exit 1
}

function debug(msg) {
    print "DEBUG: " msg
}

function array_size(arr,   i,c) {
    c = 0
    for (i in arr)
        c++
    return c
}

/^Table:/ {
    print "/* " $0 " */"
    if (tname != "")
        semantic_error("Hit Table: before EndTable:.");
}

/^Referrer:/ {
    if (NF != 1) {
        # escape opcode table
        ref = ""
        for (i = 2; i <= NF; i++)
            ref = ref $i
        eid = escape[ref]
        tname = sprintf("inat_escape_table_%d", eid)
    }
}

/^AVXcode:/ {
    if (NF != 1) {
        # AVX/escape opcode table
        aid = $2
        if (gaid <= aid)
            gaid = aid + 1
        if (tname == "")    # AVX only opcode table
            tname = sprintf("inat_avx_table_%d", $2)
    }
    if (aid == -1 && eid == -1) # primary opcode table
        tname = "inat_primary_table"
}

/^GrpTable:/ {
    print "/* " $0 " */"
    if (!($2 in group))
        semantic_error("No group: " $2 )
    gid = group[$2]
    tname = "inat_group_table_" gid
}

function operand_attributes(    s_result, s_part, k, not_first)
{
    if (attr_am[1]) 
        s_part[1] = ".addr_method1 = " attr_am[1]
    
    if (attr_am[2]) 
        s_part[2] = ".addr_method2 = " attr_am[2]
        
    if (attr_ot[1]) 
        s_part[3] = ".opnd_type1 = " attr_ot[1]
    
    if (attr_ot[2]) 
        s_part[4] = ".opnd_type2 = " attr_ot[2]
    
    not_first = null
    s_result = ""
    
    for (k = 1; k <= 4; k++) {
        if (s_part[k]) {
            if (not_first)
                s_result = s_result ", "
            else
                not_first = "yes"
            
            s_result = s_result s_part[k]
        }
    }
    
    if (length(s_result) == 0)
        return null
    else
        return s_result
}

function prepare_item(iflags,iattrs,    s_result)
{
    s_result = ""
    if (iflags) {
        s_result = ".attributes = " iflags
        if (iattrs)
            s_result = s_result ", "
    }
    
    if (iattrs) 
        s_result = s_result iattrs

    if (length(s_result) == 0)
        return null
    else
        return s_result
}

function print_table(tbl,name,fmt,n,    s)
{
    print "const insn_attr_t " name " = {"
    for (i = 0; i < n; i++) {
        id = sprintf(fmt, i)
        if (tbl[id])
            print " [" id "] = {" tbl[id] "},"
    }
    print "};"
}

/^EndTable/ {
    if (gid != -1) {
        # print group tables
        if (array_size(table) != 0) {
            print_table(table, tname "[INAT_GROUP_TABLE_SIZE]",
                    "0x%x", 8)
            gtable[gid,0] = tname
        }
        if (array_size(lptable1) != 0) {
            print_table(lptable1, tname "_1[INAT_GROUP_TABLE_SIZE]",
                    "0x%x", 8)
            gtable[gid,1] = tname "_1"
        }
        if (array_size(lptable2) != 0) {
            print_table(lptable2, tname "_2[INAT_GROUP_TABLE_SIZE]",
                    "0x%x", 8)
            gtable[gid,2] = tname "_2"
        }
        if (array_size(lptable3) != 0) {
            print_table(lptable3, tname "_3[INAT_GROUP_TABLE_SIZE]",
                    "0x%x", 8)
            gtable[gid,3] = tname "_3"
        }
    } else {
        # print primary/escaped tables
        if (array_size(table) != 0) {
            print_table(table, tname "[INAT_OPCODE_TABLE_SIZE]",
                    "0x%02x", 256)
            etable[eid,0] = tname
            if (aid >= 0)
                atable[aid,0] = tname
        }
        if (array_size(lptable1) != 0) {
            print_table(lptable1,tname "_1[INAT_OPCODE_TABLE_SIZE]",
                    "0x%02x", 256)
            etable[eid,1] = tname "_1"
            if (aid >= 0)
                atable[aid,1] = tname "_1"
        }
        if (array_size(lptable2) != 0) {
            print_table(lptable2,tname "_2[INAT_OPCODE_TABLE_SIZE]",
                    "0x%02x", 256)
            etable[eid,2] = tname "_2"
            if (aid >= 0)
                atable[aid,2] = tname "_2"
        }
        if (array_size(lptable3) != 0) {
            print_table(lptable3,tname "_3[INAT_OPCODE_TABLE_SIZE]",
                    "0x%02x", 256)
            etable[eid,3] = tname "_3"
            if (aid >= 0)
                atable[aid,3] = tname "_3"
        }
    }
    print ""
    clear_vars()
}

function add_flags(old,new) 
{
    if (old && new)
        return old " | " new
    else if (old)
        return old
    else
        return new
}

function add_reg_usage_flags(current_flags, regs_string) 
{
    if (!regs_string)
        return current_flags
    
    split(regs_string, regs_names, ",")
    for (r_index in regs_names) {
        r_name = regs_names[r_index]
        if (!regs_flag[r_name]) 
            semantic_error("Unknown register: " r_name)
        current_flags = add_flags(current_flags, regs_flag[r_name])
    }
    return current_flags
}

function add_mem_access_flags(current_flags, mem_string)
{
    if (!mem_string)
        return current_flags
    
    if (!(mem_string in mem_flag))
        semantic_error("Unknown memory access code: " mem_string)
    
    current_flags = add_flags(current_flags, mem_flag[mem_string])
    return current_flags
}

# convert operands to flags.
function convert_operands(count,opnd,      i,j,imm,mod,s)
{
    imm = null
    mod = null
    attr_am[1] = null
    attr_am[2] = null
    attr_ot[1] = null
    attr_ot[2] = null
    
    for (j = 1; j <= count; j++) {
        i = opnd[j]
       
        if (match(i, imm_expr) == 1) {
            if (!imm_flag[i])
                semantic_error("Unknown imm opnd: " i)
            if (imm) {
                if (i != "Ib")
                    semantic_error("Second IMM error")
                imm = add_flags(imm, "INAT_SCNDIMM")
            } else
                imm = imm_flag[i]
        } else if (match(i, modrm_expr)) {
            mod = "INAT_MODRM"
        }
        
        # [NB] If there are more than 2 operands, the one(s) we are 
        # interested in should be the first one(s). Typically, the 
        # remaining operands are explicitly specified registers or
        # immediates.
        if (j <= 2 && match(i, opnd_attr_expr)) {
            # Process the code for addressing method.
            s = substr(i, 1, 1)
            if (!amethod_flag[s])
                semantic_error("Unknown addressing method code: " s)
            
            # It is possible that the addressing mode is not followed by 
            # an operand type flag (example: "lea"). 
            # Also, we need to filter out "ES" and the like where the first
            # capital letter is actually not an addressing method.
            if (length(i) == 1 || match(i, "[a-z]") == 2)
                attr_am[j] = amethod_flag[s]
            
            # Process the code for operand type 
            s = substr(i, 2)
            # "d/q" will be treated as "d", not significant for now
            if (match(s, "^[a-z]+")) {
                s = substr(s, 1, RLENGTH)
                if (!opnd_type_flag[s])
                    semantic_error("Unknown operand type code: " s)
                attr_ot[j] = opnd_type_flag[s]
            }
        }
    } # end for
    return add_flags(imm, mod)
}

/^[0-9a-f]+\:/ {
    if (NR == 1)
        next
 
    # get index
    idx = "0x" substr($1, 1, index($1,":") - 1)
    if (idx in table)
        semantic_error("Redefine " idx " in " tname)

    # check if escaped opcode
    if ("escape" == $2) {
        if ($3 != "#")
            semantic_error("No escaped name")
        ref = ""
        for (i = 4; i <= NF; i++)
            ref = ref $i
        if (ref in escape)
            semantic_error("Redefine escape (" ref ")")
        escape[ref] = geid
        geid++
        table[idx] = "INAT_MAKE_ESCAPE(" escape[ref] ")"
        next
    }
    
    variant = null
    base_attrs = null
    
    # converts
    i = 2
    while (i <= NF) {
        opcode = $(i++)
        delete opnds
        ext = null
        flags = null
        opnd = null
        regs = null
        attrs = null
        mem_access = null
                
        # parse one opcode
        if (match($i, opnd_expr) && 
            !match($i, regs_expr) && !match($i, mem_expr)) 
        {
            opnd = $i
            count = split($(i++), opnds, ",")
            flags = convert_operands(count, opnds)
            attrs = operand_attributes()
        }
        
        if (match($i, ext_expr) && 
            !match($i, regs_expr) && !match($i, mem_expr))
        {
            ext = $(i++)
        }
        
        if (match($i, regs_expr)){
            regs = $(++i)
            i++
        }
        
        if (match($i, mem_expr)){
            mem_access = $(++i)
            i++
        }
        
        if (match($i, sep_expr))
            i++
        else if (i < NF)
            semantic_error($i " is not a separator")

        # check if group opcode
        if (match(opcode, group_expr)) {
            if (!(opcode in group)) {
                group[opcode] = ggid
                ggid++
            }
            flags = add_flags(flags, "INAT_MAKE_GROUP(" group[opcode] ")")
        }
        # check force(or default) 64bit
        if (match(ext, force64_expr))
            flags = add_flags(flags, "INAT_FORCE64")

        # check REX prefix
        if (match(opcode, rex_expr))
            flags = add_flags(flags, "INAT_MAKE_PREFIX(INAT_PFX_REX)")

        # check coprocessor escape : TODO
        if (match(opcode, fpu_expr))
            flags = add_flags(flags, "INAT_MODRM")

        # check VEX only code
        if (match(ext, vexonly_expr))
            flags = add_flags(flags, "INAT_VEXOK | INAT_VEXONLY")

        # check VEX only code
        if (match(ext, vexok_expr))
            flags = add_flags(flags, "INAT_VEXOK")

        # check prefixes
        if (match(ext, prefix_expr)) {
            if (!prefix_num[opcode])
                semantic_error("Unknown prefix: " opcode)
            flags = add_flags(flags, "INAT_MAKE_PREFIX(" prefix_num[opcode] ")")
        }
        
        # process register usage information
        if (regs)
            flags = add_reg_usage_flags(flags, regs)
            
        # process memory access information
        if (mem_access)
            flags = add_mem_access_flags(flags, mem_access)

        if (length(flags) != 0 || attrs) {
            # check the last prefix
            if (match(ext, lprefix1_expr)) {
                flags = add_flags(lptable1[idx],flags)
                lptable1[idx] = prepare_item(flags,attrs)
                variant = "INAT_VARIANT"
            } 
            else if (match(ext, lprefix2_expr)) {
                flags = add_flags(lptable2[idx],flags)
                lptable2[idx] = prepare_item(flags,attrs)
                variant = "INAT_VARIANT"
            } 
            else if (match(ext, lprefix3_expr)) {
                flags = add_flags(lptable3[idx],flags)
                lptable3[idx] = prepare_item(flags,attrs)
                variant = "INAT_VARIANT"
            } 
            else {
                if (length(flags) != 0)
                    table[idx] = add_flags(table[idx],flags)
                base_attrs = attrs
            }
        }
    }
    if (variant) {
        table[idx] = add_flags(table[idx],variant)
    }
    
    if ((idx in table) || base_attrs) {
        table[idx] = prepare_item(table[idx], base_attrs)
    }
}

END {
    if (awkchecked != "")
        exit 1
    # print escape opcode map's array
    print "/* Escape opcode map array */"
    print "const insn_attr_t const *inat_escape_tables[INAT_ESC_MAX + 1]" \
          "[INAT_LSTPFX_MAX + 1] = {"
    for (i = 0; i < geid; i++)
        for (j = 0; j < max_lprefix; j++)
            if (etable[i,j])
                print " ["i"]["j"] = "etable[i,j]","
    print "};\n"
    # print group opcode map's array
    print "/* Group opcode map array */"
    print "const insn_attr_t const *inat_group_tables[INAT_GRP_MAX + 1]"\
          "[INAT_LSTPFX_MAX + 1] = {"
    for (i = 0; i < ggid; i++)
        for (j = 0; j < max_lprefix; j++)
            if (gtable[i,j])
                print " ["i"]["j"] = "gtable[i,j]","
    print "};\n"
    # print AVX opcode map's array
    print "/* AVX opcode map array */"
    print "const insn_attr_t const *inat_avx_tables[X86_VEX_M_MAX + 1]"\
          "[INAT_LSTPFX_MAX + 1] = {"
    for (i = 0; i < gaid; i++)
        for (j = 0; j < max_lprefix; j++)
            if (atable[i,j])
                print " ["i"]["j"] = "atable[i,j]","
    print "};"
}

