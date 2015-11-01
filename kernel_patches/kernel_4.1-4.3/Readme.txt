1.
0001-kprobes-x86-boost-Fix-checking-if-there-is-enough-ro.patch
0002-kprobes-x86-Use-16-bytes-for-each-instruction-slot-a.patch

These two allow Kprobes to make 11-byte instructions (like "MOV r/m64, imm32" (opcode 0xc7)) "boostable". That is, there will be enough room in the buffer containing the insn for a near relative jump as well.

As RaceHound needs the similar things as the "boost" facilities (enough space in the insn buffer for a jump), these patches help it too. This way it can monitor longer instructions.

In some cases (12-byte or longer instructions), it may be needed to increase KPROBE_INSN_SLOT_SIZE in arch/x86/include/asm/kprobes.h further. 20 bytes are enough but you may always choose a greater value (say, 32 as a nice round number).
