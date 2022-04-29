
                   ,,                              ,,
                   db                  `7MM        db
                                         MM
`7Mb,od8 ,6"Yb.  `7MM  `7MMpMMMb.        MM  ,MP'`7MM  `7MMpMMMb.  .P"Ybmmm
  MM' "'8)   MM    MM    MM    MM        MM ;Y     MM    MM    MM :MI  I8
  MM     ,pm9MM    MM    MM    MM        MM;Mm     MM    MM    MM  WmmmP"
  MM    8M   MM    MM    MM    MM        MM `Mb.   MM    MM    MM 8M
.JMML.  `Moo9^Yo..JMML..JMML  JMML.    .JMML. YA..JMML..JMML  JMML.YMMMMMb
                                                                  6'     dP
                                                                  Ybmmmd' rk
----------------------------------------------------------------------------
syscall hooking on arm64 via hooking exception handler...
without ever modifying addrs in sys_call_table, syscall entries or the addr of sys_call_table

:D written by 0xwillow for rain king rk :D

---- hooking process ----
copy (el0_svc_common, length x) -> el0_svc_common_hook
copy shellcode (jmp el0_svc_common_hook, length x) -> el0_svc_common

el0_svc_common entry:
0 ---------------
check syscall #, set sys_call_table to malicious table if its a hooked syscall
load el0_svc_common_hook addr
jmp el0_svc_common_hook
x ---------------
el0_svc_common body

>>>>>>>>>>>

hooked_el0_svc_common entry:
0 ---------------
overwritten stack init code
nop
...
x ---------------
set sys_call_table to new addr
jump el0_svc_common entry + x


---- files ----
assembler.c -> just in time assembles load absolute address of el0_svc_common_hook to bypass KASLR
set_page_flags.c -> translate vaddr to pte, then flip write protect bit
hook.c -> main hooking code
copy_sys_call_table.h -> create copy of  sys_call_table
resolve_kallsyms.c -> use kprobes to find addr of kallsyms_lookup_name, then kallsyms_lookup_name to resolve unexported symbols
rain_king.h -> hooking library condensed in a single header (why lol) NOT TESTED YET
