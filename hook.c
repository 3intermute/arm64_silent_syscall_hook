#include "include/hook.h"

void __attribute__((naked)) el0_svc_common_hook(void) {
    // stack initialization, 5 instructions exactly will be overwritten, nops just to be safe
    // copy code at offset to ensure x22 will be saved on stack
    asm volatile("nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t");
    asm volatile("mov x12, #0");

    asm volatile("ldr x12, =hooked_syscall_number");
    asm volatile("ldr x12, [x12]");
    // load x19, x20, x21, x22 from stack
    // store x19, modify x20 (syscall number), store x21, modify x22 (sys_call_table)
    asm volatile("cmp x1, x12");
    asm volatile("beq redirect_table");

    asm volatile("do_not_redirect_table:");
    asm volatile("ldr x12, =el0_svc_common_ptr");
    asm volatile("ldr x12, [x12]");

    // MODIFY THIS MANUALLY WHEN SHELLCODE_INS_COUNT IS CHANGED
    asm volatile("add x12, x12, #0x14"); // SHELLCODE_INS_COUNT * INS_SIZE + NOP_OFFSET
    asm volatile("br x12");

    asm volatile("redirect_table:");
    asm volatile("ldr x12, =new_sys_call_table_ptr");
    asm volatile("ldr x2, [x12]");
    asm volatile("b do_not_redirect_table");
}

uint32_t *generate_shellcode(uintptr_t el0_svc_common_hook_addr) {
    uint32_t *code = vmalloc(SHELLCODE_INS_COUNT * INS_SIZE);
    code[0] = 0x0;
    code[1] = 0x0;
    code[2] = 0x0;
    code[3] = 0x0;
    // code[4] = cpu_to_le32(0xf940018c); // UNNEEDED, ADDRESS LOADED DIRECTLY, ldr x12, [x12]
    // if this still doesnt work, implement flag setting
    code[4] = cpu_to_le32(0xd61f0180); // br x12
    assemble_absolute_load(0b1100, el0_svc_common_hook_addr, code);

    return code;
}

int copy_shellcode_sync(void *arg) {
    void *shellcode = generate_shellcode(el0_svc_common_hook_ptr);
    pr_info("debug: shellcode: %*ph\n", SHELLCODE_INS_COUNT * INS_SIZE, shellcode); // not copying full shellcode ?

    memcpy(el0_svc_common_hook_ptr, (uintptr_t) el0_svc_common_ptr + NOP_OFFSET, SHELLCODE_INS_COUNT * INS_SIZE);
    pr_info("debug: copied el0_svc_common_ instructions %*ph\n", 64, el0_svc_common_hook_ptr);
    // https://docs.huihoo.com/doxygen/linux/kernel/3.7/stop__machine_8c.html
    memcpy((uintptr_t) el0_svc_common_ptr + NOP_OFFSET, shellcode, SHELLCODE_INS_COUNT * INS_SIZE);
    vfree(shellcode);
    pr_info("debug: copied shellcode instructions %*ph", 64, el0_svc_common_ptr);
    return 0;
}

void hook_el0_svc_common(struct ehh_hook *hook) {
    // void *invoke_syscall_ptr = kallsyms_lookup_name_("invoke_syscall");
    // pr_info("debug: invoke syscall dump -> %*ph\n", 64, invoke_syscall_ptr);

    void *orig_table = kallsyms_lookup_name_("sys_call_table");
    void *new_table = copy_sys_call_table(orig_table);
    pr_info("debug: orig_table %i -> %pK, new_table %i -> %pK\n", __NR_mkdirat,
            ((void **) orig_table)[__NR_mkdirat], __NR_mkdirat,
            ((void **) new_table)[__NR_mkdirat]);
    *((uintptr_t *) hook->orig_fn) = ((void **) orig_table)[hook->number];

    hooked_syscall_number = hook->number;
    new_sys_call_table_ptr = new_table;
    el0_svc_common_hook_ptr = &el0_svc_common_hook;
    pr_info("debug: el0_svc_common_hook_ptr @ %pK\n", el0_svc_common_hook_ptr);
    el0_svc_common_ptr = kallsyms_lookup_name_("el0_svc_common.constprop.0");

    pte_flip_write_protect(page_from_virt(el0_svc_common_hook_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    flush_tlb_all();

    stop_machine(copy_shellcode_sync, NULL, NULL);

    ((void **) new_table)[hook->number] = hook->new_fn;
}
