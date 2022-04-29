#include "hook.h"
#include "assembler.h"

void __attribute__((naked)) el0_svc_common_hook(void) {
    // stack initialization, 5 instructions exactly will be overwritten, nops just to be safe
    asm volatile("nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t");
    asm volatile("mov x12, #0");

    asm volatile("ldr x12, =hooked_syscall_number");
    asm volatile("ldr x12, [x12]");
    asm volatile("cmp x0, x12");
    asm volatile("beq redirect_table");

    asm volatile("ldr x12, =el0_svc_common_ptr");
    asm volatile("ldr x12, [x12]");

    // MODIFY THIS MANUALLY WHEN SHELLCODE_INS_COUNT IS CHANGED
    asm volatile("add x12, x12, #0x14"); // SHELLCODE_INS_COUNT * INS_SIZE + NOP_OFFSET
    asm volatile("br x12");
}

void __attribute__((naked)) redirect_table(void) {
    asm volatile("ldr x12, =new_sys_call_table_ptr");
    asm volatile("ldr x12, [x12]");
    asm volatile("mov x3, x12");
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
    orig_table = kallsyms_lookup_name_("sys_call_table");
    new_table = copy_sys_call_table(hook.orig_table);
    pr_info("debug: orig_table %i -> %pK, new_table %i -> %pK\n", __NR_mkdirat,
            ((void **) hook.orig_table)[__NR_mkdirat], __NR_mkdirat,
            ((void **) hook.new_table)[__NR_mkdirat]);
    hook->orig_fn = orig_table[hook->number];

    new_sys_call_table_ptr = new_table;
    el0_svc_common_hook_ptr = &el0_svc_common_hook;
    pr_info("debug: el0_svc_common_hook_ptr @ %pK\n", el0_svc_common_hook_ptr);
    el0_svc_common_ptr = kallsyms_lookup_name_("el0_svc_common.constprop.0");

    pte_flip_write_protect(page_from_virt(el0_svc_common_hook_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    flush_tlb_all();

    stop_machine(copy_shellcode_sync, NULL, NULL);

    new_sys_call_table_ptr[hook->number] = hook->new_fn;
}
