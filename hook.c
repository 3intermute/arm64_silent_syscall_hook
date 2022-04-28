#include "hook.h"
#include "assembler.h"

void el0_svc_common_hook(void) {
    // deal with stack initialization
    asm volatile("nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t");

    pr_info("debug: el0_svc_common hooked\n");
    
    asm volatile("mov x12, #0");
    asm volatile("ldr x12, =el0_svc_common_ptr");
    asm volatile("ldr x12, [x12]");
    asm volatile("add x12, x12, #0x30"); // shellcode_size + NOP_OFFSET
    asm volatile("blr x12");
}

uint32_t *generate_shellcode(uintptr_t el0_svc_common_hook_addr) {
    uint32_t *code = vmalloc(SHELLCODE_INS_COUNT * INS_SIZE);
    code[0] = 0x0;
    code[1] = 0x0;
    code[2] = 0x0;
    code[3] = 0x0;
    code[4] = cpu_to_le32(0xf940018c); // ldr x12, [x12]
    code[5] = cpu_to_le32(0xd63f0180); // blr x12
    assemble_absolute_load(0b1100, el0_svc_common_hook_addr, code);

    // code[0] = cpu_to_le32(0xd503201f); // nop

    return code;
}

int copy_shellcode_sync(void *arg) {
    void *shellcode = generate_shellcode(el0_svc_common_hook_ptr);
    pr_info("debug: shellcode: %*ph\n", SHELLCODE_INS_COUNT * INS_SIZE, shellcode); // not copying full shellcode ?

    memcpy(el0_svc_common_hook_ptr, el0_svc_common_ptr + NOP_OFFSET, SHELLCODE_INS_COUNT * INS_SIZE);
    pr_info("debug: copied el0_svc_common_ instructions %*ph\n", 64, el0_svc_common_hook_ptr);
    // https://docs.huihoo.com/doxygen/linux/kernel/3.7/stop__machine_8c.html
    memcpy((uintptr_t) el0_svc_common_ptr + NOP_OFFSET, shellcode, SHELLCODE_INS_COUNT * INS_SIZE);
    vfree(shellcode);
    pr_info("debug: copied shellcode instructions %*ph\n", 64, el0_svc_common_ptr);
    return 0;
}

void hook_el0_svc_common(struct ehh_hook *hook) {
    new_sys_call_table_ptr = hook->new_table;
    el0_svc_common_hook_ptr = &el0_svc_common_hook;
    el0_svc_common_ptr = kallsyms_lookup_name_("el0_svc_common.constprop.0");

    pte_flip_write_protect(page_from_virt(el0_svc_common_hook_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    flush_tlb_all();

    stop_machine(copy_shellcode_sync, NULL, NULL);
}
