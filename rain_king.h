#ifndef _RAIN_KING_H_
#define _RAIN_KING_H_

#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include <asm/pgtable.h>

#define SHELLCODE_INS_COUNT 5
#define NOP_OFFSET 0x0
#define INS_SIZE 4

void *copy_sys_call_table(void *table) {
    void *new_sys_call_table = vmalloc(sizeof(syscall_fn_t) * __NR_syscalls);
    memcpy(new_sys_call_table, table, sizeof(syscall_fn_t) * __NR_syscalls);
    return new_sys_call_table;
}

void free_new_sys_call_table(void *table) {
    vfree(table);
}



// https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/MOVK--Move-wide-with-keep-?lang=en
// movk encoding:
// 0 | 1 1 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
//------------------------------------------------------------------------
// sf|opc              |hw   |imm16                            |rd
uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd) {
    return 0xf2800000 | (imm16 << 5) | (hw << 21) | rd;
}

void assemble_absolute_load(uint32_t rd, uintptr_t addr, uint32_t *arr) {
    arr[0] = cpu_to_le32(assemble_movk(addr & 0xffff, 0b0, rd));
    arr[1] = cpu_to_le32(assemble_movk((addr & 0xffff0000) >> 16, 0b1, rd));
    arr[2] = cpu_to_le32(assemble_movk((addr & 0xffff00000000) >> 32, 0b10, rd));
    arr[3] = cpu_to_le32(assemble_movk((addr & 0xffff000000000000) >> 48, 0b11, rd));
}



static struct mm_struct *init_mm_ptr = NULL;

pte_t *page_from_virt(uintptr_t addr) {
    pr_info("debug: page_from_virt called with addr %pK\n", addr);
    if (!init_mm_ptr) {
        init_mm_ptr = kallsyms_lookup_name_("init_mm");
    }

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return NULL;
    }

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return NULL;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        return NULL;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return NULL;
    }

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep) {
        return NULL;
    }

    pr_info("debug: page_from_virt succes, virt (%pK), ptep @ %pK", addr, ptep);

    return ptep;
}

void pte_flip_write_protect(pte_t *ptep) {
    if (!pte_write(*ptep)) {
        *ptep = pte_mkwrite(pte_mkdirty(*ptep));
        *ptep = clear_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));
        pr_info("debug: pte_flip_write_protect flipped ptep @ %pK, pte_write(%i)\n", ptep, pte_write(*ptep));
        return;
    }
    *ptep = pte_wrprotect(*ptep);
    *ptep = set_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));
    pr_info("debug: pte_flip_write_protect ptep @ %pK, pte_write(%i)\n", ptep, pte_write(*ptep));
}



typedef uintptr_t (*kallsyms_lookup_name_t)(const char *symbol_name);
static kallsyms_lookup_name_t kallsyms_lookup_name__ = NULL;

uintptr_t kprobe_get_func_addr(const char *func_name) {
    static struct kprobe kp;
    kp.symbol_name = func_name;
    if (register_kprobe(&kp) < 0) {
        pr_info("debug: kprobe_get_func_addr of %s failed\n", func_name);
        return -ENOENT;
    }
    uintptr_t tmp = kp.addr;
    unregister_kprobe(&kp);
    pr_info("debug: kprobe_get_func_addr %s @ %pK\n", func_name, tmp);
    return tmp;
}

uintptr_t kallsyms_lookup_name_(const char *symbol_name) {
    if (!kallsyms_lookup_name__) {
        kallsyms_lookup_name__ = kprobe_get_func_addr("kallsyms_lookup_name");
    }
    uintptr_t tmp = kallsyms_lookup_name__(symbol_name);
    pr_info("debug: kallsyms_lookup_name_ %s @ %pK\n", symbol_name, tmp);
    return tmp;
}




static void __attribute__((used)) *new_sys_call_table_ptr;
static void __attribute__((used)) *hooked_syscall_number;
static void __attribute__((used)) *el0_svc_common_ptr;
static void __attribute__((used)) *el0_svc_common_hook_ptr;

struct ehh_hook {
    int number;

    void *new_fn;
    void *orig_fn;
};

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

    asm volatile("do_not_redirect_table:")
    asm volatile("ldr x12, =el0_svc_common_ptr");
    asm volatile("ldr x12, [x12]");

    // MODIFY THIS MANUALLY WHEN SHELLCODE_INS_COUNT IS CHANGED
    asm volatile("add x12, x12, #0x14"); // SHELLCODE_INS_COUNT * INS_SIZE + NOP_OFFSET
    asm volatile("br x12");

    asm volatile("redirect_table:")
    asm volatile("ldr x12, =new_sys_call_table_ptr");
    asm volatile("ldr x12, [x12]");
    asm volatile("mov x3, x12");
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
    void **orig_table = kallsyms_lookup_name_("sys_call_table");
    void **new_table = copy_sys_call_table(orig_table);
    pr_info("debug: orig_table %i -> %pK, new_table %i -> %pK\n", __NR_mkdirat,
            ((void **) orig_table)[__NR_mkdirat], __NR_mkdirat,
            ((void **) new_table)[__NR_mkdirat]);
    *((uintptr_t *) hook->orig_fn) = orig_table[hook->number];

    new_sys_call_table_ptr = new_table;
    el0_svc_common_hook_ptr = &el0_svc_common_hook;
    pr_info("debug: el0_svc_common_hook_ptr @ %pK\n", el0_svc_common_hook_ptr);
    el0_svc_common_ptr = kallsyms_lookup_name_("el0_svc_common.constprop.0");

    pte_flip_write_protect(page_from_virt(el0_svc_common_hook_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    flush_tlb_all();

    stop_machine(copy_shellcode_sync, NULL, NULL);

    new_table[hook->number] = hook->new_fn;
}

#endif
