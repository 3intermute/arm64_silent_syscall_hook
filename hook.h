#ifndef _HOOK_H_
#define _HOOK_H_

#define SHELLCODE_INS_COUNT 5
#define NOP_OFFSET 0x0 // 0x24 nop address

#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"

static void __attribute__((used)) *new_sys_call_table_ptr;
static void __attribute__((used)) *hooked_syscall_number;
static void __attribute__((used)) *el0_svc_common_ptr;
static void __attribute__((used)) *el0_svc_common_hook_ptr;

struct ehh_hook {
    int number;

    void *new_fn;
    void *orig_fn;
};

extern void hook_el0_svc_common(struct ehh_hook *hook);

#endif
