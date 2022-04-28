#ifndef _HOOK_H_
#define _HOOK_H_

#define SHELLCODE_INS_COUNT 6
#define NOP_OFFSET 0x10 // 0x24 nop address

#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"

static void  *new_sys_call_table_ptr;
static void  *el0_svc_common_ptr;
static void  *el0_svc_common_hook_ptr;

struct ehh_hook {
    int number;

    void *new_table;
    void *orig_table;

    void *new_fn;
    void *orig_fn;
};

extern void hook_el0_svc_common(struct ehh_hook *hook);

#endif
