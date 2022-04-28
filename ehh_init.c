#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include "resolve_kallsyms.h"
#include "copy_sys_call_table.h"
#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_VERSION("1.0");

static int __init hook_test_mod_init(void) {
    struct ehh_hook hook;
    hook.number = __NR_mkdirat;
    hook.orig_table = kallsyms_lookup_name_("sys_call_table");
    hook.new_table = copy_sys_call_table(hook.orig_table);
    pr_info("debug: orig_table %i -> %pK, new_table %i -> %pK\n", __NR_mkdirat,
            ((void **) hook.orig_table)[__NR_mkdirat], __NR_mkdirat,
            ((void **) hook.new_table)[__NR_mkdirat]);

    hook_el0_svc_common(&hook);

    pr_info("debug: module loaded\n");
    return 0;
}

static void __exit hook_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
