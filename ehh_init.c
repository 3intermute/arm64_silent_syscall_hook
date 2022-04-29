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

static asmlinkage int (*orig_kill) (const struct pt_regs *);

asmlinkage int new_kill(const struct pt_regs *regs) {
    pr_info("debug: hooked kill :D, pid (%i), sig (%i)\n", regs->regs[0], regs->regs[1]);
    return orig_kill(regs);
}

static int __init hook_test_mod_init(void) {
    struct ehh_hook hook = {__NR_kill, new_kill, &orig_kill};
    hook_el0_svc_common(&hook);

    pr_info("debug: module loaded\n");
    return 0;
}

static void __exit hook_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
