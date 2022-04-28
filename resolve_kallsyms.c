#include "resolve_kallsyms.h"

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
