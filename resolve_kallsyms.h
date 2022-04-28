#ifndef _RESOLV_KALLSYMS_H_
#define _RESOLV_KALLSYMS_H_

#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/unistd.h>

typedef uintptr_t (*kallsyms_lookup_name_t)(const char *symbol_name);
static kallsyms_lookup_name_t kallsyms_lookup_name__ = NULL;

extern uintptr_t kprobe_get_func_addr(const char *func_name);
extern uintptr_t kallsyms_lookup_name_(const char *symbol_name);

#endif
