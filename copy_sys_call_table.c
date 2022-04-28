#include "copy_sys_call_table.h"

void *copy_sys_call_table(void *table) {
    void *new_sys_call_table = vmalloc(sizeof(syscall_fn_t) * __NR_syscalls);
    memcpy(new_sys_call_table, table, sizeof(syscall_fn_t) * __NR_syscalls);
    return new_sys_call_table;
}

void free_new_sys_call_table(void *table) {
    vfree(table);
}
