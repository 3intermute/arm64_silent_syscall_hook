#ifndef _COPY_SYS_CALL_TABLE_H_
#define _COPY_SYS_CALL_TABLE_H_

#include <linux/vmalloc.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include "set_page_flags.h"

extern void *copy_sys_call_table(void *table);
extern void free_new_sys_call_table(void *table);

#endif
