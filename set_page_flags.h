#ifndef _SET_PAGE_FLAGS_H_
#define _SET_PAGE_FLAGS_H_

#include <asm/pgtable.h>
#include "resolve_kallsyms.h"

static struct mm_struct *init_mm_ptr = NULL;

extern pte_t *page_from_virt(uintptr_t addr);
extern void pte_flip_write_protect(pte_t *ptep);

#endif
