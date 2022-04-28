#include "set_page_flags.h"

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
