/*
 * dsm_unmap.c
 *
 *  Created on: 1 Aug 2011
 *      Author: john
 */

#include <asm-generic/memory_model.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include "../../../mm/internal.h"
#include <linux/page-flags.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/rmap.h>

#include <linux/mmu_notifier.h>

#include <dsm/dsm_core.h>

struct dsm_functions *funcs;
struct page *kpage;

void reg_dsm_functions(struct route_element *(*_find_routing_element)(struct dsm_vm_id *), void(*_erase_rb_swap)(struct rb_root *, struct swp_element *), int(*_insert_rb_swap)(struct rb_root *, unsigned long), int(*_page_blue)(unsigned long, struct dsm_vm_id *), struct swp_element* (*_search_rb_swap)(struct rb_root *, unsigned long)) {
    printk("[register_dsm_functions] plugin func ptrs\n");

    funcs = kmalloc(sizeof(*funcs), GFP_KERNEL);

    funcs->_find_routing_element = _find_routing_element;
    funcs->_erase_rb_swap = _erase_rb_swap;
    funcs->_insert_rb_swap = _insert_rb_swap;
    funcs->_page_blue = _page_blue;
    funcs->_search_rb_swap = _search_rb_swap;

}
EXPORT_SYMBOL(reg_dsm_functions);

void dereg_dsm_functions(void) {
    kfree(funcs);

}
EXPORT_SYMBOL(dereg_dsm_functions);

int dsm_flag_page_remote(struct mm_struct *mm, struct dsm_vm_id id, unsigned long addr) {
    spinlock_t *ptl;
    pte_t *pte;
    int r = 0;
    struct page *page;
    struct vm_area_struct *vma;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    struct rb_root *swp_root;
    struct route_element *route_e;
    struct swp_element *ele;
    swp_entry_t swp_e;

    down_read(&mm->mmap_sem);

    retry:

    vma = find_vma(mm, addr);
    if (!vma || vma->vm_start > addr)
        goto out;

    page = follow_page(vma, addr, FOLL_GET);
    if (!page) {

        printk("\n[*] No page FOUND \n");
        pgd = pgd_offset(mm, addr);
        if (!pgd_present(*pgd))
            goto out;

        pud = pud_offset(pgd, addr);
        if (!pud_present(*pud))
            goto out;

        pmd = pmd_offset(pud, addr);
        BUG_ON(pmd_trans_huge(*pmd));
        if (!pmd_present(*pmd))
            goto out;

        // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock
        route_e = funcs->_find_routing_element(&id);
        BUG_ON(!route_e);

        pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
        pte_entry = *pte;

        if (!pte_present(pte_entry)) {
            if (pte_none(pte_entry)) {
                printk("[*] Directly inserting PTE  because no page exist \n");
                set_pte_at(mm, addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));
                goto out_pte_unlock;
            } else {
                swp_e = pte_to_swp_entry(pte_entry);
                if (non_swap_entry(swp_e)) {
                    if (is_migration_entry(swp_e)) {
                        pte_unmap_unlock(pte, ptl);
                        migration_entry_wait(mm, pmd, addr);
                        goto retry;
                    } else {
                        BUG();
                    }
                } else {
                    chain_fault: printk("[*] mm  faulting because swap\n");
                    pte_unmap_unlock(pte, ptl);
                    r = handle_mm_fault(mm, vma, addr, FAULT_FLAG_WRITE);
                    if (r & VM_FAULT_ERROR) {
                        printk("[*] failed at faulting \n");
                        BUG();
                    }
                    printk("[*] faulting success \n");
                    r = 0;

                    goto retry;

                }

            }

        } else {
            printk("[*] bad pte \n");
            BUG();
        }

    }

    pte = page_check_address(page, mm, addr, &ptl, 0);
    if (!pte) {
        // we can have a double request .. so we just retry
        goto retry;
    }
    if (!trylock_page(page)) {

        r = -EFAULT;
        goto out_pte_unlock;
    }

    printk("[*] page addresse: %p \n", (unsigned long) page_address_in_vma(page, vma));
    printk("[*] insert_swp_ele->addr : %p \n", (unsigned long) addr);

    flush_cache_page(vma, addr, pte_pfn(*pte));

    ptep_clear_flush_notify(vma, addr, pte);
    set_pte_at(mm, addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));
    page_remove_rmap(page);

    dec_mm_counter(mm, MM_ANONPAGES);
    // this is a page flagging without data exchange so we can free the page
    if (!page_mapped(page))
        try_to_free_swap(page);
    put_page(page);
    unlock_page(page);
    out_pte_unlock: pte_unmap_unlock(pte, ptl);
    out: up_read(&mm->mmap_sem);

    return r;

}
EXPORT_SYMBOL(dsm_flag_page_remote);

