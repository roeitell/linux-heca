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

static int unmap_remote_page(struct page *page, unsigned long addr, struct dsm_vm_id *id) {
    int r = 0;
    spinlock_t *ptl;
    pte_t *pte;
    struct mm_struct *mm = current->mm;

    /* DSM1 : temp code test kernel mem swap **********/
    dst_addr = 0;

    kpage = alloc_page(GFP_KERNEL);
    if (!kpage)
        return -1;

    get_page(kpage);

    // DSM1 : temp code
    dst_addr = (unsigned long) kmap(kpage);
    if (!dst_addr) {
        free_page((unsigned long) kpage);

        return -1;

    }
    printk("[*] dst_addr : %lu\n", dst_addr);

    memset((void *) dst_addr, 'X', PAGE_SIZE);

    printk("[*] <unmap_remote_page> req_addr : %llu\n", (unsigned long long) addr);

    printk("[*] kpage : %10.10s\n", (char *) dst_addr);
    /**********************/

    pte = page_check_address(page, mm, addr, &ptl, 0);

    if (!pte)
        return -EFAULT;

    page_remove_rmap(page);

    set_pte_at_notify(mm, addr, pte, swp_entry_to_pte(make_dsm_entry(id->dsm_id, id->vm_id)));

    if (!page_mapped(page))
        try_to_free_swap(page);

    put_page(page);

    pte_unmap_unlock(pte, ptl);

    return r;

}

int dsm_flag_remote(unsigned long addr, struct dsm_vm_id *id) {
    int r;
    struct page *page;

    r = get_user_pages_fast(addr, 1, 1, &page);

    if (r <= 0)
        goto out;

    if (!trylock_page(page))
        goto out;

    r = unmap_remote_page(page, addr, id);

    unlock_page(page);

    out: return r;

}
EXPORT_SYMBOL(dsm_flag_remote);
