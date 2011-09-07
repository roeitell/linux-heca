/*
 * dsm_page_request.c
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

#include <dsm/dsm_core.h>
#include <dsm/dsm_ctl.h>
#include <dsm/dsm_rb.h>

#include <linux/mmu_notifier.h>

unsigned long dst_addr;

static pte_t *dsm_page_walker(struct mm_struct *mm, unsigned long addr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep = 0;

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

    ptep = pte_offset_map(pmd, addr);

    out: return ptep;

}

static void forward_red_page(struct mm_struct *mm, dsm_message *msg) {
    pte_t *ptep;
    pte_t pte;
    swp_entry_t entry;
    struct dsm_vm_id id;

    printk("[*] forward_red_page\n");

    ptep = dsm_page_walker(mm, msg->req_addr);

    printk("[*] z\n");

    pte = *ptep;
    if (!pte_present(pte)) {
        BUG_ON(pte_none(pte));

        entry = pte_to_swp_entry(pte);

        if (is_dsm_entry(entry)) {
            dsm_entry_to_val(entry, &id.dsm_id, &id.vm_id);

            msg->dest = dsm_vm_id_to_u32(&id);

        }

    }

}

static inline void forward_blue_page(dsm_message *msg, struct swp_element *swp_ele) {
    msg->dest = dsm_vm_id_to_u32(&swp_ele->id);

}

int dsm_extract_page(dsm_message *msg) {

    spinlock_t *ptl;
    pte_t *pte;
    int r = 0;
    struct page *page;
    struct vm_area_struct *vma;
    struct dsm_vm_id id;
    swp_entry_t swp_e;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    struct rb_root *swp_root;
    struct route_element *route_e;
    struct swp_element *ele;
    struct mm_struct *mm;

    // DSM1 : temp code test kernel mem swap
    /******************************************/
    printk("[*] version 1 \n");
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

    printk("[*] dst_addr : %p\n", dst_addr);

    memset((void *) dst_addr, 'X', PAGE_SIZE);

    printk("[*] <extract_page> req_addr : %p\n", msg->req_addr);

    printk("[*] kpage : %10.10s\n", (char *) dst_addr);
    /************************************************/

    id.dsm_id = u32_to_dsm_id(msg->dest);
    id.vm_id = u32_to_vm_id(msg->dest);

    route_e = funcs->_find_routing_element(&id);
    BUG_ON(!route_e);

    mm = route_e->data->mm;
    down_read(&mm->mmap_sem);
    retry: spin_lock(&route_e->data->root_swap_lock);

    vma = find_vma(mm, msg->req_addr);
    if (!vma || vma->vm_start > msg->req_addr)
        goto out;

    page = follow_page(vma, msg->req_addr, FOLL_GET);
    if (!page) {

        printk("\n[*] No page FOUND \n");
        pgd = pgd_offset(mm, msg->req_addr);
        if (!pgd_present(*pgd))
            goto out;

        pud = pud_offset(pgd, msg->req_addr);
        if (!pud_present(*pud))
            goto out;

        pmd = pmd_offset(pud, msg->req_addr);
        BUG_ON(pmd_trans_huge(*pmd));
        if (!pmd_present(*pmd))
            goto out;

        // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock

        pte = pte_offset_map_lock(mm, pmd, msg->req_addr, &ptl);
        pte_entry = *pte;

        if (!pte_present(pte_entry)) {
            if (pte_none(pte_entry)) {
                printk("[*] Directly inserting PTE  because no page exist \n");
                set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));
                //DSM1 note we might do a empty send in order to save bandwidth
                //send
               goto out_pte;

            } else {
                swp_entry_t swp_e = pte_to_swp_entry(pte_entry);
                if (non_swap_entry(swp_e)) {
                    if (is_dsm_entry(swp_e)) {
                        swp_root = &route_e->data->root_swap;
                        ele = funcs->_search_rb_swap(swp_root, msg->req_addr);
                        if (ele) {
                            // we requested the page already .. so lets wait until we have it and then send it .. bad performance... blaaaa

                            //DSM1 we should have something like migration  wait
                            printk("[*] we spin because already requested on dsm entry \n");
                            pte_unmap_unlock(pte, ptl);
                            spin_unlock(&route_e->data->root_swap_lock);
                            goto retry;

                        } else {
                            // we forward the request but here we just chain fault
                            // forward page red or blue
                            //forward_blue_page(msg, ele);
                            //goto out_pte;
                            printk("[*] we chain fault on dsm entry \n");
                            goto chain_fault;
                        }

                    } else if (is_migration_entry(swp_e)) {
                        pte_unmap_unlock(pte, ptl);
                        spin_unlock(&route_e->data->root_swap_lock);
                        migration_entry_wait(mm, pmd, msg->req_addr);
                        goto retry;
                    } else {
                        BUG();
                    }
                } else {
                    chain_fault: printk("[*] mm  faulting because swap\n");
                    pte_unmap_unlock(pte, ptl);
                    spin_unlock(&route_e->data->root_swap_lock);
                    r = handle_mm_fault(mm, vma, msg->req_addr, FAULT_FLAG_WRITE);
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
    //we always lock the pte first then the page...
    pte = page_check_address(page, mm, msg->req_addr, &ptl, 0);
    if (!pte) {
        // we can have a double request .. so we just retry
        spin_unlock(&route_e->data->root_swap_lock);
        goto retry;
    }
    if (!trylock_page(page)) {

        r = -EFAULT;
        goto out_pte;
    }

    printk("[*] page addresse: %p \n", (unsigned long) page_address_in_vma(page, vma));
    printk("[*] insert_swp_ele->addr : %p \n", (unsigned long) msg->req_addr);

    flush_cache_page(vma, msg->req_addr, pte_pfn(*pte));

    ptep_clear_flush_notify(vma, msg->req_addr, pte);
    set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));
    page_remove_rmap(page);

    dec_mm_counter(mm, MM_ANONPAGES);

    //we send the page over here

    //DSM1: note the page might not be freed if it is on a write invalidate method

    /************* temp code the page should be freed post send ***********/
    if (!page_mapped(page))
        try_to_free_swap(page);
    put_page(page);
    /********************************************/
    unlock_page(page);
    out_pte: pte_unmap_unlock(pte, ptl);
    out: spin_unlock(&route_e->data->root_swap_lock);
    up_read(&mm->mmap_sem);

    return r;

}
EXPORT_SYMBOL(dsm_extract_page);

int dsm_update_pte_entry(dsm_message *msg) {
    spinlock_t *ptl;
    pte_t *pte;
    int r = 0;
    struct page *page;
    struct vm_area_struct *vma;
    struct dsm_vm_id id;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    struct rb_root *swp_root;
    struct route_element *route_e;
    struct swp_element *ele;
    swp_entry_t swp_e;
    struct mm_struct *mm;

    id.dsm_id = u32_to_dsm_id(msg->dest);
    id.vm_id = u32_to_vm_id(msg->dest);

    route_e = funcs->_find_routing_element(&id);
    BUG_ON(!route_e);
    mm = route_e->data->mm;
    down_read(&mm->mmap_sem);
    retry: spin_lock(&route_e->data->root_swap_lock);

    vma = find_vma(mm, msg->req_addr);
    if (!vma || vma->vm_start > msg->req_addr)
        goto out;

    page = follow_page(vma, msg->req_addr, FOLL_GET);
    if (!page) {

        printk("\n[*] No page FOUND \n");
        pgd = pgd_offset(mm, msg->req_addr);
        if (!pgd_present(*pgd))
            goto out;

        pud = pud_offset(pgd, msg->req_addr);
        if (!pud_present(*pud))
            goto out;

        pmd = pmd_offset(pud, msg->req_addr);
        BUG_ON(pmd_trans_huge(*pmd));
        if (!pmd_present(*pmd))
            goto out;

        pte = pte_offset_map_lock(mm, pmd, msg->req_addr, &ptl);
        pte_entry = *pte;

        if (!pte_present(pte_entry)) {
            if (pte_none(pte_entry)) {
                printk("[*] Directly inserting PTE  because no page exist \n");
                set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));

                goto out_pte;

            } else {
                swp_e = pte_to_swp_entry(pte_entry);
                if (non_swap_entry(swp_e)) {
                    if (is_dsm_entry(swp_e)) {
                        swp_root = &route_e->data->root_swap;
                        ele = funcs->_search_rb_swap(swp_root, msg->req_addr);
                        if (ele) {
                            // we requested the page already .. so lets wait until we have it and then send it .. bad performance... blaaaa

                            //DSM1 we should have something like migration  wait
                            printk("[*]no need to spin as we are requesting the page \n");
                            goto out_pte;

                        } else {
                            printk("[*] we forward the update before update\n");
                            //DSM1 forward update
                            printk("[*] we update the entry\n");
                            set_pte_at(mm, msg->req_addr, pte, swp_entry_to_pte(make_dsm_entry((uint16_t) id.dsm_id, (uint8_t) id.vm_id)));
                            goto out_pte;
                        }

                    } else if (is_migration_entry(swp_e)) {
                        pte_unmap_unlock(pte, ptl);
                        spin_unlock(&route_e->data->root_swap_lock);
                        migration_entry_wait(mm, pmd, msg->req_addr);
                        goto retry;
                    } else {
                        BUG();
                    }
                } else {
                    printk("[*] in swap no need to update\n");
                    goto out_pte;

                }

            }

        } else {
            printk("[*] bad pte \n");
            BUG();
        }

    }
    out_pte: pte_unmap_unlock(pte, ptl);
    out: spin_unlock(&route_e->data->root_swap_lock);
    up_read(&mm->mmap_sem);

    return r;

}
EXPORT_SYMBOL(dsm_update_pte_entry);

