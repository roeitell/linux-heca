/*
 * page_fault.c
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

/*
 * Blue Page:
 * 		We get a page fault on a blue page when it has been swapped out, and therefore there
 * 		is a swp_element representing it in the swp_tree.
 *
 * 	Red Page:
 * 		Red pages are unmapped on VM start.
 */
static int request_page_insert(struct mm_struct *mm, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags) {
    struct rb_root *swp_root;
    struct swp_element *swp_ele;
    dsm_message msg;
    struct dsm_vm_id id;
    struct route_element *route_e;
    //we need to use the page addr and not the fault address in order to have a unique reference
    unsigned long norm_addr = addr & PAGE_MASK;

    dsm_entry_to_val(*entry, &id.dsm_id, &id.vm_id);

    printk("[*] <request_page_insert> \n");

    route_e = funcs->_find_routing_element(&id);
    BUG_ON(!route_e);
    spin_lock(&route_e->data->root_swap_lock);
    swp_root = &route_e->data->root_swap;

    swp_ele = funcs->_search_rb_swap(swp_root, norm_addr);

    retry:

    if (funcs->_page_blue(norm_addr, &id)) {
        printk("[*] <request_page_insert> blue page \n");

        /* If blue page not in swp_tree - means the page is now local */
        //if (!swp_ele)
        if (!swp_ele->addr) {
            printk("[*] <request_page_insert> return vm_fault_major blue\n");
            goto vmfault;
        } else {
            swp_ele->pmd = pmd;

            /* If blue page in swp_tree but already requested - ignore and loop */
            if (swp_ele->flags == 1) // DSM1: create flags lol - 1 = IN
                goto retry;
        }

    } else {
        printk("[*] <request_page_insert> red page \n");

        /* If red page is in swp_tree - then we have requested it.  If not received - ignore and loop */
        if (swp_ele) {
            if (swp_ele->flags == 1) // DSM1: create flags - 1 = IN
                    {
                printk("[*] <request_page_insert> return vm_fault_major red\n");
                goto vmfault;
            } else
                goto retry;

        } else {
            printk("[*] <request_page_insert> insert red\n");

            funcs->_insert_rb_swap(swp_root, norm_addr);

            /* DSM3: Maybe avoid having to do this twice - another insert_rb_swap with pmd as param.*/
            swp_ele = funcs->_search_rb_swap(swp_root, norm_addr);

            swp_ele->pmd = pmd;

        }

    }
    spin_unlock(&route_e->data->root_swap_lock);
    //DSM1  : we request teh rdma page HERE!!
    printk("[*] <request_page_insert> hi\n");

    msg.req_addr = (uint64_t) norm_addr;

    msg.dst_addr = (uint64_t) dst_addr;

    printk("[*] <request_page_insert> before page insert\n");

    return dsm_insert_page(mm, &msg, &id);

    vmfault: spin_unlock(&route_e->data->root_swap_lock);
    return VM_FAULT_MAJOR;
}

#ifdef CONFIG_DSM_CORE
int dsm_swap_wrapper(struct mm_struct *mm, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
    return request_page_insert(mm, addr, pte, entry, pmd, flags);

}
#else
int dsm_swap_wrapper(struct mm_struct *mm, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags) {
    return 0;

}

#endif /* CONFIG_DSM */

/*
 * Received a page via dsm_rdma. The kernel buffer containing the page will be consumed,
 * the PTE will be nullified and the PTE of the faulting page (which initiated the request)
 * will be set to the received page.
 *
 * Blue pages will be removed from the swp_tree.  Red pages will remain with the flags set to
 * received.
 */
int dsm_insert_page(struct mm_struct *mm, dsm_message *msg, struct dsm_vm_id *id) {
    struct page *recv_page;
    pte_t *pte;
    struct swp_element *swp_ele;
    struct rb_root *swp_root;
    unsigned long addr_fault = msg->req_addr;
    struct vm_area_struct *vma;
    spinlock_t *ptl;
    struct route_element *route_e;

    printk("[*] a \n");

    route_e = funcs->_find_routing_element(&id);
    BUG_ON(!route_e);
    spin_lock(&route_e->data->root_swap_lock);
    swp_root = &route_e->data->root_swap;

    swp_ele = funcs->_search_rb_swap(swp_root, addr_fault);
    BUG_ON(!swp_ele);

    printk("[*] b \n");

    pte = pte_offset_map_lock(mm, swp_ele->pmd, addr_fault, &ptl);
    BUG_ON(!pte);

    printk("[*] c \n");

    vma = find_vma_intersection(mm, addr_fault, addr_fault + PAGE_SIZE);
    if (!vma)
        goto out;

    printk("[*] d \n");

    recv_page = kpage;
    if (!recv_page)
        goto out;

    if (!trylock_page(recv_page))
        goto out;

    get_page(recv_page);

    // Address of page fault - points to received page.
    set_pte_at_notify(mm, addr_fault, pte, mk_pte(recv_page, vma->vm_page_prot));

    page_add_anon_rmap(recv_page, vma, addr_fault);

    inc_mm_counter(mm, MM_ANONPAGES);

    update_mmu_cache(vma, addr_fault, pte);

    put_page(kpage);

    kunmap(kpage);

    if (funcs->_page_blue(addr_fault, id)) {
        funcs->_erase_rb_swap(swp_root, swp_ele);
        printk("[*] erased swap ele\n");
    } else {
        printk("[*] remote swp_flag = 1\n");
        swp_ele->flags = 1; // DSM1 - swp_ele flags - 1 = IN/received
    }

    unlock_page(recv_page);

    out: pte_unmap_unlock(pte, ptl);
    spin_unlock(&route_e->data->root_swap_lock);
    return VM_FAULT_MAJOR;

}
EXPORT_SYMBOL(dsm_insert_page);
