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
static int request_page_insert(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
    dsm_message msg;
    struct dsm_vm_id id;
    struct route_element *route_e;
    struct route_element *fault_route_e;
    //we need to use the page addr and not the fault address in order to have a unique reference
    unsigned long norm_addr = addr & PAGE_MASK;
    spinlock_t *ptl;
    int ret = VM_FAULT_ERROR;
    struct page *page = NULL;
    printk("[request_page_insert] before pte lock \n");
    pte = pte_offset_map_lock(mm, pmd, norm_addr, &ptl);
    BUG_ON(!pte);

    printk("[request_page_insert]before page check \n");

    printk("[request_page_insert] a \n");
    if (pte_present(*pte))
    {
        printk("[request_page_insert] double fault , and page resolved we just return\n");
        ret = VM_FAULT_MAJOR;
        goto out;
    }

    printk("[request_page_insert] b \n");

    //DSM1 we need to test if its a swap or other if yes we do vm faul retry
    if (!is_dsm_entry(*entry))
    {
        return VM_FAULT_RETRY;

    }

    dsm_entry_to_val(*entry, &id.dsm_id, &id.vm_id);

    printk("[request_page_insert] c \n");

    printk("[request_page_insert] <request_page_insert> \n");

    route_e = funcs->_find_routing_element(&id);
    BUG_ON(!route_e);

    printk("[request_page_insert] d \n");

    fault_route_e = funcs->_find_local_routing_element(route_e, mm);
    BUG_ON(!fault_route_e);

    printk("[request_page_insert] e \n");

    if (route_e->data)
    {
        // we just call  dsm_extract -page
        printk("[request_page_insert] page local to host we just grab it \n");
        printk("[request_page_insert]  Normalised page addr : %p \n", norm_addr);
        printk("[request_page_insert] page marshal : %p \n", norm_addr - fault_route_e->data->offset);
        printk("[request_page_insert] remote page addr: %p \n", norm_addr + route_e->data->offset - fault_route_e->data->offset);

        page = dsm_extract_page(id, route_e, norm_addr + route_e->data->offset - fault_route_e->data->offset);

    }
    else
    {
        //DSM1  : we request the rdma page HERE!!
        //page  remote so we send message
        printk("[request_page_insert] request dsm page \n");

        msg.req_addr = (uint64_t) norm_addr - fault_route_e->data->offset;

        msg.dst_addr = (uint64_t) dst_addr;

        printk("[request_page_insert]  before page insert\n");
    }

    printk("[request_page_insert] f \n");

    if (page)
    {
        printk("[request_page_insert] g \n");
        ret = dsm_insert_page(mm, vma, pte, norm_addr, page, &id, fault_route_e);
    }
    else
    {
        printk("[request_page_insert] h \n");
        ret = VM_FAULT_ERROR;
    }
    printk("[request_page_insert] i \n");
    pte_unmap_unlock(pte, ptl);

out:

    return ret;

}

#ifdef CONFIG_DSM_CORE
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
    return request_page_insert(mm, vma ,addr, pte, entry, pmd, flags);

}
#else
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
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
int dsm_insert_page(struct mm_struct *mm, struct vm_area_struct *vma, pte_t *pte, unsigned long addr_fault, struct page * recv_page, struct dsm_vm_id *id, struct route_element *route_e)
{
    int ret = VM_FAULT_ERROR;

    if (!recv_page)
        goto out;

    if (!trylock_page(recv_page))
        goto out;

    // Address of page fault - points to received page.
    set_pte_at_notify(mm, addr_fault, pte, mk_pte(recv_page, vma->vm_page_prot));

    page_add_anon_rmap(recv_page, vma, addr_fault);

    inc_mm_counter(mm, MM_ANONPAGES);

    update_mmu_cache(vma, addr_fault, pte);

    unlock_page(recv_page);
    ret = VM_FAULT_MAJOR;
out:

    return ret;

}
EXPORT_SYMBOL(dsm_insert_page);
