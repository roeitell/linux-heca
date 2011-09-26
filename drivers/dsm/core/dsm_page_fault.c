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


static int request_page_insert(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd, unsigned int flags)
{
    dsm_message msg;
    struct dsm_vm_id id;
    struct subvirtual_machine *svm;
    struct subvirtual_machine *fault_svm;
    //we need to use the page addr and not the fault address in order to have a unique reference
    unsigned long norm_addr = addr & PAGE_MASK;
    spinlock_t *ptl;
    int ret = VM_FAULT_ERROR;
    struct page *page = NULL;

    pte = pte_offset_map_lock(mm, pmd, norm_addr, &ptl);
    BUG_ON(!pte);

    if (pte_present(*pte))
    {
        ret = VM_FAULT_MAJOR;
        goto out;
    }

    //DSM1 we need to test if its a swap or other if yes we do vm faul retry
    if (!is_dsm_entry(*entry))
    {
        return VM_FAULT_RETRY;

    }

    dsm_entry_to_val(*entry, &id.dsm_id, &id.svm_id);

    printk("[request_page_insert] dsm_id : %d .. svm_id : %d\n", id.dsm_id, id.svm_id);

    svm = funcs->_find_svm(&id);
    BUG_ON(!svm);

    fault_svm = funcs->_find_local_svm(svm->id.dsm_id, mm);

    BUG_ON(!fault_svm);

    if (svm->priv)
    {
        page = dsm_extract_page(fault_svm->id, svm, norm_addr + svm->priv->offset - fault_svm->priv->offset);

    }
    else
    {
        //DSM1  : we request the rdma page HERE!!
        //page remote so we send message

        msg.req_addr = (uint64_t) norm_addr - fault_svm->priv->offset;

        msg.dst_addr = (uint64_t) dst_addr;

    }

    if (page)
    {
        ret = dsm_insert_page(mm, vma, pte, norm_addr, page, &id, fault_svm);
    }
    else
    {
        ret = VM_FAULT_ERROR;
    }

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
int dsm_insert_page(struct mm_struct *mm, struct vm_area_struct *vma, pte_t *pte,
					unsigned long addr_fault, struct page * recv_page,
					struct dsm_vm_id *id, struct subvirtual_machine *svm)
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
