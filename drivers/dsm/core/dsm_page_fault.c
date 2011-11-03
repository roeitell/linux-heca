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
#include <dsm/dsm_sr.h>
#include <linux/mmu_notifier.h>

void signal_completion_page_request(struct tx_buf_ele * tx_e,
                unsigned long data) {
        struct page_request_completion *pr_comp =
                        (struct page_request_completion *) data;
        page_pool_ele * ppe = tx_e->wrk_req->dst_addr;
        pr_comp->page = ppe->mem_page;
        ppe->mem_page = NULL;
        errk("[signal_completion_page_request] Received page at %p \n",
                        pr_comp->page);
        complete(&pr_comp->comp);

}

static int request_page_insert(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd,
                unsigned int flags) {

        struct dsm_vm_id id;
        struct subvirtual_machine *svm;
        struct subvirtual_machine *fault_svm;
        //we need to use the page addr and not the fault address in order to have a unique reference
        unsigned long norm_addr = addr & PAGE_MASK;
        spinlock_t *ptl;
        int ret = VM_FAULT_ERROR;
        struct page *page = NULL;

        errk("[?] fault\n");

        pte = pte_offset_map_lock(mm, pmd, norm_addr, &ptl);
        BUG_ON(!pte);

        if (pte_present(*pte)) {
                ret = VM_FAULT_MAJOR;
                goto out;
        }

        //DSM1 we need to test if its a swap or other if yes we do vm faul retry
        if (!is_dsm_entry(*entry)) {
                return VM_FAULT_RETRY;
        }

        dsm_entry_to_val(*entry, &id.dsm_id, &id.svm_id);

        errk("[request_page_insert] dsm_id : %d .. svm_id : %d\n", id.dsm_id,
                        id.svm_id);

        svm = funcs->_find_svm(&id);
        BUG_ON(!svm);

        fault_svm = funcs->_find_local_svm(svm->id.dsm_id, mm);

        BUG_ON(!fault_svm);

        if (svm->priv) {
                page = dsm_extract_page(
                                fault_svm->id,
                                svm,
                                norm_addr + svm->priv->offset
                                                - fault_svm->priv->offset);

                if (page == (void *) -EFAULT
                )
                        return VM_FAULT_ERROR;
        } else {
                //DSM1  : we request the rdma page HERE!!
                //page remote so we send message
                struct page_request_completion pr_comp;
                init_completion(&pr_comp.comp);
                errk(
                                "[request_page_insert] request page addr %p , norm addr %p from [dsm %d /svm %d]\n",
                                norm_addr,
                                (uint64_t)(norm_addr - fault_svm->priv->offset),
                                fault_svm->id.dsm_id, fault_svm->id.svm_id);
                funcs->request_dsm_page(svm->ele, fault_svm->id, svm->id,
                                (uint64_t)(norm_addr - fault_svm->priv->offset),
                                signal_completion_page_request,
                                (unsigned long) &pr_comp);
                wait_for_completion_interruptible(&pr_comp.comp);
                page = pr_comp.page;

        }

        if (page) {
                ret = dsm_insert_page(mm, vma, pte, norm_addr, page, &id);
        } else {
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
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long addr, pte_t *pte, swp_entry_t *entry, pmd_t *pmd,
                unsigned int flags) {
        return 0;
}
#endif /* CONFIG_DSM */

/*
 * Received a page via dsm_rdma. The kernel buffer containing the page will be consumed,
 * the PTE will be nullified and the PTE of the faulting page (which initiated the request)
 * will be set to the received page.
 *
 */
int dsm_insert_page(struct mm_struct *mm, struct vm_area_struct *vma,
                pte_t *pte, unsigned long addr_fault, struct page * recv_page,
                struct dsm_vm_id *id) {
        int ret = VM_FAULT_ERROR;
        struct mem_cgroup *mem_cg;

        // DSM3: this may be totally unnecessary.
        int charge_swap = 0;

        if (!recv_page)
                goto out;

        if (!trylock_page(recv_page))
                goto out;

//    if (!(page_mapped(recv_page) || (recv_page->mapping && !PageAnon(recv_page))))
//    {
//        errk("[!] mem_cgroup_newpage_charge\n");
//        mem_cgroup_newpage_charge(recv_page, mm, GFP_KERNEL);
//    }
//    else
//    {   // I think this will always be called - though just to be sure...
//        if (mem_cgroup_try_charge_swapin(mm, recv_page, GFP_KERNEL, &mem_cg))
//        {
//            ret = VM_FAULT_OOM;
//            goto out;
//        }
//
//        charge_swap = 1;
//    }

        // Address of page fault - points to received page.
        set_pte_at_notify(mm, addr_fault, pte,
                        mk_pte(recv_page, vma->vm_page_prot));

        page_add_anon_rmap(recv_page, vma, addr_fault);

        //if (charge_swap)
        //    mem_cgroup_commit_charge_swapin(recv_page, mem_cg);

        inc_mm_counter(mm, MM_ANONPAGES);

        update_mmu_cache(vma, addr_fault, pte);
//FUNCS
//        if (funcs->_page_local(addr_fault, id, mm)) {
//                printk("[dsm_insert_page] page_local\n");
//                // Set recv_page flags
//                //recv_page->mapping = (void *) PAGE_MAPPING_DSM;
//
//                funcs->_red_page_insert(page_to_pfn(recv_page), id, addr_fault);
//
//                printk("[dsm_insert_page] page inserted into tree\n");
//        }

        unlock_page(recv_page);
        ret = VM_FAULT_MAJOR;
        out:

        return ret;
}
EXPORT_SYMBOL(dsm_insert_page);
