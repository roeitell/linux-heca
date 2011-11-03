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

#include <linux/ksm.h>
#include <asm-generic/mman-common.h>

struct page *dsm_extract_page(struct dsm_vm_id id,
                struct subvirtual_machine *svm, unsigned long norm_addr) {
        spinlock_t *ptl;
        pte_t *pte;
        int r = 0;
        struct page *page = NULL;
        struct vm_area_struct *vma;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t pte_entry;
        struct mm_struct *mm;
        swp_entry_t swp_e;
        unsigned long ksm_flag;
        struct red_page *rp = NULL;

        mm = svm->priv->mm;
        // if local
        down_read(&mm->mmap_sem);

        errk(
                        "[dsm_extract_page] new DSM_SWP_ENTRY set to - dsm_id : %d, svm_id : %d",
                        id.dsm_id, id.svm_id);
        retry:

        vma = find_vma(mm, norm_addr);
        if (!vma || vma->vm_start > norm_addr)
                goto out;

        ksm_flag = vma->vm_flags & VM_MERGEABLE;

        pgd = pgd_offset(mm, norm_addr);
        if (!pgd_present(*pgd))
                goto out;

        pud = pud_offset(pgd, norm_addr);
        if (!pud_present(*pud))
                goto out;

        pmd = pmd_offset(pud, norm_addr);
        BUG_ON(pmd_trans_huge(*pmd));
        if (!pmd_present(*pmd))
                goto out;

        // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock

        pte = pte_offset_map_lock(mm, pmd, norm_addr, &ptl);
        pte_entry = *pte;

        if (!pte_present(pte_entry)) {
                if (pte_none(pte_entry)) {
                        set_pte_at(
                                        mm,
                                        norm_addr,
                                        pte,
                                        swp_entry_to_pte(
                                                        make_dsm_entry(
                                                                        (uint16_t) id.dsm_id,
                                                                        (uint8_t) id.svm_id)));
                        //DSM1 note we might do a empty send in order to save bandwidth
                        //send
                        goto out_pte;

                } else {
                        swp_e = pte_to_swp_entry(pte_entry);
                        if (non_swap_entry(swp_e)) {
                                if (is_dsm_entry(swp_e)) {
                                        // we forward the request but here we just chain fault
                                        // forward page red or blue
                                        //forward_blue_page(msg, ele);
                                        //goto out_pte;
                                        errk(
                                                        "[[EXTRACT_PAGE]] we chain fault on dsm entry \n");
                                        goto chain_fault;
                                } else if (is_migration_entry(swp_e)) {
                                        pte_unmap_unlock(pte, ptl);

                                        migration_entry_wait(mm, pmd,
                                                        norm_addr);
                                        goto retry;
                                } else {
                                        BUG();
                                }
                        } else {
                                chain_fault:
                                errk(
                                                "[[EXTRACT_PAGE]] mm  faulting because swap\n");
                                pte_unmap_unlock(pte, ptl);

                                r = handle_mm_fault(mm, vma, norm_addr,
                                                FAULT_FLAG_WRITE);
                                if (r & VM_FAULT_ERROR) {
                                        errk("[*] failed at faulting \n");
                                        BUG();
                                }
                                errk("[EXTRACT_PAGE] faulting success \n");
                                r = 0;
                                goto retry;
                        }
                }
        } else {
                page = vm_normal_page(vma, norm_addr, *pte);
                if (!page) {
                        // DSM3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf
                        if (pte_pfn(*pte) == (void *) ZERO_PAGE(0))
                                goto bad_page;

                        page = pte_page(*pte);
                }
        }

        if (PageKsm(page)) {
                errk("[dsm_extract_page] KSM page\n");

                r = ksm_madvise(vma, norm_addr, norm_addr, MADV_UNMERGEABLE,
                                &ksm_flag);

                if (r) {
                        printk("[dsm_extract_page] ksm_madvise ret : %d\n", r);

                        // DSM1 : better ksm error handling required.
                        return (void *) -EFAULT;
                }
        }

        if (!trylock_page(page)) {
                errk("[[EXTRACT_PAGE]] cannot lock page\n");
                r = -EFAULT;
                goto out_pte;
        }

        flush_cache_page(vma, norm_addr, pte_pfn(*pte));
        ptep_clear_flush_notify(vma, norm_addr, pte);
        set_pte_at(
                        mm,
                        norm_addr,
                        pte,
                        swp_entry_to_pte(
                                        make_dsm_entry((uint16_t) id.dsm_id,
                                                        (uint8_t) id.svm_id)));

        // Remove page from red_page_tree if contained
//FUNCS
//        rp = funcs->_red_page_search(page_to_pfn(page));
//        if (rp)
//                funcs->_red_page_erase(rp);

        page_remove_rmap(page);

        dec_mm_counter(mm, MM_ANONPAGES);
        // this is a page flagging without data exchange so we can free the page
        if (!page_mapped(page))
                try_to_free_swap(page);
        //DSM1 do we need a put_page???/
        unlock_page(page);
        isolate_lru_page(page);
        if (PageActive(page)) {
                ClearPageActive(page);
        }
        out_pte:

        pte_unmap_unlock(pte, ptl);
        // if local
        up_read(&mm->mmap_sem);
        out:

        return page;

        bad_page: pte_unmap_unlock(pte, ptl);
        return (void *) -EFAULT;

}
EXPORT_SYMBOL(dsm_extract_page);

struct page *dsm_extract_page_from_remote(dsm_message *msg) {
        struct dsm_vm_id remote_id;
        struct dsm_vm_id local_id;
        struct subvirtual_machine *local_svm;
        struct page *page = NULL;
        unsigned long norm_addr;
        if (!msg) {
                errk("[dsm_extract_page_from_remote] no message ! %p  \n", msg);
                return NULL;
        }
        remote_id.dsm_id = u32_to_dsm_id(msg->dest);
        remote_id.svm_id = u32_to_vm_id(msg->dest);

        local_id.dsm_id = u32_to_dsm_id(msg->src);
        local_id.svm_id = u32_to_vm_id(msg->src);
        local_svm = funcs->_find_svm(&local_id);
        if (unlikely(!local_svm)) {
                errk(
                                "[dsm_extract_page_from_remote] coudln't find local_svm id:  [dsm %d / svm %d]  \n",
                                local_id.dsm_id, local_id.svm_id);
                return NULL;
        }

        norm_addr = msg->req_addr + local_svm->priv->offset;

        errk(
                        "[dsm_extract_page_from_remote] local  [dsm %d / svm %d] , remote [dsm %d / svm %d] , address %p , norm address %p   \n",
                        local_id.dsm_id, local_id.svm_id, remote_id.dsm_id,
                        remote_id.svm_id, msg->req_addr, norm_addr);
        errk("[dsm_extract_page_from_remote] offset %p , mm %p \n",
                        local_svm->priv->offset, local_svm->priv->mm);

        page = dsm_extract_page(remote_id, local_svm, norm_addr);

        return page;
}
EXPORT_SYMBOL(dsm_extract_page_from_remote);

/*
 * Local node A sends a blue page to node B, the dsm_swp_entry on node A points to B.  Node C requests the page from Node A,
 * Node A forwards the request to Node B, which sends the page to Node C and sets the dsm_swp_entry to Node C.
 *
 * When Node D requests the page from Node A, the request needs to be passed along the whole chain until hitting Node C, which can
 * process the request and send the page.
 *
 * This function will allow the updating of PTE values along the chain.  Node C will send the update command to
 * Node A, it will update the dsm_swap_entry to point to Node C, then forward the command to each Node along the chain.
 *
 * Node D then requests the page from Node A, the request is now passed straight to Node C.  It is asynchronous, if Node A is not
 * updated on time, the next Node can still pass the request along fine - either to the next node or directly to the final.
 *
 */
int dsm_update_pte_entry(dsm_message *msg) // DSM1 - update all code
{
        spinlock_t *ptl;
        pte_t *pte;
        int r = 0;
        struct vm_area_struct *vma;
        struct dsm_vm_id id;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t pte_entry;
        struct subvirtual_machine *svm;
        swp_entry_t swp_e;
        struct mm_struct *mm;

        id.dsm_id = u32_to_dsm_id(msg->dest);
        id.svm_id = u32_to_vm_id(msg->dest);

        svm = funcs->_find_svm(&id);
        BUG_ON(!svm);
        mm = svm->priv->mm;
        down_read(&mm->mmap_sem);
        retry:

        vma = find_vma(mm, msg->req_addr);
        if (!vma || vma->vm_start > msg->req_addr)
                goto out;

        errk("\n[*] No page FOUND \n");
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
                        set_pte_at(
                                        mm,
                                        msg->req_addr,
                                        pte,
                                        swp_entry_to_pte(
                                                        make_dsm_entry(
                                                                        (uint16_t) id.dsm_id,
                                                                        (uint8_t) id.svm_id)));
                } else {
                        swp_e = pte_to_swp_entry(pte_entry);
                        if (!non_swap_entry(swp_e)) {
                                if (is_dsm_entry(swp_e)) {
                                        // store old dest
                                        struct dsm_vm_id old;

                                        dsm_entry_to_val(
                                                        pte_to_swp_entry(
                                                                        pte_entry),
                                                        &old.dsm_id,
                                                        &old.svm_id);

                                        if (old.dsm_id != id.dsm_id
                                                        && old.svm_id
                                                                        != id.svm_id) {
                                                // update pte
                                                set_pte_at(
                                                                mm,
                                                                msg->req_addr,
                                                                pte,
                                                                swp_entry_to_pte(
                                                                                make_dsm_entry(
                                                                                                (uint16_t) id.dsm_id,
                                                                                                (uint8_t) id.svm_id)));

                                                // forward msg
                                                // DSM1: fwd message RDMA function call.
                                                // old.dsm_id, old.svm_id.
                                        }
                                } else if (is_migration_entry(swp_e)) {
                                        pte_unmap_unlock(pte, ptl);

                                        migration_entry_wait(mm, pmd,
                                                        msg->req_addr);

                                        goto retry;
                                } else {
                                        errk(
                                                        "[*] SWP_ENTRY - not dsm or migration.\n");
                                        BUG();
                                }
                        } else {
                                errk("[*] in swap no need to update\n");
                        }
                }
        }

        pte_unmap_unlock(pte, ptl);

        out:

        up_read(&mm->mmap_sem);

        return r;

}
EXPORT_SYMBOL(dsm_update_pte_entry);

