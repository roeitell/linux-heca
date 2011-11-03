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

#include <linux/ksm.h>
#include <asm-generic/mman-common.h>

struct dsm_functions *funcs;
struct page *kpage;

void reg_dsm_functions(
                struct subvirtual_machine *(*_find_svm)(struct dsm_vm_id *),
                struct subvirtual_machine *(*_find_local_svm)(u16,
                                struct mm_struct *),
                int(*request_dsm_page)(conn_element *, struct dsm_vm_id,
                                struct dsm_vm_id, uint64_t,
                                void(*func)(struct tx_buf_ele *, unsigned long),
                                unsigned long data)) {

        funcs = kmalloc(sizeof(*funcs), GFP_KERNEL);

        funcs->_find_svm = _find_svm;
        funcs->_find_local_svm = _find_local_svm;
        funcs->request_dsm_page = request_dsm_page;
}
EXPORT_SYMBOL(reg_dsm_functions);

void dereg_dsm_functions(void) {
        kfree(funcs);
}
EXPORT_SYMBOL(dereg_dsm_functions);

int dsm_flag_page_remote(struct mm_struct *mm, struct dsm_vm_id id,
                unsigned long request_addr) {
        spinlock_t *ptl;
        pte_t *pte;
        int r = 0;
        struct page *page = 0;
        struct vm_area_struct *vma;
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t pte_entry;
        swp_entry_t swp_e;
        struct subvirtual_machine *svm;
        unsigned long addr = request_addr & PAGE_MASK;
        unsigned long ksm_flag;

        down_read(&mm->mmap_sem);

        retry:

        vma = find_vma(mm, addr);
        if (!vma || vma->vm_start > addr)
                goto out;

        ksm_flag = vma->vm_flags & VM_MERGEABLE;

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
        svm = funcs->_find_svm(&id);
        BUG_ON(!svm);

        pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
        pte_entry = *pte;

        if (!pte_present(pte_entry)) {
                if (pte_none(pte_entry)) {

                        set_pte_at(
                                        mm,
                                        addr,
                                        pte,
                                        swp_entry_to_pte(
                                                        make_dsm_entry(
                                                                        (uint16_t) id.dsm_id,
                                                                        (uint8_t) id.svm_id)));
                        goto out_pte_unlock;
                } else {
                        swp_e = pte_to_swp_entry(pte_entry);
                        if (non_swap_entry(swp_e)) {
                                if (is_migration_entry(swp_e)) {
                                        pte_unmap_unlock(pte, ptl);
                                        migration_entry_wait(mm, pmd, addr);
                                        goto retry;
                                } else {
                                        r = -EFAULT;
                                        goto out_pte_unlock;
                                }
                        } else {

                                pte_unmap_unlock(pte, ptl);
                                r = handle_mm_fault(mm, vma, addr,
                                                FAULT_FLAG_WRITE);
                                if (r & VM_FAULT_ERROR) {
                                        errk("[*] failed at faulting \n");
                                        BUG();
                                }

                                r = 0;

                                goto retry;

                        }

                }

        } else {
                page = vm_normal_page(vma, request_addr, *pte);
                if (unlikely(!page)) {
                        //DSM1 we need to test if the pte is not null
                        page = pte_page(*pte);
                }
        }

        if (PageKsm(page)) {
                errk("[dsm_flag_page_remote] KSM page\n");

                r = ksm_madvise(vma, request_addr, request_addr,
                                MADV_UNMERGEABLE, &ksm_flag);

                if (r) {
                        printk("[dsm_extract_page] ksm_madvise ret : %d\n", r);

                        // DSM1 : better ksm error handling required.
                        return -EFAULT;

                }

        }

        if (!trylock_page(page)) {
                r = -EFAULT;
                goto out_pte_unlock;
        }

        flush_cache_page(vma, addr, pte_pfn(*pte));

        ptep_clear_flush_notify(vma, addr, pte);
        set_pte_at(
                        mm,
                        addr,
                        pte,
                        swp_entry_to_pte(
                                        make_dsm_entry((uint16_t) id.dsm_id,
                                                        (uint8_t) id.svm_id)));
        page_remove_rmap(page);

        dec_mm_counter(mm, MM_ANONPAGES);
        // this is a page flagging without data exchange so we can free the page
        if (!page_mapped(page))
                try_to_free_swap(page);

        // DSM1 - should we put_page in flag remote?
        //put_page(page);
        unlock_page(page);
        isolate_lru_page(page);
        if (PageActive(page))
                ClearPageActive(page);
        __free_page(page);

        out_pte_unlock:

        pte_unmap_unlock(pte, ptl);

        out:

        up_read(&mm->mmap_sem);

        return r;

}
EXPORT_SYMBOL(dsm_flag_page_remote);

int try_to_unmap_dsm(struct page *page) {
        struct red_page *rp = NULL;
        struct subvirtual_machine *svm = NULL;
        struct vm_area_struct *vma = NULL;
        struct mm_struct *mm;
        int ret = SWAP_FAIL;

        printk("[try_to_unmap_dsm] !!!\n");
//FUNCS
//        rp = funcs->_red_page_search(page_to_pfn(page));
//
//        printk("[try_to_unmap_dsm] red_page : %d\n", !!rp);
//
//        if (rp) {
//                svm = funcs->_find_svm(&rp->id);
//
//                printk("[try_to_unmap_dsm] svm : %d\n", !!svm);
//
//                if (svm && svm->priv) {
//                        mm = svm->priv->mm;
//                        vma = find_vma(mm, rp->addr);
//                        if (vma || vma->vm_start < rp->addr)
//                                ret = handle_mm_fault(mm, vma, rp->addr,
//                                                FAULT_FLAG_WRITE);
//
//                        printk("[try_to_unmap_dsm] handle_mm_fault : %d\n",
//                                        ret);
//
//                }
//        }

        return ret;
}
