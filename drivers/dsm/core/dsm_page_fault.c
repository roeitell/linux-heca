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
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mmu_notifier.h>
#include <linux/rmap.h>
#include <dsm/dsm_core.h>
#include <dsm/dsm_ctl.h>
#include <dsm/dsm_rb.h>
#include <dsm/dsm_sr.h>

RADIX_TREE(dsm_tree, GFP_ATOMIC);
DEFINE_SPINLOCK(dsm_lock);

void signal_completion_page_request(struct tx_buf_ele * tx_e) {
        page_pool_ele * ppe = tx_e->wrk_req->dst_addr;
        SetPageUptodate(ppe->mem_page);
        unlock_page(ppe->mem_page);
        ppe->mem_page = NULL;

}

void delete_from_dsm_cache(struct page *page, unsigned long addr) {

        VM_BUG_ON(!PageLocked(page));

        spin_lock_irq(&dsm_lock);
        radix_tree_delete(&dsm_tree, addr);
        set_page_private(page, 0);
        spin_unlock_irq(&dsm_lock);

        put_page(page);
}

static int __add_to_dsm_cache(struct page *page, unsigned long addr) {
        int error;

        VM_BUG_ON(!PageLocked(page));

        get_page(page);
        set_page_private(page, addr);

        spin_lock_irq(&dsm_lock);
        error = radix_tree_insert(&dsm_tree, addr, page);
        if (likely(!error)) {

        }
        spin_unlock_irq(&dsm_lock);

        if (unlikely(error)) {
                /*
                 * Only the context which have set SWAP_HAS_CACHE flag
                 * would call add_to_swap_cache().
                 * So add_to_swap_cache() doesn't returns -EEXIST.
                 */
                VM_BUG_ON(error == -EEXIST);
                set_page_private(page, 0UL);

                put_page(page);
        }

        return error;
}

void dsm_readpage(struct page* page, unsigned long addr,
                struct subvirtual_machine *svm,
                struct subvirtual_machine *fault_svm) {

        funcs->request_dsm_page(
                        page,
                        svm,
                        fault_svm,
                        (uint64_t) (addr - fault_svm->priv->offset), signal_completion_page_request)
                        ;
}

struct page *find_get_dsm_page(unsigned long addr) {
        void **pagep;
        struct page *page;

        rcu_read_lock();
        repeat: page = NULL;
        pagep = radix_tree_lookup_slot(&dsm_tree, addr);
        if (pagep) {
                page = radix_tree_deref_slot(pagep);
                if (unlikely(!page))
                        goto out;
                if (radix_tree_deref_retry(page))
                        goto repeat;

                if (!page_cache_get_speculative(page))
                        goto repeat;

                /*
                 * Has the page moved?
                 * This is part of the lockless pagecache protocol. See
                 * include/linux/pagemap.h for details.
                 */
                if (unlikely(page != *pagep)) {
                        page_cache_release(page);
                        goto repeat;
                }
        }
        out: rcu_read_unlock();

        return page;
}

struct page * get_remote_dsm_page(gfp_t gfp_mask, struct vm_area_struct *vma,
                unsigned long addr, struct subvirtual_machine *svm,
                struct subvirtual_machine *fault_svm) {

        struct page *found_page, *new_page = NULL;
        int err;

        do {
                /*
                 * First check the swap cache.  Since this is normally
                 * called after lookup_swap_cache() failed, re-calling
                 * that would confuse statistics.
                 */
                found_page = find_get_dsm_page(addr);
                if (found_page)
                        break;

                /*
                 * Get a new page to read into from swap.
                 */
                if (!new_page) {
                        new_page = alloc_page_vma(gfp_mask, vma, addr);
                        if (!new_page)
                                break; /* Out of memory */
                }

                /*
                 * call radix_tree_preload() while we can wait.
                 */
                err = radix_tree_preload(gfp_mask & GFP_KERNEL);
                if (err)
                        break;

                /* May fail (-ENOMEM) if radix-tree node allocation failed. */
                __set_page_locked(new_page);

                err = __add_to_dsm_cache(new_page, addr);
                if (likely(!err)) {
                        radix_tree_preload_end();
                        /*
                         * Initiate read into locked page and return.
                         */
                        lru_cache_add_anon(new_page);
                        dsm_readpage(new_page, addr, svm, fault_svm);
                        return new_page;
                }
                radix_tree_preload_end();
                __clear_page_locked(new_page);
        } while (err != -ENOMEM);

        if (new_page)
                put_page(new_page);
        return found_page;

}

struct page * get_local_dsm_page(gfp_t gfp_mask, struct vm_area_struct *vma,
                unsigned long addr, struct subvirtual_machine *svm,
                struct subvirtual_machine *fault_svm) {
        struct page * page = NULL;
        int err = 0;
        /*
         * call radix_tree_preload() while we can wait.
         */
        err = radix_tree_preload(gfp_mask & GFP_KERNEL);
        if (err)
                return NULL;
        spin_lock_irq(&dsm_lock);
        page = find_get_dsm_page(addr);
        if (!page) {
                page = dsm_extract_page_protected(
                                fault_svm->id,
                                svm->priv->mm,
                                addr + svm->priv->offset
                                                - fault_svm->priv->offset);

                /* May fail (-ENOMEM) if radix-tree node allocation failed. */
                __set_page_locked(page);
                err = radix_tree_insert(&dsm_tree, addr, page);
                BUG_ON(err);
                if (!trylock_page(page)) {
                        SetPageUptodate(page);
                        unlock_page(page);
                }
        }
        spin_unlock_irq(&dsm_lock);
        radix_tree_preload_end();
        return page;

}

static inline int pte_unmap_dsm_same(struct mm_struct *mm, pmd_t *pmd,
                pte_t *page_table, pte_t orig_pte) {
        int same = 1;
#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT)
        if (sizeof(pte_t) > sizeof(unsigned long)) {
                spinlock_t *ptl = pte_lockptr(mm, pmd);
                spin_lock(ptl);
                same = pte_same(*page_table, orig_pte);
                spin_unlock(ptl);
        }
#endif
        pte_unmap(page_table);
        return same;
}

static int request_page_insert(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long address, pte_t *page_table, pmd_t *pmd,
                unsigned int flags, pte_t orig_pte, swp_entry_t entry) {

        struct dsm_vm_id id;
        struct subvirtual_machine *svm;
        struct subvirtual_machine *fault_svm;
        //we need to use the page addr and not the fault address in order to have a unique reference
        unsigned long norm_addr = address & PAGE_MASK;
        spinlock_t *ptl;
        int ret = 0;
        struct page *page = NULL;
        int exclusive = 0;

        pte_t pte;
        int locked;

        errk("[request_page_insert] faulting for page %p , norm %p \n ",
                        address, norm_addr);
        if (!pte_unmap_dsm_same(mm, pmd, page_table, orig_pte)) {
                errk("[request_page_insert] not same pte !!!! \n ");
                goto out;
        }

        page = find_get_dsm_page(norm_addr);
        errk("[request_page_insert] did we find page %p \n ", page);
        if (!page) {

                errk("[request_page_insert] didn't find page \n ");
                dsm_entry_to_val(entry, &id.dsm_id, &id.svm_id);

                svm = funcs->_find_svm(&id);
                BUG_ON(!svm);

                fault_svm = funcs->_find_local_svm(svm->id.dsm_id, mm);

                BUG_ON(!fault_svm);
                if (svm->priv) {
                        page = get_local_dsm_page(GFP_HIGHUSER_MOVABLE, vma,
                                        norm_addr, svm, fault_svm);
                } else {
                        page = get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma,
                                        norm_addr, svm, fault_svm);

                }
                if (!page) {
                        page_table = pte_offset_map_lock(mm, pmd, address,
                                        &ptl);
                        if (likely(pte_same(*page_table, orig_pte)))
                                ret = VM_FAULT_OOM;

                        goto unlock;
                }
                ret = VM_FAULT_MAJOR;
        }
        errk("[request_page_insert] got page ! \n ");
        locked = lock_page_or_retry(page, mm, flags);
        if (!locked) {
                ret |= VM_FAULT_RETRY;
                goto out;
        }

        page_table = pte_offset_map_lock(mm, pmd, address, &ptl);

        if (unlikely(!pte_same(*page_table, orig_pte))) {
                goto out_nomap;
        }
        if (unlikely(!PageUptodate(page))) {
                ret = VM_FAULT_SIGBUS;
                goto out_nomap;
        }
        inc_mm_counter(mm, MM_ANONPAGES);
        pte = mk_pte(page, vma->vm_page_prot);
        if (flags & FAULT_FLAG_WRITE) {

                pte = maybe_mkwrite(pte_mkdirty(pte), vma);
                flags &= ~FAULT_FLAG_WRITE;
                ret |= VM_FAULT_WRITE;
                exclusive = 1;

        }
        flush_icache_page(vma, page);
        ptep_clear_flush(vma, address, page_table);
        set_pte_at_notify(mm, address, page_table, pte);
        do_page_add_anon_rmap(page, vma, address, exclusive);
        update_mmu_cache(vma, address, page_table);
        delete_from_dsm_cache(page, norm_addr);
        pte_unmap_unlock(pte, ptl);
        unlock_page(page);
        errk("[request_page_insert] page fault success \n ");
        out: return ret;

        out_nomap: pte_unmap_unlock(page_table, ptl);
        unlock_page(page);
        return ret;
        unlock: pte_unmap_unlock(page_table, ptl);
        return ret;

}

#ifdef CONFIG_DSM_CORE
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long address, pte_t *page_table, pmd_t *pmd,
                unsigned int flags, pte_t orig_pte, swp_entry_t entry)
{
        return request_page_insert(mm, vma,
                        address, page_table, pmd,
                        flags, orig_pte,entry);
}
#else
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long address, pte_t *page_table, pmd_t *pmd,
                unsigned int flags, pte_t orig_pte, swp_entry_t entry) {
        return 0;
}
#endif /* CONFIG_DSM */

