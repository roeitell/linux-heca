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
#include <linux/spinlock.h>
#include <linux/delayacct.h>
#include <linux/ksm.h>
#include <linux/radix-tree.h>
#include <linux/init.h>
#include <linux/pagemap.h>

static DEFINE_SPINLOCK(dsm_page_tree_lock);
static RADIX_TREE(dsm_page_tree, GFP_ATOMIC|__GFP_NOWARN);

void signal_completion_page_request(struct tx_buf_ele * tx_e) {

        page_pool_ele * ppe = tx_e->wrk_req->dst_addr;
        errk(
                        "[signal_completion_page_request] got page data back , unlocking \n ");
        BUG_ON(PageUptodate( ppe->mem_page));
        SetPageUptodate(ppe->mem_page);
        unlock_page(ppe->mem_page);
        ppe->mem_page = NULL;

}
EXPORT_SYMBOL(signal_completion_page_request);

void __delete_from_dsm_cache(struct page *page) {
        VM_BUG_ON(!PageLocked(page));
        VM_BUG_ON(PageWriteback(page));
        errk("[__delete_from_dsm_cache] deleting \n ");
        radix_tree_delete(&dsm_page_tree, page_private(page));
        set_page_private(page, 0);

}

void delete_from_dsm_cache(struct page *page) {
        unsigned long addr;

        addr = page_private(page);

        spin_lock_irq(&dsm_page_tree_lock);
        __delete_from_dsm_cache(page);
        spin_unlock_irq(&dsm_page_tree_lock);

        page_cache_release(page);
}

int reuse_dsm_cache_page(struct page *page) {
        int count;

        VM_BUG_ON(!PageLocked(page));
        if (unlikely(PageKsm(page)))
                return 0;
        count = page_mapcount(page);
        if (count <= 1) {
                if (count == 1 && !PageWriteback(page)) {
                        delete_from_dsm_cache(page);
                        SetPageDirty(page);
                }
        }
        return count <= 1;
}

void queue_request_dsm_page(struct subvirtual_machine *svm,
                struct subvirtual_machine *fault_svm, unsigned long address,
                struct page * page) {

        funcs->request_dsm_page(svm->ele, fault_svm->id, svm->id,
                        (uint64_t) (address - fault_svm->priv->offset),
                        page, signal_completion_page_request);

}

static int add_to_dsm_page_cache(struct page *page, unsigned long address) {
        int error;

        VM_BUG_ON(!PageLocked(page));

        page_cache_get(page);
        set_page_private(page, address);

        spin_lock_irq(&dsm_page_tree_lock);
        error = radix_tree_insert(&dsm_page_tree, address, page);
        if (likely(!error)) {
                // we should track the stats here
                //                __inc_zone_page_state(page, NR_FILE_PAGES);

        }
        spin_unlock_irq(&dsm_page_tree_lock);

        if (unlikely(error)) {

                VM_BUG_ON(error == -EEXIST);
                set_page_private(page, 0UL);

                page_cache_release(page);
        }

        return error;
}

struct page * find_get_dsm_page(unsigned long address) {
        void **pagep;
        struct page *page;

        rcu_read_lock();
        repeat: page = NULL;
        pagep = radix_tree_lookup_slot(&dsm_page_tree, address);
        if (pagep) {
                page = radix_tree_deref_slot(pagep);
                if (unlikely(!page))
                        goto out;
//WE NEED TO UPDATE TO LATEST KERNEL
                //THEIR IS SOME CHANGE HERE
                if (radix_tree_deref_retry(page))
                        goto repeat;

                if (!page_cache_get_speculative(page))
                        goto repeat;

                if (unlikely(page != *pagep)) {
                        page_cache_release(page);
                        goto repeat;
                }
        }
        out: rcu_read_unlock();

        return page;
}

struct page * get_local_dsm_page(void) {
        return NULL;
}

struct page * get_remote_dsm_page(struct subvirtual_machine *svm,
                struct subvirtual_machine *fault_svm, gfp_t gfp_mask,
                struct vm_area_struct *vma, unsigned long address) {
        struct page *found_page, *new_page = NULL;
        int err;
        do {
                found_page = find_get_dsm_page(address);
                if (found_page)
                        break;

                if (!new_page) {
                        new_page = alloc_page_vma(gfp_mask, vma, address);
                        if (!new_page)
                                break;

                }

                err = radix_tree_preload(gfp_mask & GFP_KERNEL);
                if (err)
                        break;

                __set_page_locked(new_page);

                err = add_to_dsm_page_cache(new_page, address);

                if (likely(!err)) {
                        radix_tree_preload_end();
                        /*
                         * Initiate rdma fetch in page locked and return
                         */
                        lru_cache_add_anon(new_page);
                        queue_request_dsm_page(svm, fault_svm, address,
                                        new_page);

                        return new_page;
                }
                radix_tree_preload_end();

                __clear_page_locked(new_page);

        } while (err != -ENOMEM);

        if (new_page)
                page_cache_release(new_page);
        return found_page;

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
        struct page *swapcache = NULL;
        struct mem_cgroup *ptr;
        int locked;
        pte_t pte;
        int exclusive = 0;

        dsm_entry_to_val(entry, &id.dsm_id, &id.svm_id);

        svm = funcs->_find_svm(&id);
        BUG_ON(!svm);

        fault_svm = funcs->_find_local_svm(svm->id.dsm_id, mm);

        BUG_ON(!fault_svm);
        errk("[request_page_insert]before request page %p \n", page);
        delayacct_set_flag(DELAYACCT_PF_SWAPIN);
        if (svm->priv) {

                page = get_local_dsm_page();

//                page = dsm_extract_page_protected(
//                                fault_svm->id,
//                                svm->priv->mm,
//                                norm_addr + svm->priv->offset
//                                                - fault_svm->priv->offset);

        } else {
                page = get_remote_dsm_page(svm, fault_svm, GFP_HIGHUSER_MOVABLE,
                                vma, norm_addr);

        }
        errk("[request_page_insert] faulting for addr %p , norm %p  page %p\n ",
                        address, norm_addr, page);
        if (!page) {

                page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
                if (likely(pte_same(*page_table, orig_pte)))
                        ret = VM_FAULT_OOM;
                delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
                goto unlock;
        }
        errk("[request_page_insert] page ok page %p \n", page);
        ret = VM_FAULT_MAJOR;
        count_vm_event(PGMAJFAULT);
        mem_cgroup_count_vm_event(mm, PGMAJFAULT);
        errk("[request_page_insert]accounting page %p \n", page);
        locked = lock_page_or_retry(page, mm, flags);
        delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
        if (!locked) {
                ret |= VM_FAULT_RETRY;
                goto out_release;
        }
        errk("[request_page_insert]lock ok  page %p \n", page);
        if (ksm_might_need_to_copy(page, vma, address)) {
                swapcache = page;
                page = ksm_does_need_to_copy(page, vma, address);

                if (unlikely(!page)) {
                        BUG_ON(!page);
                        errk("requested by ksm  page %p \n", page);
                        ret = VM_FAULT_OOM;
                        page = swapcache;
                        swapcache = NULL;
                        // we need to send back the page !!

                        goto out_page;
                }
        }
        errk("[request_page_insert]ksm ok page %p \n", page);
        /*
         * Back out if somebody else already faulted in this pte.
         */
        page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
        if (unlikely(!pte_same(*page_table, orig_pte)))
                goto out_nomap;
        errk("[request_page_insert]pte lock ok page %p \n", page);
        if (unlikely(!PageUptodate(page))) {
                ret = VM_FAULT_SIGBUS;
                goto out_nomap;
        }
        errk("[request_page_insert]not up to date ok page %p \n", page);
        //inc_mm_counter_fast(mm, MM_ANONPAGES);
        //dec_mm_counter_fast(mm, MM_SWAPENTS);
        pte = mk_pte(page, vma->vm_page_prot);
        if ((flags & FAULT_FLAG_WRITE) && reuse_dsm_cache_page(page)) {
                pte = maybe_mkwrite(pte_mkdirty(pte), vma);
                flags &= ~FAULT_FLAG_WRITE;
                ret |= VM_FAULT_WRITE;
                exclusive = 1;
        }
        errk("[request_page_insert]maybe write ok page %p \n", page);
        flush_icache_page(vma, page);
        set_pte_at(mm, address, page_table, pte);
        do_page_add_anon_rmap(page, vma, address, exclusive);
        errk("[request_page_insert]set pte + rmap ok page %p \n", page);
// we remove the page from the cache here !
        if (find_get_dsm_page(norm_addr)) {
                delete_from_dsm_cache(page);
        }
        unlock_page(page);
        if (swapcache) {
                unlock_page(swapcache);
                page_cache_release(swapcache);
        }
        errk("[request_page_insert]unlock page + free dsm cache ok page %p \n",
                        page);
        /* No need to invalidate - it was non-present before */
        update_mmu_cache(vma, address, page_table);
        errk("[request_page_insert]mmu update  page %p \n", page);
        unlock: pte_unmap_unlock(pte, ptl);
        errk("[request_page_insert]unlock  page %p \n", page);
        out: return ret;

        out_nomap:
//        mem_cgroup_cancel_charge_swapin(ptr);
        pte_unmap_unlock(page_table, ptl);

        out_page: unlock_page(page);

        out_release: page_cache_release(page);
        if (swapcache) {
                unlock_page(swapcache);
                page_cache_release(swapcache);
        }

        return ret;
}

#ifdef CONFIG_DSM_CORE
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long address, pte_t *page_table, pmd_t *pmd,
                unsigned int flags, pte_t orig_pte, swp_entry_t entry)
{
        return request_page_insert(mm, vma, address, page_table, pmd, flags, orig_pte, entry);
}
#else
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
                unsigned long address, pte_t *page_table, pmd_t *pmd,
                unsigned int flags, pte_t orig_pte, swp_entry_t entry) {
        return 0;
}
#endif /* CONFIG_DSM */

