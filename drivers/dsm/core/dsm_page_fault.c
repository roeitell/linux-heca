/*
 * page_fault.c
 *
 *  Created on: 1 Aug 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

unsigned long zero_dsm_pfn __read_mostly;

static int __init init_dsm_zero_pfn(void)
{
    zero_dsm_pfn = page_to_pfn(ZERO_PAGE(0));
    return 0;
}
core_initcall(init_dsm_zero_pfn);

static inline int is_dsm_zero_pfn(unsigned long pfn) {
    return pfn == zero_dsm_pfn;
}

static int reuse_dsm_page(struct subvirtual_machine *svm, struct page *page,
        unsigned long addr) {
    int count;

    VM_BUG_ON(!PageLocked(page));
    if (unlikely(PageKsm(page)))
        return 0;

    count = page_mapcount(page);
    if (count == 0 && !PageWriteback(page)) {
        set_page_private(page, 0);
        if (!PageSwapBacked(page))
            SetPageDirty(page);
    }

    return count <= 1;
}

static inline void cow_user_page(struct page *dst, struct page *src,
        unsigned long va, struct vm_area_struct *vma) {

    if (unlikely(!src)) {
        void *kaddr = kmap_atomic(dst, KM_USER0);
        void __user *uaddr = (void __user *) (va & PAGE_MASK);

        if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE))
            clear_page(kaddr);
        kunmap_atomic(kaddr, KM_USER0);
        flush_dcache_page(dst);
    } else
        copy_user_highpage(dst, src, va, vma);
}

static int do_wp_dsm_page(struct subvirtual_machine *fault_svm,
        struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address,
        pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,
        unsigned long norm_address) __releases(ptl)
{
    struct page *old_page, *new_page;
    pte_t entry;
    int ret = 0;
    int page_mkwrite = 0;
    struct page *dirty_page = NULL;

    old_page = vm_normal_page(vma, address, orig_pte);
    if (!old_page) {
        if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == (VM_WRITE | VM_SHARED))
            goto reuse;
        goto gotten;
    }

    if (PageAnon(old_page) && !PageKsm(old_page)) {
        if (!trylock_page(old_page)) {
            page_cache_get(old_page);
            pte_unmap_unlock(page_table, ptl);
            lock_page(old_page);
            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (!pte_same(*page_table, orig_pte)) {
                unlock_page(old_page);
                goto unlock;
            }
            page_cache_release(old_page);
        }
        if (reuse_dsm_page(fault_svm, old_page, norm_address)) {
            page_move_anon_rmap(old_page, vma, address);
            unlock_page(old_page);
            goto reuse;
        }
        unlock_page(old_page);
    } else if (unlikely(
            (vma->vm_flags & (VM_WRITE | VM_SHARED))
                    == (VM_WRITE | VM_SHARED))) {

        if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
            struct vm_fault vmf;
            int tmp;

            vmf.virtual_address = (void __user *) (address & PAGE_MASK);
            vmf.pgoff = old_page->index;
            vmf.flags = FAULT_FLAG_WRITE | FAULT_FLAG_MKWRITE;
            vmf.page = old_page;

            page_cache_get(old_page);
            pte_unmap_unlock(page_table, ptl);

            tmp = vma->vm_ops->page_mkwrite(vma, &vmf);
            if (unlikely(tmp & (VM_FAULT_ERROR | VM_FAULT_NOPAGE))) {
                ret = tmp;
                goto unwritable_page;
            }
            if (unlikely(!(tmp & VM_FAULT_LOCKED))) {
                lock_page(old_page);
                if (!old_page->mapping) {
                    ret = 0; /* retry the fault */
                    unlock_page(old_page);
                    goto unwritable_page;
                }
            } else
                VM_BUG_ON(!PageLocked(old_page));

            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (!pte_same(*page_table, orig_pte)) {
                unlock_page(old_page);
                goto unlock;
            }

            page_mkwrite = 1;
        }
        dirty_page = old_page;
        page_cache_get(dirty_page);

        reuse: flush_cache_page(vma, address, pte_pfn(orig_pte));
        entry = pte_mkyoung(orig_pte);
        entry = maybe_mkwrite(pte_mkdirty(entry), vma);
        if (ptep_set_access_flags(vma, address, page_table, entry, 1))
            update_mmu_cache(vma, address, page_table);
        pte_unmap_unlock(page_table, ptl);
        ret |= VM_FAULT_WRITE;

        if (!dirty_page)
            return ret;

        if (!page_mkwrite) {
            wait_on_page_locked(dirty_page);
            set_page_dirty_balance(dirty_page, page_mkwrite);
        }
        put_page(dirty_page);
        if (page_mkwrite) {
            struct address_space *mapping = dirty_page->mapping;

            set_page_dirty(dirty_page);
            unlock_page(dirty_page);
            page_cache_release(dirty_page);
            if (mapping) {
                balance_dirty_pages_ratelimited(mapping);
            }
        }

        if (vma->vm_file)
            file_update_time(vma->vm_file);

        return ret;
    }

    page_cache_get(old_page);
    gotten: pte_unmap_unlock(page_table, ptl);

    if (unlikely(anon_vma_prepare(vma)))
        goto oom;

    if (is_dsm_zero_pfn(pte_pfn(orig_pte))) {
        new_page = alloc_zeroed_user_highpage_movable(vma, address);
        if (!new_page)
            goto oom;
    } else {
        new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
        if (!new_page)
            goto oom;
        cow_user_page(new_page, old_page, address, vma);
    }
    __SetPageUptodate(new_page);

    if (mem_cgroup_newpage_charge(new_page, mm, GFP_KERNEL))
        goto oom_free_new;

    page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (likely(pte_same(*page_table, orig_pte))) {
        if (old_page) {
            if (!PageAnon(old_page)) {
                dec_mm_counter(mm, MM_FILEPAGES);
                inc_mm_counter(mm, MM_ANONPAGES);
            }
        } else
            inc_mm_counter(mm, MM_ANONPAGES);
        flush_cache_page(vma, address, pte_pfn(orig_pte));
        entry = mk_pte(new_page, vma->vm_page_prot);
        entry = maybe_mkwrite(pte_mkdirty(entry), vma);

        ptep_clear_flush(vma, address, page_table);
        page_add_new_anon_rmap(new_page, vma, address);
        set_pte_at_notify(mm, address, page_table, entry);
        update_mmu_cache(vma, address, page_table);
        if (old_page) {
            page_remove_rmap(old_page);
        }

        new_page = old_page;
        ret |= VM_FAULT_WRITE;
    } else
        mem_cgroup_uncharge_page(new_page);

    if (new_page)
        page_cache_release(new_page);
    unlock: pte_unmap_unlock(page_table, ptl);
    if (old_page) {
        if ((ret & VM_FAULT_WRITE) && (vma->vm_flags & VM_LOCKED)) {
            lock_page(old_page); /* LRU manipulation */
            munlock_vma_page(old_page);
            unlock_page(old_page);
        }
        page_cache_release(old_page);
    }

    return ret;
    oom_free_new:
    page_cache_release(new_page);
    oom: if (old_page) {
        if (page_mkwrite) {
            unlock_page(old_page);
            page_cache_release(old_page);
        }
        page_cache_release(old_page);
    }
    return VM_FAULT_OOM;

    unwritable_page:
    page_cache_release(old_page);
    return ret;
}

static int dsm_page_fault_success(struct page *page,
       struct subvirtual_machine *fault_svm, struct vm_area_struct *vma,
       unsigned long address, pte_t *page_table, pmd_t *pmd,
       unsigned int flags, pte_t orig_pte) {

    struct mm_struct *mm = fault_svm->priv->mm;
    struct page *swapcache = NULL;
    int ret = 0, exclusive = 0;
    pte_t pte;
    spinlock_t *ptl;
    unsigned long norm_addr = address & PAGE_MASK;

    if (ksm_might_need_to_copy(page, vma, address)) {
        swapcache = page;
        page = ksm_does_need_to_copy(page, vma, address);
        if (unlikely(!page)) {
            ret = VM_FAULT_OOM;
            page = swapcache;
            swapcache = NULL;
            goto out_page;
        }
    }

    /*
     * If several threads are trying to update the pte, only the first shall
     * succeed. Others will either not be able to lock, or identify an
     * already-modified pte.
     *
     */
    page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (unlikely(!pte_same(*(page_table), orig_pte)))
        goto out_nomap;
    if (unlikely(!PageUptodate(page))) {
        ret = VM_FAULT_SIGBUS;
        goto out_nomap;
    }

    pte = mk_pte(page, vma->vm_page_prot);
    if (likely(reuse_dsm_page(fault_svm, page, norm_addr))) {
//we should pretty much always get in there unless we read fault
        pte = maybe_mkwrite(pte_mkdirty(pte), vma);
        flags &= ~FAULT_FLAG_WRITE;
        ret |= VM_FAULT_WRITE;
        exclusive = 1;
    }
    flush_icache_page(vma, page);
    set_pte_at(mm, address, page_table, pte);

    do_page_add_anon_rmap(page, vma, address, exclusive);
    inc_mm_counter(mm, MM_ANONPAGES);

    unlock_page(page);

    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }
    if (flags & FAULT_FLAG_WRITE) {
        ret |= do_wp_dsm_page(fault_svm, mm, vma, address, 
                page_table, pmd, ptl, pte, norm_addr);
        if (ret & VM_FAULT_ERROR)
            ret &= VM_FAULT_ERROR;
        goto out;
    }

    update_mmu_cache(vma, address, page_table);
    atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_request_success);
    pte_unmap_unlock(pte, ptl);
    goto out;

    out_nomap: pte_unmap_unlock(page_table, ptl);
    out_page: unlock_page(page);
    page_cache_release(page);
    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }

    out: return ret;
}

static void dsm_pull_req_complete(struct tx_buf_ele *tx_e) {
    struct page_pool_ele *ppe = tx_e->wrk_req->dst_addr;
    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct page *page;
    int i;

    /*
     * First response to arrive releases everyone; and unlocks first page, to
     * signal a faulter thread it can now set the pte.
     * 
     */
    if (!test_and_set_bit_lock(DSM_CACHE_COMPLETE, &dpc->flags)) {

        /*
         * Order is important: first inc refcount for right page, then release
         * everyone.
         *
         */
        mem_cgroup_reset_owner(ppe->mem_page);
        lru_cache_add_anon(ppe->mem_page);

        for (i = dpc->npages; i; --i) {
            page = dpc->pages[i-1];
            if (page) {
                page_cache_release(page);
                set_page_private(page, 0);
                SetPageUptodate(page);

                if (page == ppe->mem_page)
                    dpc->found = i;
            }
        }

        unlock_page(dpc->pages[0]);
    }

    /*
     * All rdma requests returned; if we are page faulting (and not
     * pre-fetching or responding to a push), we can discard the dsm_cache
     * entry. Otherwise, we still need it to signal future faults that page
     * has already been brought.
     *
     */
    if (dpc->tag == PULL_TAG) {
        if (atomic_dec_and_test(&dpc->nproc))
            set_bit(DSM_CACHE_DISCARD, &dpc->flags);
    }

    ppe->mem_page = NULL;
}

static void dsm_try_pull_req_complete(struct tx_buf_ele *tx_e) {
    struct page_pool_ele *ppe = tx_e->wrk_req->dst_addr;
    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct mm_struct *mm;
    unsigned long addr;

    /*
     * Pull try failed, no-op. Page will be released on gc, same as when
     * regular pull doesn't respond.
     *
     */
    if (tx_e->dsm_msg->type == TRY_REQUEST_PAGE_FAIL) {
        atomic64_inc(&dpc->svm->svm_sysfs.stats.nb_page_pull_fail);
        return;
    } 

    dsm_pull_req_complete(tx_e);

    /*
     * Get_user_pages for addr will trigger a page fault, and the faulter
     * will find the updated page and set the pte.
     *
     */
    addr = tx_e->dsm_msg->req_addr + dpc->svm->priv->offset;
    mm = dpc->svm->priv->mm;
    use_mm(mm);
    down_read(&mm->mmap_sem);
    get_user_pages(current, mm, addr, 1, 1, 0, &ppe->mem_page, NULL);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);
}

static int get_remote_dsm_page(gfp_t gfp_mask, struct vm_area_struct *vma,
        unsigned long addr, struct dsm_page_cache *dpc, struct svm_list svms,
        struct subvirtual_machine *fault_svm, unsigned long private, int tag) {

    struct page *new_page = NULL;
    int i, j;
    void (*func)(struct tx_buf_ele *) = NULL;

    if (tag == PULL_TRY_TAG) {
        func = dsm_try_pull_req_complete;
        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_requested);
    } else {
        func = dsm_pull_req_complete;
        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_pull);
    }

    for (i = 0, j = 0; i < svms.num; i++) {
        if (!svms.pp[i])
            continue;

        new_page = alloc_page_vma(gfp_mask, vma, addr);
        if (!new_page) {
            dpc->npages = j;
            goto finish; /* Out of Memory, send less rdma requests for page */
        }

        if (!j)
            __set_page_locked(new_page);

        page_cache_get(new_page);
        set_page_private(new_page, private);
        SetPageSwapBacked(new_page);

        dpc->pages[j++] = new_page;

        funcs->request_dsm_page(new_page, svms.pp[i], fault_svm,
               (uint64_t) (addr - fault_svm->priv->offset), func, tag, dpc);
    }

    finish: return j;
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

static struct dsm_page_cache *get_dsm_page(struct mm_struct *mm, unsigned long addr,
        struct subvirtual_machine *fault_svm, unsigned long private, int tag) {

    pte_t *pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct vm_area_struct *vma;
    unsigned long norm_addr = addr & PAGE_MASK;
    struct dsm_page_cache *dpc = NULL;
    struct dsm_swp_data dsd;

    dpc = dsm_cache_get(fault_svm, norm_addr);
    if (!dpc) {

        vma = find_vma(mm, addr);
        if (unlikely(!vma || vma->vm_start > addr))
            goto out;

        pgd = pgd_offset(mm, addr);
        if (unlikely(!pgd_present(*pgd)))
            goto out;

        pud = pud_offset(pgd, addr);
        if (unlikely(!pud_present(*pud)))
            goto out;

        pmd = pmd_offset(pud, addr);
        if (unlikely(pmd_none(*pmd)))
            goto out;

        if (unlikely(pmd_bad(*pmd))) {
            pmd_clear_bad(pmd);
            goto out;
        }
        if (unlikely(pmd_trans_huge(*pmd)))
            goto out;

        pte = pte_offset_map(pmd, addr);
        pte_entry = *pte;

        if (unlikely(!pte_present(pte_entry))) {
            if (!pte_none(pte_entry)) {
                swp_e = pte_to_swp_entry(pte_entry);
                if (non_swap_entry(swp_e)) {
                    if (is_dsm_entry(swp_e)) {
                        dsd = swp_entry_to_dsm_data(swp_e);

                        dpc = dsm_cache_add(fault_svm, norm_addr, dsd.svms.num,
                                dsd.svms.num, tag);
                        if (dpc) {
                            get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma,
                                    norm_addr, dpc, dsd.svms, fault_svm,
                                    private, tag);
                            atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_requested_prefetch);
                        }
                    }
                }
            }
        }
    }
    out:

    return dpc;
}

static int do_dsm_page_fault(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd,
        unsigned int flags, pte_t orig_pte, swp_entry_t entry) {

    struct dsm_swp_data dsd;
    struct subvirtual_machine *fault_svm;
//we need to use the page addr and not the fault address in order to have a unique reference
    unsigned long norm_addr = address & PAGE_MASK;
    spinlock_t *ptl;
    int ret = 0, i, rethrow, sent, exists = 0;
    struct dsm_page_cache *dpc;
    struct page *found_page;

    printk("[do_dsm_page_fault] faulting for page %p , norm %p \n",
            (void*) address, (void*) norm_addr);

    dsd = swp_entry_to_dsm_data(entry);
    fault_svm = find_local_svm(dsd.dsm, mm);
    BUG_ON(!fault_svm);

    /*
     * Order here is crucial: another fault for this page might be racing us.
     * If next two blocks are reversed, another thread could set the pte and
     * release the dsm_cache entry between them.
     * 
     * dsm_cache_add is protected by a spin lock (same as __add_to_swap_cache),
     * therefore threads cannot race into next block.
     *
     */
    do {
        dpc = dsm_cache_get(fault_svm, norm_addr);
        if (dpc) {
            exists = 1;
            break;
        }

        /*
         * Fails if we couldn't alloc, or if someone has raced us to the cache
         * and already added the entry.
         *
         */
        dpc = dsm_cache_add(fault_svm, norm_addr, dsd.svms.num, dsd.svms.num, 
                PULL_TAG);

    } while (!dpc);

    if (!pte_unmap_dsm_same(mm, pmd, page_table, orig_pte)) {
        if (!exists) /* it's our entry, we need to release it */
            dsm_cache_release(fault_svm, norm_addr);
        goto out;
    }

    if (exists) {

        /*
         * We already sent rdma requests for this page. This can be the second
         * attempt of our thread to fault; another thread may have already
         * faulted for it; and the might have been pre-fetched, or try-pulled
         * (pushed to us). In all cases, rdma requests have already been sent.
         *
         */
        if (likely(dpc->tag & (PULL_TAG | PULL_TRY_TAG | PREFETCH_TAG))) {
            dpc->tag = PULL_TAG;
            if (dpc->tag == PULL_TRY_TAG)
                goto prefetch;
            goto wait;
        }

        /*
         * An unfinished push means we still have the page up-to-date in memory;
         * cancel the push and re-set the pte.
         *
         */
        else if (dpc->tag == PUSH_TAG) {
            dpc->tag = PULL_TAG;
            found_page = dpc->pages[0];
            goto found;
        }

        printk("[do_dsm_page_fault] unhandled tag %d\n", dpc->tag);
        BUG();
    }

    sent = get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma, norm_addr, dpc,
            dsd.svms, fault_svm, 0, PULL_TAG);

    if (!sent) {
        page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
        ret = (likely(pte_same(*page_table, orig_pte))) ?
            VM_FAULT_OOM : VM_FAULT_MAJOR;
        pte_unmap_unlock(*page_table, ptl);
        dsm_cache_release(fault_svm, norm_addr);
        goto out;
    }

    prefetch:
    for (i = 1; i < 40; i++) {
        get_dsm_page(mm, address + i * PAGE_SIZE, fault_svm, 0,
            PREFETCH_TAG);
    }

    /*
     * This is a major logical intersection. If one of the rdma requests has
     * already returned, but pte has not yet been set for it, we can re-lock the
     * page and continue to fully resolve the page fault, regardless of the
     * thread or attempt we are in. Otherwise, the pages are still locked, and
     * we will re-throw the fault. On the second attempt we will always continue
     * to the next block, trying to set the pte for the returned data. The next
     * block has protections of its own, guaranteeing it will only be executed
     * once.
     *
     * The edge case of continuing on the second attempt, without any of the
     * requests yet to return should be rare. Re-throwing the fault usually
     * happens only after the page is unlocked; an exception is running with
     * NOWAIT flag, which happens in kvm - but kvm handles it differently.
     *
     * This is identical to the standard page faulting in linux, to support all
     * possible modes (and specifically, kvm and the NOWAIT flag).
     *
     */
    wait: rethrow = !lock_page_or_retry(dpc->pages[0], mm, flags);
    if (rethrow) {
        ret |= VM_FAULT_RETRY;
        goto out;
    }

    /*
     * Second attempt, yet no rdma request has yet returned.
     *
     */
    if (!dpc->found) {
        ret |= VM_FAULT_ERROR;
        goto out;
    }
    found_page = dpc->pages[dpc->found-1];

    found: ret = dsm_page_fault_success(found_page, fault_svm, vma, address,
                page_table, pmd, flags, orig_pte);
    dsm_cache_release(fault_svm, address);

    out: return ret;
}

#ifdef CONFIG_DSM_CORE
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd,
        unsigned int flags, pte_t orig_pte, swp_entry_t entry)
{
    return do_dsm_page_fault(mm, vma, address, page_table, pmd, flags, 
            orig_pte, entry);
}
#else
int dsm_swap_wrapper(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd,
        unsigned int flags, pte_t orig_pte, swp_entry_t entry) {
    return 0;
}

#endif /* CONFIG_DSM */

struct dsm_page_cache *dsm_trigger_page_pull(struct dsm *dsm, 
        struct subvirtual_machine *local_svm, unsigned long norm_addr) {
    struct dsm_page_cache *dpc = NULL;
    struct mm_struct *mm;

    mm = local_svm->priv->mm;
    use_mm(mm);
    down_read(&mm->mmap_sem);
    dpc = get_dsm_page(mm, norm_addr, local_svm, ULONG_MAX, PULL_TRY_TAG);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);

    return dpc;
}
EXPORT_SYMBOL(dsm_trigger_page_pull);

