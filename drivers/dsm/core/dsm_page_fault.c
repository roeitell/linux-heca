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
        page_cache_release(page);
        dsm_cache_release(svm, addr);
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

static inline void dpc_nproc_dec(struct dsm_page_cache **dpc, int dealloc) {
    atomic_dec(&(*dpc)->nproc);
    if (dealloc && atomic_cmpxchg(&(*dpc)->nproc, 1, 0) == 1) {
        page_cache_release((*dpc)->pages[0]);
        dsm_dealloc_dpc(dpc);
    }
}

static void dsm_pull_req_complete(struct tx_buf_ele *tx_e) {
    struct page_pool_ele *ppe = tx_e->wrk_req->dst_addr;
    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct page *page = ppe->mem_page;
    int i;

    for (i = 0; i < dpc->npages && dpc->pages[i] != page; i++)
        ;
    if (unlikely(i == dpc->npages))
        goto out;

    page_cache_release(page);
    set_page_private(page, 0);
    SetPageUptodate(page);

    if (atomic_cmpxchg(&dpc->found, -1, i) == -1) {
        mem_cgroup_reset_owner(page);
        lru_cache_add_anon(page);
        unlock_page(dpc->pages[0]);
    }

    dpc_nproc_dec(&dpc, dpc->tag != PREFETCH_TAG);
    out: ppe->mem_page = NULL;
}

static void dsm_try_pull_req_complete(struct tx_buf_ele *tx_e) {
    struct page_pool_ele *ppe = tx_e->wrk_req->dst_addr;
    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct mm_struct *mm = dpc->svm->priv->mm;
    unsigned long addr = tx_e->dsm_msg->req_addr + dpc->svm->priv->offset;

    /*
     * Pull try only happens when pushing to us - meaning we're only trying to
     * pull from a single svm. If fail, we can discard the whole operation.
     *
     */
    if (unlikely(tx_e->dsm_msg->type == TRY_REQUEST_PAGE_FAIL)) {
        page_cache_release(ppe->mem_page);
        SetPageUptodate(ppe->mem_page);

        unlock_page(dpc->pages[0]);
        atomic64_inc(&dpc->svm->svm_sysfs.stats.nb_page_pull_fail);

        dsm_cache_release(dpc->svm, addr);
        dpc_nproc_dec(&dpc, 1);
        return;
    }

    dsm_pull_req_complete(tx_e);

    /*
     * Get_user_pages for addr will trigger a page fault, and the faulter
     * will find the updated page and set the pte.
     *
     */
    use_mm(mm);
    down_read(&mm->mmap_sem);
    get_user_pages(current, mm, addr, 1, 1, 0, &ppe->mem_page, NULL);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);
}

static struct page *get_remote_dsm_page(struct vm_area_struct *vma,
        unsigned long addr, struct dsm_page_cache *dpc,
        struct subvirtual_machine *fault_svm,
        struct subvirtual_machine *remote_svm,
        unsigned long private, int tag, int i) {

    void (*func)(struct tx_buf_ele *);
    struct page *page;

    if (unlikely(!remote_svm))
        goto out;

    if (!dpc->pages[i])
        dpc->pages[i] = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, addr);
    page = dpc->pages[i];

    if (unlikely(!page))
        goto out;

    if (tag == PULL_TRY_TAG) {
        func = dsm_try_pull_req_complete;
        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_requested);
    } else {    /* prefetch or pull */
        func = dsm_pull_req_complete;
        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_pull);
    }

    page_cache_get(page);
    set_page_private(page, private);
    SetPageSwapBacked(page);

    funcs->request_dsm_page(page, remote_svm, fault_svm,
            (uint64_t) (addr - fault_svm->priv->offset), func, tag, dpc);

    out: return page;
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

static struct dsm_page_cache *get_dsm_page(struct mm_struct *mm,
        unsigned long addr, struct subvirtual_machine *fault_svm,
        unsigned long private, int tag);

static struct dsm_page_cache *dsm_cache_add_send(
        struct subvirtual_machine *fault_svm, struct svm_list svms,
        unsigned long addr, unsigned long norm_addr, int nproc, int tag,
        struct vm_area_struct *vma, struct mm_struct *mm, int private,
        int prefetch) {
    struct dsm_page_cache *new_dpc = NULL, *found_dpc = NULL;
    struct page *page = NULL;
    int r;

    do {
        found_dpc = dsm_cache_get_hold(fault_svm, norm_addr);
        if (unlikely(found_dpc))
            goto fail;

        if (!new_dpc) {
            new_dpc = dsm_alloc_dpc(svms.num, svms.num + nproc, tag, fault_svm);
            if (!new_dpc)
                goto fail;
        }

        if (!page) {
            page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, norm_addr);
            if (!page)
                goto fail;

            __set_page_locked(page);
            page_cache_get(page);
            set_page_private(page, 0);
            SetPageSwapBacked(page);
            new_dpc->pages[0] = page;
        }

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (unlikely(r))
            goto fail;

        spin_lock_irq(&fault_svm->page_cache_spinlock);
        r = radix_tree_insert(&fault_svm->page_cache, norm_addr, new_dpc);
        spin_unlock_irq(&fault_svm->page_cache_spinlock);
        radix_tree_preload_end();

        if (likely(!r)) {
            for (r = 0; r < svms.num; r++) {
                get_remote_dsm_page(vma, norm_addr, new_dpc, fault_svm,
                        svms.pp[r], private, tag, r);
            }
            if (prefetch) {
                for (r = 1; r < 40; r++) {
                    get_dsm_page(mm, addr + r * PAGE_SIZE, fault_svm, 0,
                            PREFETCH_TAG);
                }
            }
            return new_dpc;
        }
    } while (r != -ENOMEM);

    fail:
    if (new_dpc) {
        if (page) {
            ClearPageSwapBacked(page);
            unlock_page(page);
            page_cache_release(page);
        }
        dsm_dealloc_dpc(&new_dpc);
    }
    return found_dpc;       
}

static struct dsm_page_cache *get_dsm_page(struct mm_struct *mm,
        unsigned long addr, struct subvirtual_machine *fault_svm,
        unsigned long private, int tag) {

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
                        dsm_cache_add_send(fault_svm, dsd.svms, addr, norm_addr,
                                2, tag, vma, mm, private, 0);
                        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_requested_prefetch);
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
    int ret = 0, i, rethrow, exclusive = 0;
    struct dsm_page_cache *dpc;
    struct page *found_page, *swapcache = NULL;
    pte_t pte;

    dsd = swp_entry_to_dsm_data(entry);
    fault_svm = find_local_svm(dsd.dsm, mm);

    if (!pte_unmap_dsm_same(mm, pmd, page_table, orig_pte))
        goto out;

    retry: dpc = dsm_cache_get_hold(fault_svm, norm_addr);
    if (!dpc) {
        dpc = dsm_cache_add_send(fault_svm, dsd.svms, address, norm_addr, 3,
                PULL_TAG, vma, mm, 0, flags & FAULT_FLAG_ALLOW_RETRY);
        if (!dpc) {
            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (likely(pte_same(*page_table, orig_pte)))
                ret = VM_FAULT_OOM;
            pte_unmap_unlock(pte, ptl);
            return ret;
        }
        ret = VM_FAULT_MAJOR;
        count_vm_event(PGMAJFAULT);
        mem_cgroup_count_vm_event(mm, PGMAJFAULT);
    }

    if (unlikely(dpc->tag != PULL_TAG)) {
        i = dpc->tag;
        dpc->tag = PULL_TAG;

        if (unlikely(i == PUSH_TAG)) {
            found_page = dpc->pages[0];
            goto found;
        }
    }

    rethrow = !lock_page_or_retry(dpc->pages[0], mm, flags);
    if (rethrow) {
        ret |= VM_FAULT_RETRY;
        goto out;
    }

    i = atomic_read(&dpc->found);
    if (i < 0) {
        if (unlikely(page_private(dpc->pages[0]) == ULONG_MAX)) {
            dpc_nproc_dec(&dpc, 1);
            goto retry;
        }
        goto out;
    }

    found_page = dpc->pages[i];
    if (i)
        __set_page_locked(found_page);

    found: page_cache_get(found_page);
    if (ksm_might_need_to_copy(found_page, vma, address)) {
        swapcache = found_page;
        found_page = ksm_does_need_to_copy(found_page, vma, address);
        if (unlikely(!found_page)) {
            ret = VM_FAULT_OOM;
            found_page = swapcache;
            swapcache = NULL;
            goto out_page;
        }
    }

    page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (unlikely(!pte_same(*(page_table), orig_pte)))
        goto out_nomap;
    if (unlikely(!PageUptodate(found_page))) {
        ret = VM_FAULT_SIGBUS;
        goto out_nomap;
    }

    pte = mk_pte(found_page, vma->vm_page_prot);
    if (likely(reuse_dsm_page(fault_svm, found_page, norm_addr))) {
//we should pretty much always get in there unless we read fault
        pte = maybe_mkwrite(pte_mkdirty(pte), vma);
        flags &= ~FAULT_FLAG_WRITE;
        ret |= VM_FAULT_WRITE;
        exclusive = 1;
    }
    flush_icache_page(vma, found_page);
    set_pte_at(mm, address, page_table, pte);

    do_page_add_anon_rmap(found_page, vma, address, exclusive);
    inc_mm_counter(mm, MM_ANONPAGES);

    unlock_page(found_page);
    if (i)
        unlock_page(dpc->pages[0]);

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
    atomic_dec(&dpc->nproc);
    goto out;

    out_nomap: pte_unmap_unlock(page_table, ptl);
    out_page: unlock_page(found_page);
    page_cache_release(found_page);
    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }

    out: dpc_nproc_dec(&dpc, !(ret & VM_FAULT_RETRY));
    return ret;
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

