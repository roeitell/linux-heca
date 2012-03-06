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
        struct dsm_fault_data *fd) {
    struct mm_struct *mm = fd->fault_svm->priv->mm;
    struct page *swapcache = NULL;
    int ret = 0, exclusive = 0;
    pte_t pte;
    spinlock_t *ptl;
    unsigned long norm_addr = fd->address & PAGE_MASK;

    if (ksm_might_need_to_copy(page, fd->vma, fd->address)) {
        swapcache = page;
        page = ksm_does_need_to_copy(page, fd->vma, fd->address);
        if (unlikely(!page)) {
            ret = VM_FAULT_OOM;
            page = swapcache;
            swapcache = NULL;
            goto out_page;
        }
    }

    fd->page_table = pte_offset_map_lock(mm, fd->pmd, fd->address, &ptl);
    if (unlikely(!pte_same(*(fd->page_table), fd->orig_pte)))
        goto out_nomap;
    if (unlikely(!PageUptodate(page))) {
        ret = VM_FAULT_SIGBUS;
        goto out_nomap;
    }

    pte = mk_pte(page, fd->vma->vm_page_prot);
    if (likely(reuse_dsm_page(fd->fault_svm, page, norm_addr))) {
//we should pretty much always get in there unless we read fault
        pte = maybe_mkwrite(pte_mkdirty(pte), fd->vma);
        fd->flags &= ~FAULT_FLAG_WRITE;
        ret |= VM_FAULT_WRITE;
        exclusive = 1;
    }
    flush_icache_page(fd->vma, page);
    set_pte_at(mm, fd->address, fd->page_table, pte);

    do_page_add_anon_rmap(page, fd->vma, fd->address, exclusive);
    inc_mm_counter(mm, MM_ANONPAGES);

    unlock_page(page);

    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }
    if (fd->flags & FAULT_FLAG_WRITE) {
        ret |= do_wp_dsm_page(fd->fault_svm, mm, fd->vma, fd->address, 
                fd->page_table, fd->pmd, ptl, pte, norm_addr);
        if (ret & VM_FAULT_ERROR)
            ret &= VM_FAULT_ERROR;
        goto out;
    }

    update_mmu_cache(fd->vma, fd->address, fd->page_table);
    atomic64_inc(&fd->fault_svm->svm_sysfs.stats.nb_page_request_success);
    pte_unmap_unlock(pte, ptl);
    goto out;

    out_nomap: pte_unmap_unlock(fd->page_table, ptl);
    out_page: unlock_page(page);
    page_cache_release(page);
    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }

    out: return ret;
}

static void dsm_page_fault_complete(struct tx_buf_ele *tx_e) {
    struct page_pool_ele *ppe = tx_e->wrk_req->dst_addr;
    struct dsm_fault_data *fd = tx_e->wrk_req->fault_data;
    struct dsm_page_cache *pc = fd->pc;
    int i;

    /*
     * First response to arrive resets the flag, and removes the struct pc
     *  from the dsm cache, to signal that action is over. We can also
     *  discard all the redundant pages we alloced.
     *
     *  TODO: Need a cheaper way to assert the flag than a spinlock here.
     *
     */
    spin_lock(&pc->lock);
    if (test_bit(DSM_CACHE_ACTIVE, &pc->flags)) {

        page_cache_release(ppe->mem_page);
        set_page_private(ppe->mem_page, 0);
        SetPageUptodate(ppe->mem_page);

        /*
         * No fd means this is the result of either a pull request (someone
         * pushed to us), or a prefetch; in these cases we don't need to set the
         * pte, simply unlock the updated page, and make sure we still have it 
         * in dsm cache.
         *
         */
        if (fd) {
            pc->fault_state = dsm_page_fault_success(ppe->mem_page, fd);
            dsm_cache_release(fd->fault_svm, fd->address);
        } else {
            unlock_page(ppe->mem_page);
        }

        for (i = 0; i < pc->npages; i++) {
            if (pc->pages[i] && pc->pages[i] != ppe->mem_page) {
                page_cache_release(pc->pages[i]);
                set_page_private(pc->pages[i], 0);
                SetPageUptodate(pc->pages[i]);

                unlock_page(pc->pages[i]);
                pc->pages[i] = NULL;
            }
        }

        clear_bit(DSM_CACHE_ACTIVE, &pc->flags);
    }
    spin_unlock(&pc->lock);

    /*
     * All pull requests returned, we can de-alloc the pc.
     *
     */
    if (!--pc->nproc)
        set_bit(DSM_CACHE_DISCARD, &pc->flags);

    ppe->mem_page = NULL;
}

static void dsm_try_page_fault_complete(struct tx_buf_ele *tx_e) {
    struct page_pool_ele *ppe = tx_e->wrk_req->dst_addr;
    struct dsm_fault_data *fd = tx_e->wrk_req->fault_data;
    struct dsm_page_cache *pc = fd->pc;
    struct dsm *dsm;
    struct page *page;
    struct mm_struct *mm;
    struct subvirtual_machine *local_svm;
    unsigned long addr;
    int i;

    /*
     * Pull try failed, no worries; release the page, and if all the requests
     * returned, release the pc.
     *
     */
    if (tx_e->dsm_msg->type == TRY_REQUEST_PAGE_FAIL) {
        printk("[signal_completion_try_page_request] request failed we release everything \n");

        /*
         * We need to discard this specific page, because the pull request
         * may never succeed.
         *
         */
        spin_lock(&pc->lock);
        if (test_bit(DSM_CACHE_ACTIVE, &pc->flags)) {
            for (i = 0; i < pc->npages; i++) {
                if (pc->pages[i] == ppe->mem_page) {
                    SetPageUptodate(pc->pages[i]);
                    unlock_page(pc->pages[i]);
                    page_cache_release(pc->pages[i]);
                    pc->pages[i] = NULL;
                    break;
                }
            }
        }

        /*
         * All pull requests returned, we can de-alloc the pc.
         *
         */
        if (!--pc->nproc)
            set_bit(DSM_CACHE_DISCARD, &pc->flags);

        spin_unlock(&pc->lock);
        atomic64_inc(&local_svm->svm_sysfs.stats.nb_page_pull_fail);

    } else {
        dsm_page_fault_complete(tx_e); 

        dsm = funcs->_find_dsm(tx_e->dsm_msg->dsm_id);
        BUG_ON(!dsm);
        local_svm = funcs->_find_svm(dsm, tx_e->dsm_msg->dest_id);
        BUG_ON(!local_svm);
        addr = tx_e->dsm_msg->req_addr + local_svm->priv->offset;

        /*
         * Get_user_pages for addr will trigger a page fault.
         */
        mm = local_svm->priv->mm;
        use_mm(mm);
        down_read(&mm->mmap_sem);
        get_user_pages(current, mm, addr, 1, 1, 0, &page, NULL);
        up_read(&mm->mmap_sem);
        unuse_mm(mm);
    }
}

static struct dsm_page_cache *get_remote_dsm_page(gfp_t gfp_mask, 
        struct vm_area_struct *vma, unsigned long addr, struct dsm *dsm, 
        u32 *svm_ids, struct subvirtual_machine *fault_svm, 
        unsigned long private, int tag, struct dsm_fault_data *fd) {

    struct dsm_page_cache *pc;
    struct page *new_page = NULL;
    int i;
    void (*func)(struct tx_buf_ele *);

    for (i = 0; svm_ids[i]; i++)
        ;
    pc = dsm_cache_add(fault_svm, addr, i, i, tag);
    if (!pc)
        goto fail;

    if (tag != TRY_TAG) {
        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_requested);
        func = dsm_page_fault_complete;
    } else {
        atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_pull);
        func = dsm_try_page_fault_complete;
    }

    for (i = 0; svm_ids[i]; i++) {
        new_page = alloc_page_vma(gfp_mask, vma, addr);
        if (!new_page)
            goto fail; /* Out of memory */

        __set_page_locked(new_page);
        page_cache_get(new_page);
        set_page_private(new_page, private);

        SetPageSwapBacked(new_page);
        mem_cgroup_reset_owner(new_page);
        lru_cache_add_anon(new_page);

        pc->pages[i] = new_page;

        if (fd)
            fd->pc = pc;
        funcs->request_dsm_page(new_page, svm_ids[i], fault_svm,
               (uint64_t) (addr - fault_svm->priv->offset), func, tag, fd);
    }

    fail: return pc;
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

static struct page *get_dsm_page(struct mm_struct *mm, unsigned long addr,
        struct subvirtual_machine *fault_svm, unsigned long private, int tag) {

    pte_t *pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct vm_area_struct *vma;
    unsigned long norm_addr = addr & PAGE_MASK;
    struct page *page = NULL;

    if (!dsm_cache_get(fault_svm, norm_addr)) {

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
                        struct dsm_vm_ids id = swp_entry_to_svm_ids(swp_e);

                        /*
                         * Fault_data NULLified, signals the callback that it
                         * doesn't need to set the pte, just store the page.
                         *
                         */
                        get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma,
                            norm_addr, id.dsm, id.svm_ids, fault_svm, private, 
                            tag, NULL);
                       atomic64_inc(&fault_svm->svm_sysfs.stats.nb_page_requested_prefetch);
                    }
                }
            }
        }
    }
    out:

    return page;
}

static struct dsm_fault_data *pack_fault_data(struct subvirtual_machine *svm,
        struct vm_area_struct *vma, unsigned long address, pte_t *page_table,
        pmd_t *pmd, unsigned int flags, pte_t orig_pte) {
    struct dsm_fault_data *fd = kmalloc(sizeof(struct dsm_fault_data), 
            GFP_KERNEL);    /* TODO: Use a slab allocator */
    fd->fault_svm = svm;
    fd->vma = vma;
    fd->address = address;
    fd->page_table = page_table;
    fd->pmd = pmd;
    fd->flags = flags;
    fd->orig_pte = orig_pte;
    return fd;
}

static int dsm_wait(void *word) {
    schedule();
    return 0;
}

static int do_dsm_page_fault(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd,
        unsigned int flags, pte_t orig_pte, swp_entry_t entry) {

    struct dsm_vm_ids id;
    struct subvirtual_machine *fault_svm;
//we need to use the page addr and not the fault address in order to have a unique reference
    unsigned long norm_addr = address & PAGE_MASK;
    spinlock_t *ptl;
    int ret = 0, i;
    struct dsm_page_cache *pc;
    struct dsm_fault_data *fault_data;

    printk("[do_dsm_page_fault] faulting for page %p , norm %p \n",
            (void*) address, (void*) norm_addr);

    if (!pte_unmap_dsm_same(mm, pmd, page_table, orig_pte))
        goto out;

    id = swp_entry_to_svm_ids(entry);
    fault_svm = find_local_svm(id.dsm, mm);
    BUG_ON(!fault_svm);

    fault_data = pack_fault_data(fault_svm, vma, address, page_table, pmd,
            flags, orig_pte);

    /*
     * Faulting for a page which is already in midst action. This could either
     * be a push or a prefetch, since we could not fault twice.
     *
     */ 
    pc = dsm_cache_get(fault_svm, norm_addr);
    if (pc && test_bit(DSM_CACHE_ACTIVE, &pc->flags)) {
        struct page *page = NULL;

        /*
         * Unfinished push, means page is still up to date.
         *
         */
        if (pc->tag == PUSH_TAG)
            page = pc->pages[0];

        /*
         * Tried to prefetch this page before; see if one of the requests
         * has already returned.
         *
         */
        else if (pc->tag == PREFETCH_TAG) {
            for (i = 0; i < pc->npages; i++) {
                if (pc->pages[i]) {
                    page = pc->pages[i];
                    break;
                }
            }
        }

        /*
         * Either we have the page, so we can end the process, or we want to
         * do a clean page fault from the beginning.
         *
         */
        dsm_cache_release(fault_svm, address);
        if (page) {
            fault_data->pc = pc;
            dsm_page_fault_success(page, fault_data);
            page_cache_release(page);
            goto prefetch;
        }

        /* Fallback ... */
    }

    pc = get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma, norm_addr,
        id.dsm, id.svm_ids, fault_svm, 0, PULL_TAG, fault_data);

    if (!pc) {
        page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
        ret = (likely(pte_same(*page_table, orig_pte))) ?
            VM_FAULT_OOM : VM_FAULT_MAJOR;
        pte_unmap_unlock(*page_table, ptl);
        goto out;
    }

    prefetch:
    /*
    for (i = 1; i < 40; i++) {
        get_dsm_page(mm, address + i * PAGE_SIZE, fault_svm, 0,
            PREFETCH_TAG);
    }
    */

    /*
     * Wait until first pull arrives successfully; then resolve page fault.
     * Note: pc cannot be de-alloced while we're waiting, since gc will reset
     * the flags and have another full iteration before de-allocing it.
     *
     */
    wait_on_bit(&pc->flags, DSM_CACHE_ACTIVE, dsm_wait, TASK_RUNNING);
    ret = pc->fault_state;

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

/*
 * TODO: Make sure we get a page back from get_dsm_page
 *
 */
struct page *dsm_trigger_page_pull(struct dsm *dsm, 
        struct subvirtual_machine *local_svm, unsigned long norm_addr) {
    struct page *page = NULL;
    struct mm_struct *mm;

    mm = local_svm->priv->mm;
    use_mm(mm);
    down_read(&mm->mmap_sem);
    page = get_dsm_page(mm, norm_addr, local_svm, ULONG_MAX, TRY_TAG);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);

    return page;
}
EXPORT_SYMBOL(dsm_trigger_page_pull);

