/*
 * drivers/dsm/dsm_push.c
 *
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include <dsm/dsm_core.h>
#include <dsm/dsm_trace.h>

#define DSM_CONGESTION_THRESHOLD 512 
static unsigned long congestion = 0;
inline int dsm_is_congested(void)
{
    trace_is_congested(congestion);
    return congestion > DSM_CONGESTION_THRESHOLD;
}

static inline void dsm_push_finish_notify(struct page *page)
{
    struct zone *zone = page_zone(page);
    wait_queue_head_t *waitqueue =
        &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
    rotate_reclaimable_page(page);
    ClearPageDirty(page);
    TestClearPageWriteback(page);
    __wake_up_bit(waitqueue, &page->flags, PG_writeback);
}

static int dsm_push_cache_add(struct dsm_page_cache *dpc,
        struct subvirtual_machine *svm, unsigned long addr)
{
    struct dsm_page_cache *rb_dpc;
    struct rb_node **new, *parent = NULL;
    int r = 0;

    write_seqlock(&svm->push_cache_lock);
    for (new = &svm->push_cache.rb_node; *new;) {
        rb_dpc = rb_entry(*new, struct dsm_page_cache, rb_node);
        parent = *new;
        BUG_ON(!rb_dpc);
        if (addr < rb_dpc->addr)
            new = &(*new)->rb_left;
        else if (addr > rb_dpc->addr)
            new = &(*new)->rb_right;
        else {
            r = -EEXIST;
            goto out;
        }
    }

    rb_link_node(&dpc->rb_node, parent, new);
    rb_insert_color(&dpc->rb_node, &svm->push_cache);

out:
    write_sequnlock(&svm->push_cache_lock);
    return r;
}

/* FIXME: push_cache lookup needs rcu protection */
static struct dsm_page_cache *dsm_push_cache_lookup(
        struct subvirtual_machine *svm, unsigned long addr)
{
    struct dsm_page_cache *dpc = NULL;
    struct rb_node *node;
    int seq;

    do {
        seq = read_seqbegin(&svm->push_cache_lock);
        for (node = svm->push_cache.rb_node; node; dpc = NULL) {
            dpc = rb_entry(node, struct dsm_page_cache, rb_node);
            BUG_ON(!dpc);
            if (addr < dpc->addr)
                node = node->rb_left;
            else if (addr > dpc->addr)
                node = node->rb_right;
            else
                break;
        }
    } while (read_seqretry(&svm->push_cache_lock, seq));

    return dpc;
}

static struct dsm_page_cache *dsm_push_cache_get(struct subvirtual_machine *svm,
        unsigned long addr, struct subvirtual_machine *remote_svm)
{
    struct rb_node *node;
    struct dsm_page_cache *dpc = NULL;
    int seq, i;

    BUG_ON(!svm);

    do {
        seq = read_seqbegin(&svm->push_cache_lock);
        for (node = svm->push_cache.rb_node; node; dpc = NULL) {
            dpc = rb_entry(node, struct dsm_page_cache, rb_node);
            BUG_ON(!dpc);
            if (addr < dpc->addr)
                node = node->rb_left;
            else if (addr > dpc->addr)
                node = node->rb_right;
            else
                break;
        }
    } while (read_seqretry(&svm->push_cache_lock, seq));

    if (likely(dpc) && remote_svm) {
        for (i = 0; i < dpc->svms.num; i++) {
            if (dpc->svms.pp[i] == remote_svm) {
                if (likely(test_and_clear_bit(i, &dpc->bitmap) &&
                        atomic_add_unless(&dpc->nproc, 1, 0))) {
                    goto out;
                }
                break;
            }
        }
        dpc = NULL;
    }

out: 
    return dpc;
}

inline void dsm_push_cache_release(struct subvirtual_machine *svm,
        struct dsm_page_cache **dpc, int lock)
{
    if (likely(lock)) {
        write_seqlock(&svm->push_cache_lock);
        rb_erase(&(*dpc)->rb_node, &svm->push_cache);
        write_sequnlock(&svm->push_cache_lock);
    } else {
        /* !lock only when traversing push_cache when removing svms */
        rb_erase(&(*dpc)->rb_node, &svm->push_cache);
    }
    if (likely((*dpc)->pages[0])) {
        page_cache_release((*dpc)->pages[0]);
        dsm_push_finish_notify((*dpc)->pages[0]);
    }
    dsm_dealloc_dpc(dpc);
    congestion--;
}

struct dsm_page_cache *dsm_push_cache_get_remove(struct subvirtual_machine *svm,
        unsigned long addr)
{
    struct dsm_page_cache *dpc;
    struct rb_node *node;

    write_seqlock(&svm->push_cache_lock);
    for (node = svm->push_cache.rb_node; node; dpc = 0) {
        dpc = rb_entry(node, struct dsm_page_cache, rb_node);
        if (addr < dpc->addr)
            node = node->rb_left;
        else if (addr > dpc->addr)
            node = node->rb_right;
        else
            break;
    }
    if (likely(dpc)) {
        rb_erase(&dpc->rb_node, &svm->push_cache);
        dpc->bitmap = 0;
    }
    write_sequnlock(&svm->push_cache_lock);

    return dpc;
}

int dsm_extract_pte_data(struct dsm_pte_data *pd, struct mm_struct *mm,
        unsigned long addr) 
{
    pd->pte = NULL;
    pd->vma = find_vma(mm, addr);
    if (unlikely(!pd->vma || pd->vma->vm_start > addr))
        return -1;

    pd->pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd_present(*(pd->pgd))))
        return -2;

    pd->pud = pud_offset(pd->pgd, addr);
    if (unlikely(!pud_present(*(pd->pud))))
        return -3;

    pd->pmd = pmd_offset(pd->pud, addr);
    if (unlikely(pmd_none(*(pd->pmd)))) {
        return -4;
    }
    if (unlikely(pmd_bad(*(pd->pmd)))) {
        pmd_clear_bad(pd->pmd);
        return -5;
    }

    if (unlikely(pmd_trans_huge(*(pd->pmd)))) {
        spin_lock(&mm->page_table_lock);
        if (likely(pmd_trans_huge(*(pd->pmd)))) {
            if (unlikely(pmd_trans_splitting(*(pd->pmd)))) {
                spin_unlock(&mm->page_table_lock);
                wait_split_huge_page(pd->vma->anon_vma, pd->pmd);
            } else {
                spin_unlock(&mm->page_table_lock);
                split_huge_page_pmd(pd->vma, addr, pd->pmd);
            }
        } else {
            spin_unlock(&mm->page_table_lock);
        }
    }
    pd->pte = pte_offset_map(pd->pmd, addr);
    return !pd->pte;
}

static struct subvirtual_machine *dsm_extract_handle_missing_pte(
        struct subvirtual_machine *local_svm, struct mm_struct *mm,
        unsigned long addr, pte_t pte_entry, struct dsm_pte_data *pd,
        int *redirect_id)
{
    swp_entry_t swp_e;
    struct dsm_swp_data dsd;
    struct dsm_page_cache *dpc =NULL;

    /* page could be swapped to disk */
    swp_e = pte_to_swp_entry(pte_entry);
    if (!non_swap_entry(swp_e))
        goto fail;

    if (is_migration_entry(swp_e)) {
        migration_entry_wait(mm, pd->pmd, addr);
        goto fail;
    }

    /* not a swap entry or a migration entry, must be ours */
    BUG_ON(!is_dsm_entry(swp_e));
    BUG_ON(swp_entry_to_dsm_data(swp_e, &dsd) < 0);

    /* we check if we are already pulling */
    dpc = dsm_cache_get(local_svm, addr);
    if (dpc)
        goto fail;

    /* FIXME: enable RRAIM support, rely on distributed directory */
    BUG_ON(dsd.svms.num != 1);
    return dsd.svms.pp[0];

    /* couldn't find a redirect, gup needed */
fail:
    return NULL;
}

int dsm_try_unmap_page(struct mm_struct *mm, unsigned long addr,
        struct subvirtual_machine *remote_svm)
{
    struct dsm_pte_data pd;
    struct page *page;
    spinlock_t *ptl;
    pte_t pte_entry;
    int r, release = 0;

    down_read(&mm->mmap_sem);

retry:
    r = dsm_extract_pte_data(&pd, mm, addr);
    if (unlikely(r)) {
        trace_extract_pte_data_err(r);
        goto out_mm;
    }

    pte_entry = *(pd.pte);
    pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
        pte_unmap_unlock(pd.pte, ptl);
        goto retry;
    }

    /* first access to page */
    if (pte_none(pte_entry)) {
        set_pte_at(mm, addr, pd.pte,
                dsm_descriptor_to_pte(remote_svm->descriptor, 0));
        goto out;
    }

    /* page already unmapped somewhere */
    if (unlikely(!pte_present(pte_entry))) {
        /* TODO: If pte isn't dsm, gup or defer_gup (it should be dsm); If pte
         * is dsm, validate descriptor == remote_dsm->descriptor
         */
        r = -EEXIST;
        goto out;
    }

    page = vm_normal_page(pd.vma, addr, pte_entry);
    if (!page) {
        /* DSM3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf */
        if (pte_pfn(*(pd.pte)) == (unsigned long) (void *) ZERO_PAGE(0))
            goto out;

        page = pte_page(*(pd.pte));
    }

    if (unlikely(PageTransHuge(page))) {
        if (!PageHuge(page) && PageAnon(page)) {
            pte_unmap_unlock(pd.pte, ptl);
            if (unlikely(split_huge_page(page)))
                goto out;
            goto retry;
        }
    }

    if (unlikely(PageKsm(page))) {
        pte_unmap_unlock(pd.pte, ptl);
        if (!dsm_initiate_fault(mm, addr, 1)) {
            r = -EFAULT;  /* DSM1 : better ksm error handling required. */
            goto out;
        }
    }

    flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
    ptep_clear_flush(pd.vma, addr, pd.pte);
    set_pte_at(mm, addr, pd.pte,
            dsm_descriptor_to_pte(remote_svm->descriptor, 0));

    page_remove_rmap(page);
    release = 1;
    dec_mm_counter(mm, MM_ANONPAGES);

out:
    pte_unmap_unlock(pd.pte, ptl);
    if (release) {
        mmu_notifier_invalidate_page(mm, addr);
        page_cache_release(page);
    }
out_mm:
    up_read(&mm->mmap_sem);
    return r;
}

/* mmap_sem already held for read */
static int dsm_initiate_fault_fast(struct mm_struct *mm, unsigned long addr)
{
    int r;

    use_mm(mm);
    r = get_user_pages(current, mm, addr, 1, 1, 0, NULL, NULL);
    unuse_mm(mm);

    BUG_ON(r > 1);
    return r == 1;
}

/* we arrive with mm semaphore held */
static struct page *dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm,
        unsigned long addr, pte_t *return_pte, u32 *svm_id, int deferred)
{
    spinlock_t *ptl;
    int r;
    struct page *page;
    struct dsm_pte_data pd;
    pte_t pte_entry;

retry:
    r = 0;
    page = NULL;
    r = dsm_extract_pte_data(&pd, mm, addr);
    if (unlikely(r)) {
        trace_extract_pte_data_err(r);
        if (likely(deferred && r != -1)) {
            if (dsm_initiate_fault_fast(mm, addr))
                goto retry;
        }
        goto out;
    }
    pte_entry = *(pd.pte);

    /* first time dealing with this addr? */
    if (pte_none(pte_entry)) {
        if (!dsm_initiate_fault_fast(mm, addr))
            goto out;
        goto retry;
    }

    pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
        pte_unmap_unlock(pd.pte, ptl);
        goto retry;
    }

    if (unlikely(!pte_present(pte_entry))) {
        struct subvirtual_machine *redirect_svm;

        redirect_svm = dsm_extract_handle_missing_pte(local_svm, mm, addr,
                pte_entry, &pd, svm_id);
        if (redirect_svm) {
            set_pte_at(mm, addr, pd.pte,
                    dsm_descriptor_to_pte(redirect_svm->descriptor, 0));
            *svm_id = redirect_svm->svm_id;
        } else if (deferred) {
            pte_unmap_unlock(pd.pte, ptl);
            if (!dsm_initiate_fault_fast(mm, addr))
                goto out;
            goto retry;
        }
        goto bad_page;
    }

    page = vm_normal_page(pd.vma, addr, *(pd.pte));
    if (!page) {
        /* DSM3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf */
        if (pte_pfn(*(pd.pte)) == (unsigned long) (void *) ZERO_PAGE(0))
            goto bad_page;

        page = pte_page(*(pd.pte));
    }

    if (unlikely(PageTransHuge(page))) {
        if (!PageHuge(page) && PageAnon(page)) {
            pte_unmap_unlock(pd.pte, ptl);
            if (unlikely(split_huge_page(page)))
                goto bad_page;
            goto retry;
        }
    }

    if (unlikely(PageKsm(page))) {
        pte_unmap_unlock(pd.pte, ptl);
        if (!dsm_initiate_fault_fast(mm, addr))
            goto out;
        goto retry;
    }


    page_cache_get(page);

    flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
    ptep_clear_flush(pd.vma, addr, pd.pte);
    set_pte_at(mm, addr, pd.pte,
            dsm_descriptor_to_pte(remote_svm->descriptor, DSM_INFLIGHT));

    page_remove_rmap(page);
    dec_mm_counter(mm, MM_ANONPAGES);

    *return_pte = *(pd.pte);

    pte_unmap_unlock(pd.pte, ptl);
    mmu_notifier_invalidate_page(mm, addr);
    page_cache_release(page);
out: 
    return page;
    
bad_page: 
    pte_unmap_unlock(pd.pte, ptl);
    return NULL;
}

static struct page *try_dsm_extract_page(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, struct mm_struct *mm,
        unsigned long addr, pte_t *return_pte)
{
    struct page *page;
    struct dsm_page_cache *dpc = NULL;
    pte_t pte_entry;
    struct dsm_pte_data pd;
    int clear_pte_flag = 0;
    spinlock_t *ptl = NULL;

retry:
    page = NULL;
    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        goto out;

    pte_entry = *(pd.pte);
    if (likely(!dpc)) {
        dpc = dsm_push_cache_get(local_svm, addr, remote_svm);
        if (unlikely(!dpc))
            goto out;
    }

    page = dpc->pages[0];
    BUG_ON(!page);

    /* first response to arrive and grab the pte lock */
    if (pte_present(pte_entry)) {
        u32 pte_flag = 0;

        /* make sure shrink_page_list is finished with this page */
        lock_page(page);
        pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (unlikely(!pte_same(*(pd.pte), pte_entry))) {
            unlock_page(page);
            pte_unmap_unlock(pd.pte, ptl);
            goto retry;
        }

        flush_cache_page(pd.vma, addr, pte_pfn(*(pd.pte)));
        ptep_clear_flush(pd.vma, addr, pd.pte);
        if (dpc->svms.num > 1) {
            pte_flag = DSM_PUSHING;
            clear_pte_flag = 1; /* race condition */
        }
        set_pte_at(mm, addr, pd.pte, dsm_descriptor_to_pte(dpc->tag, pte_flag));
        page_remove_rmap(page);
        dec_mm_counter(mm, MM_ANONPAGES);
        pte_unmap_unlock(pd.pte, ptl);
        mmu_notifier_invalidate_page(mm, addr);
        page_cache_release(page);
        unlock_page(page);

    /* racing with the first response */
    } else if (unlikely(pte_none(pte_entry))) {
        goto retry;

    /* signal that this is not the first response */
    } else {
        clear_pte_flag = 1;
    }

    atomic_dec(&dpc->nproc);
    if (find_first_bit(&dpc->bitmap, dpc->svms.num) >= dpc->svms.num &&
            atomic_cmpxchg(&dpc->nproc, 1, 0) == 1) {
        if (clear_pte_flag)
            dsm_clear_swp_entry_flag(mm, addr, *(pd.pte), DSM_PUSHING_BITPOS);
        dsm_push_cache_release(local_svm, &dpc, 1);
    }

    *return_pte = *(pd.pte);

out:
    return page;
}

struct page *dsm_extract_page_from_remote(struct subvirtual_machine *local_svm,
        struct subvirtual_machine *remote_svm, unsigned long addr, u16 tag,
        pte_t *pte, u32 *svm_id, int deferred)
{
    struct mm_struct *mm;
    struct page *page = NULL;

    BUG_ON(!local_svm);

    mm = local_svm->mm;
    BUG_ON(!mm);

    down_read(&mm->mmap_sem);
    page = (tag == TRY_REQUEST_PAGE)?
        try_dsm_extract_page(local_svm, remote_svm, mm, addr, pte) : 
        dsm_extract_page(local_svm, remote_svm, mm, addr, pte, svm_id,
                deferred);
    up_read(&mm->mmap_sem);

    return page;
}

/* this function is purely for development, used in the PUSH ioctl */
struct page *dsm_find_normal_page(struct mm_struct *mm, unsigned long addr)
{
    struct page *page = NULL;
    struct dsm_pte_data pd;
    pte_t pte_entry, *pte;
    spinlock_t *ptl;

    if (dsm_extract_pte_data(&pd, mm, addr))
        goto out;

    pte_entry = *(pd.pte);
    if (!pte_present(pte_entry))
        goto out;

retry:
    pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (!pte_same(*pte, pte_entry)) {
        pte_unmap_unlock(pte, ptl);
        goto retry;
    }
    page = vm_normal_page(pd.vma, addr, *pte);
    pte_unmap_unlock(pte, ptl);

out:
    return page;
}

int dsm_prepare_page_for_push(struct subvirtual_machine *local_svm,
        struct svm_list svms, struct page *page, unsigned long addr,
        struct mm_struct *mm, u32 descriptor)
{
    struct dsm_pte_data pd;
    struct dsm_page_cache *dpc = NULL;
    pte_t pte_entry, *pte;
    spinlock_t *ptl;
    int i, r;

    BUG_ON(!local_svm);

    /*
     * We only change pte when the first response returns, in order to keep the
     * page accessible; therefore someone might ask us to re-push a page before
     * any response has even returned.
     */
    if (dsm_push_cache_lookup(local_svm, addr))
        return -EEXIST;


    dpc = dsm_alloc_dpc(local_svm, addr, svms, 1, descriptor);
    if (unlikely(!dpc))
        return -ENOMEM;
retry:
    /* we're trying to swap out an active page, everything should be here */
    /* we lock the pte to avoid racing with an incoming page request */
    dsm_extract_pte_data(&pd, mm, addr);
    BUG_ON(!pd.pte);
    pte_entry = *(pd.pte);
    if (unlikely(!pte_present(pte_entry)))
        goto bad_page;

    pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*pte, pte_entry))) {
        pte_unmap_unlock(pte, ptl);
        goto retry;
    }

    if (unlikely(PageTransHuge(page) && !PageHuge(page) && PageAnon(page))) {
        if (unlikely(split_huge_page(page)))
            goto bad_page_unlock;
    }

    if (unlikely(PageKsm(page))) {
        pte_unmap_unlock(pd.pte, ptl);
        if (!dsm_initiate_fault(mm, addr, 1))
            goto bad_page;
        goto retry;
    }

    r = dsm_push_cache_add(dpc, local_svm, addr);
    if (unlikely(r))
        goto bad_page_unlock;

    dpc->bitmap = 0;
    dpc->pages[0] = page;

    /*
     * refcount is as follows:
     *  1 for being in dpc (released upon dealloc)
     *  1 for every svm sent to (released on dsm_ppe_clear_release)
     */
    page_cache_get(page);
    for_each_valid_svm(svms, i) {
        page_cache_get(page);
        dpc->bitmap += (1 << i);
    }

    /*
     * PageWriteback signals shrink_page_list it can either synchronously wait
     * for op to complete, or just ignore the page and continue. It also gives
     * __isolate_lru_page a chance to bail.
     */
    SetPageDirty(page);
    TestSetPageWriteback(page);

    pte_unmap_unlock(pte, ptl);
    congestion++;
    return 0;
    
bad_page_unlock:
    pte_unmap_unlock(pte, ptl);
bad_page:
    dsm_dealloc_dpc(&dpc);

    return -EFAULT;
}

int dsm_cancel_page_push(struct subvirtual_machine *svm, unsigned long addr,
        struct page *page)
{
    struct dsm_page_cache *dpc = dsm_push_cache_get(svm, addr, NULL);
    int i;

    if (unlikely(!dpc))
        return -1;

    for_each_valid_svm(dpc->svms, i)
        page_cache_release(page);
    dsm_push_cache_release(svm, &dpc, 1);

    return 0;
}

/*
 * Return 0 => page dsm or not dsm_remote => try to swap out
 * Return 1 => page is dsm => do not swap out (not necessarily scheduled yet to
 *             be pushed back, could also be done in next cycle)
 */
static int _push_back_if_remote_dsm_page(struct page *page)
{
    struct anon_vma *anon_vma;
    pgoff_t pgoff;
    struct anon_vma_chain *avc;
    int ret = 0;

    if (unlikely(!get_dsm_module_state()))
        goto out;

    /* don't push pages that belong to more than one process, avoid pitfalls */
    if (page_mapcount(page) > 1)
        goto out;

    anon_vma = page_lock_anon_vma_read(page);
    if (!anon_vma)
        goto out;

    /* note: should actually find only one relevant vma */
    pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
    anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff, pgoff) {
        struct vm_area_struct *vma = avc->vma;
        unsigned long address;
        struct subvirtual_machine *svm;
        struct memory_region *mr;

        address = page_address_in_vma(page, vma);
        if (address == -EFAULT)
            continue;

        svm = find_local_svm(vma->vm_mm);
        if (!svm)
            continue;

        /* lookup a remote mr owner, to push the page to */
        mr = search_mr(svm, address);
        if (!mr || mr->local == DSM_LOCAL_MR) {
            release_svm(svm);
            continue;
        }

        dsm_request_page_pull(svm->dsm, svm, page, address, vma->vm_mm, mr);

        release_svm(svm);
        if (PageSwapCache(page))
            try_to_free_swap(page);

        ret = 1;
        break;
    }

    page_unlock_anon_vma_read(anon_vma);
out:
    return ret;
}

int push_back_if_remote_dsm_page(struct page *page)
{
    return _push_back_if_remote_dsm_page(page);
}

/* no locks are held when calling this function */
int dsm_flag_page_remote(struct mm_struct *mm, struct dsm *dsm, u32 descriptor,
        unsigned long request_addr)
{
    spinlock_t *ptl;
    pte_t *pte;
    int r = 0, release = 0;
    struct page *page = 0;
    struct vm_area_struct *vma;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    unsigned long addr = request_addr & PAGE_MASK;

    down_read(&mm->mmap_sem);

retry:
    r = 0;
    vma = find_vma(mm, addr);
    if (unlikely(!vma || vma->vm_start > addr)) {
        printk("[dsm_flag_page_remote] no vma \n");
        goto out;
    }

    // ksm_flag = vma->vm_flags & VM_MERGEABLE;

    pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd_present(*pgd))) {
        if (!dsm_initiate_fault(mm, addr, 1)) {
            printk("[dsm_flag_page_remote] no pgd\n");
            r = -EFAULT;
            goto out;
        }
        goto retry;
    }

    pud = pud_offset(pgd, addr);
    if (unlikely(!pud_present(*pud))) {
        if (!dsm_initiate_fault(mm, addr, 1)) {
            printk("[dsm_flag_page_remote] no pud\n");
            r = -EFAULT;
            goto out;
        }
        goto retry;
    }

    pmd = pmd_offset(pud, addr);
    if (unlikely(pmd_none(*pmd))) {
        __pte_alloc(mm, vma, pmd, addr);
        goto retry;
    }
    if (unlikely(pmd_bad(*pmd))) {
        pmd_clear_bad(pmd);
        printk("[dsm_flag_page_remote] bad pmd \n");
        goto out;
    }
    if (unlikely(pmd_trans_huge(*pmd))) {
        spin_lock(&mm->page_table_lock);
        if (likely(pmd_trans_huge(*pmd))) {
            if (unlikely(pmd_trans_splitting(*pmd))) {
                spin_unlock(&mm->page_table_lock);
                wait_split_huge_page(vma->anon_vma, pmd);
            } else {
                spin_unlock(&mm->page_table_lock);
                split_huge_page_pmd(vma, addr, pmd);
            }
        } else {
            spin_unlock(&mm->page_table_lock);
        }
    }

    // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock
    pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
    pte_entry = *pte;

    if (!pte_present(pte_entry)) {
        if (pte_none(pte_entry)) {
            set_pte_at(mm, addr, pte, dsm_descriptor_to_pte(descriptor, 0));
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
                if (!dsm_initiate_fault(mm, addr, 1)) {
                    printk("[*] failed at faulting \n");
                    r = -EFAULT;
                    goto out;
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
    if (PageTransHuge(page)) {
        printk("[*] we have a huge page \n");
        if (!PageHuge(page) && PageAnon(page)) {
            if (unlikely(split_huge_page(page))) {
                printk("[*] failed at splitting page \n");
                goto out;
            }
        }
    }
    if (PageKsm(page)) {
        printk("[dsm_flag_page_remote] KSM page\n");
        pte_unmap_unlock(pte, ptl);
        if (!dsm_initiate_fault(mm, addr, 1)) {
            printk("[dsm_extract_page] ksm_madvise ret : %d\n", r);
            // DSM1 : better ksm error handling required.
            r = -EFAULT;
            goto out;
        }
        goto retry;
    }

    if (!trylock_page(page)) {
        printk("[dsm_flag_page_remote] coudln't lock page \n");
        r = -EFAULT;
        goto out_pte_unlock;
    }

    flush_cache_page(vma, addr, pte_pfn(*pte));
    ptep_clear_flush(vma, addr, pte);
    set_pte_at(mm, addr, pte, dsm_descriptor_to_pte(descriptor, 0));
    page_remove_rmap(page);

    dec_mm_counter(mm, MM_ANONPAGES);

    // this is a page flagging without data exchange so we can free the page

    unlock_page(page);
    release = 1;

out_pte_unlock:
    pte_unmap_unlock(pte, ptl);
    if (release) {
        mmu_notifier_invalidate_page(mm, addr);
        page_cache_release(page);
    }
out:
    up_read(&mm->mmap_sem);
    return r;
}

