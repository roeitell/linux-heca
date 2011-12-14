/*
 * page_fault.c
 *
 *  Created on: 1 Aug 2011
 *      Author: john
 */

#include <dsm/dsm_mem.h>
#include <dsm/dsm_module.h>

RADIX_TREE(dsm_tree, GFP_ATOMIC);
DEFINE_SPINLOCK(dsm_lock);

unsigned long zero_dsm_pfn __read_mostly;

static int __init init_dsm_zero_pfn(void)
 {
         zero_dsm_pfn = page_to_pfn(ZERO_PAGE(0));
         return 0;
 }
core_initcall(init_dsm_zero_pfn);

void signal_completion_page_request(struct tx_buf_ele * tx_e) {
    struct page_pool_ele * ppe = tx_e->wrk_req->dst_addr;
    BUG_ON(!ppe);
    BUG_ON(!ppe->mem_page);

    set_page_private(ppe->mem_page, 0);
    SetPageUptodate(ppe->mem_page);
    unlock_page(ppe->mem_page);
    ppe->mem_page = NULL;
    return;

}

void signal_completion_try_page_request(struct tx_buf_ele * tx_e) {
    struct page * page;
    struct mm_struct *mm;
    struct dsm_vm_id local_id;
    struct subvirtual_machine *local_svm;
    unsigned long addr;

    struct page_pool_ele * ppe = tx_e->wrk_req->dst_addr;
    BUG_ON(!ppe);
    BUG_ON(!ppe->mem_page);

    local_id.dsm_id = u32_to_dsm_id(tx_e->dsm_msg->dest);
    local_id.svm_id = u32_to_vm_id(tx_e->dsm_msg->dest);
    local_svm = funcs->_find_svm(&local_id);
    BUG_ON(!local_svm);
    addr = tx_e->dsm_msg->req_addr + local_svm->priv->offset;
    if (tx_e->dsm_msg->type == TRY_REQUEST_PAGE_FAIL) {
        delete_from_dsm_cache(ppe->mem_page, addr);
        SetPageUptodate(ppe->mem_page);
        unlock_page(ppe->mem_page);
        return;
    } else {
        set_page_private(ppe->mem_page, 0);
        SetPageUptodate(ppe->mem_page);
        unlock_page(ppe->mem_page);
        ppe->mem_page = NULL;
        mm = local_svm->priv->mm;
        use_mm(mm);
        down_read(&mm->mmap_sem);
        get_user_pages(current, mm, addr, 1, 1, 0, &page, NULL);
        up_read(&mm->mmap_sem);
        unuse_mm(mm);
    }

}

int delete_from_dsm_cache(struct page *page, unsigned long addr) {

    int ret = 1;
    VM_BUG_ON(!PageLocked(page));

    spin_lock_irq(&dsm_lock);
    if (unlikely(!radix_tree_delete(&dsm_tree, addr)))
        ret = 0;
    else
        page_cache_release(page);

    spin_unlock_irq(&dsm_lock);
    return ret;
}

static int __add_to_dsm_cache(struct page *page, unsigned long addr,
        unsigned long private, int tag) {
    int error;

    VM_BUG_ON(!PageLocked(page));

    page_cache_get(page);
    set_page_private(page, private);

    spin_lock_irq(&dsm_lock);
    error = radix_tree_insert(&dsm_tree, addr, page);
    if ((!error) && (tag < RADIX_TREE_MAX_TAGS))
        radix_tree_tag_set(&dsm_tree, addr, tag);

    spin_unlock_irq(&dsm_lock);

    if (unlikely(error)) {
        VM_BUG_ON(error == -EEXIST);
        set_page_private(page, 0UL);
        page_cache_release(page);
    }

    return error;
}

static void dsm_readpage(struct page* page, unsigned long addr,
        struct subvirtual_machine *svm, struct subvirtual_machine *fault_svm) {
    VM_BUG_ON(!PageLocked(page));
    VM_BUG_ON(PageUptodate(page));
    funcs->request_dsm_page(
            page,
            svm,
            fault_svm,
            (uint64_t) (addr - fault_svm->priv->offset), signal_completion_page_request, 0)
            ;
}

static void dsm_try_readpage(struct page* page, unsigned long addr,
        struct subvirtual_machine *svm, struct subvirtual_machine *fault_svm) {
    VM_BUG_ON(!PageLocked(page));
    VM_BUG_ON(PageUptodate(page));
    funcs->request_dsm_page(
            page,
            svm,
            fault_svm,
            (uint64_t) (addr - fault_svm->priv->offset), signal_completion_try_page_request, 1)
            ;

}

static struct page * get_remote_dsm_page(gfp_t gfp_mask,
        struct vm_area_struct *vma, unsigned long addr,
        struct subvirtual_machine *svm, struct subvirtual_machine *fault_svm,
        unsigned long private, int tag) {

    struct page *found_page, *new_page = NULL;
    int err;

    do {

        found_page = find_get_dsm_page(addr);
        if (found_page)
            break;

        if (!new_page) {
            new_page = alloc_page_vma(gfp_mask, vma, addr);
            if (!new_page)
                break; /* Out of memory */
        }

        err = radix_tree_preload(gfp_mask & GFP_KERNEL);
        if (err)
            break;

        __set_page_locked(new_page);

        err = __add_to_dsm_cache(new_page, addr, private, tag);
        if (likely(!err)) {
            radix_tree_preload_end();

            lru_cache_add_anon(new_page);
            if (tag != TRY_TAG
            )
                dsm_readpage(new_page, addr, svm, fault_svm);

            else
                dsm_try_readpage(new_page, addr, svm, fault_svm);
            return new_page;
        }
        radix_tree_preload_end();
        __clear_page_locked(new_page);
    } while (err != -ENOMEM);

    if (new_page)
        page_cache_release(new_page);
    if (tag == TRY_TAG
    )
        return NULL;
    else
        return found_page;

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
static int reuse_dsm_page(struct page * page, unsigned long addr) {
    int count;

    VM_BUG_ON(!PageLocked(page));
    if (unlikely(PageKsm(page)))
        return 0;
    count = page_mapcount(page);
    if (count == 0 && !PageWriteback(page)) {
        delete_from_dsm_cache(page, addr);
        set_page_private(page, 0);
        if (!PageSwapBacked(page))
            SetPageDirty(page);
    }

    return count <= 1;
}

static inline int is_dsm_zero_pfn(unsigned long pfn) {
    return pfn == zero_dsm_pfn;
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

static int do_wp_dsm_page(struct mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl,
        pte_t orig_pte, unsigned long norm_address) __releases(ptl)
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
        if (reuse_dsm_page(old_page, norm_address)) {
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
        get_page(dirty_page);

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

static struct page * get_dsm_page(struct mm_struct *mm, unsigned long addr,
        struct subvirtual_machine *fault_svm, unsigned long private, int tag) {

    pte_t *pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct vm_area_struct *vma;
    unsigned long norm_addr = addr & PAGE_MASK;
    struct subvirtual_machine *svm;
    struct dsm_vm_id id;

    if (!find_get_dsm_page(norm_addr)) {

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
                        dsm_entry_to_val(swp_e, &id.dsm_id, &id.svm_id);
                        svm = funcs->_find_svm(&id);
                        BUG_ON(!svm);
                        return get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma,
                                norm_addr, svm, fault_svm, private, tag);
                    }
                }
            }
        }
    }
    out:

    return NULL;
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
    struct page *page, *swapcache = NULL;
    int exclusive = 0;
    int i;
    pte_t pte;
    int locked;

    printk("[request_page_insert] faulting for page %p , norm %p \n ",
            (void*) address, (void*) norm_addr);
    retry:

    if (!pte_unmap_dsm_same(mm, pmd, page_table, orig_pte))
        goto out;

    page = find_get_dsm_page(norm_addr);
    if (!page) {
        dsm_entry_to_val(entry, &id.dsm_id, &id.svm_id);
        svm = funcs->_find_svm(&id);
        BUG_ON(!svm);

        fault_svm = funcs->_find_local_svm(svm->id.dsm_id, mm);
        BUG_ON(!fault_svm);

        page = get_remote_dsm_page(GFP_HIGHUSER_MOVABLE, vma, norm_addr, svm,
                fault_svm, 0, RADIX_TREE_MAX_TAGS);

        if (!page) {
            page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (likely(pte_same(*page_table, orig_pte)))
                ret = VM_FAULT_OOM;
            goto unlock;
        }
        ret = VM_FAULT_MAJOR;
        for (i = 1; i < 40; i++)
            get_dsm_page(mm, address + i * PAGE_SIZE
            , fault_svm, 0, PREFETCH_TAG);
    }

    locked = lock_page_or_retry(page, mm, flags);
    if (!locked) {
        ret |= VM_FAULT_RETRY;
        goto out;
    }
    if (unlikely(page_private(page) == ULONG_MAX))
        if (page_is_tagged_in_dsm_cache(norm_addr, TRY_TAG))
            goto rebelote;

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

    page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
    if (unlikely(!pte_same(*page_table, orig_pte)))
        goto out_nomap;

    dsm_stats_page_fault_update(NULL);
    if (unlikely(!PageUptodate(page))) {
        ret = VM_FAULT_SIGBUS;
        goto out_nomap;
    }
    inc_mm_counter(mm, MM_ANONPAGES);
    pte = mk_pte(page, vma->vm_page_prot);
    if (likely(reuse_dsm_page(page, norm_addr))) {
//we should pretty much always get in there unless we read fault
        pte = maybe_mkwrite(pte_mkdirty(pte), vma);
        flags &= ~FAULT_FLAG_WRITE;
        ret |= VM_FAULT_WRITE;
        exclusive = 1;
    }
    flush_icache_page(vma, page);
    set_pte_at(mm, address, page_table, pte);
    do_page_add_anon_rmap(page, vma, address, exclusive);

    unlock_page(page);

    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }
    if ((flags & FAULT_FLAG_WRITE)) {
        ret |= do_wp_dsm_page(mm, vma, address, page_table, pmd, ptl, pte,
                norm_addr);
        if (ret & VM_FAULT_ERROR)
            ret &= VM_FAULT_ERROR;
        goto out;
    }
    update_mmu_cache(vma, address, page_table);
    printk("[request_page_insert] page fault success \n ");
    unlock: pte_unmap_unlock(pte, ptl);
    out: return ret;

    out_nomap: pte_unmap_unlock(page_table, ptl);
    out_page: unlock_page(page);
    page_cache_release(page);
    if (swapcache) {
        unlock_page(swapcache);
        page_cache_release(swapcache);
    }
    return ret;
    rebelote: unlock_page(page);
    page_cache_release(page);
    goto retry;
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

struct page *find_get_dsm_page(unsigned long addr) {
    void **pagep;
    struct page *page;

    rcu_read_lock();
    repeat: page = NULL;
    pagep = radix_tree_lookup_slot(&dsm_tree, addr);
    if (pagep) {
//NEED TO BE UPDATED TO 3.1
        page = radix_tree_deref_slot(pagep);
        if (unlikely(!page))
            goto out;
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

int add_page_pull_to_dsm_cache(struct page * page, unsigned long addr,
        gfp_t gfp_mask) {
    int err = radix_tree_preload(gfp_mask & GFP_KERNEL);

    if (err)
        return err;
    err = __add_to_dsm_cache(page, addr, 0, PULL_TAG);
    radix_tree_preload_end();
    return err;
}

int page_is_tagged_in_dsm_cache(unsigned long addr, int tag) {

    int res;

    rcu_read_lock();
    res = radix_tree_tag_get(&dsm_tree, addr, tag);
    rcu_read_unlock();

    return res;

}

struct page * page_is_in_dsm_cache(unsigned long addr) {

    void **pagep;
    struct page *page;

    rcu_read_lock();
    repeat: page = NULL;
    pagep = radix_tree_lookup_slot(&dsm_tree, addr);
    if (pagep) {
        //NEED TO BE UPDATED TO 3.1
        page = radix_tree_deref_slot(pagep);
        if (unlikely(!page))
            goto out;
        if (radix_tree_deref_retry(page))
            goto repeat;

    }
    out: rcu_read_unlock();

    return page;

}
EXPORT_SYMBOL(page_is_in_dsm_cache);

struct page *dsm_trigger_page_pull(struct dsm_message *msg) {

    struct dsm_vm_id local_id;
    struct subvirtual_machine *local_svm = NULL;
    struct page *page = NULL;
    unsigned long norm_addr;
    struct mm_struct *mm;

    local_id.dsm_id = u32_to_dsm_id(msg->src);
    local_id.svm_id = u32_to_vm_id(msg->src);
    local_svm = funcs->_find_svm(&local_id);
    BUG_ON(!local_svm);

    norm_addr = msg->req_addr + local_svm->priv->offset;

    mm = local_svm->priv->mm;
    use_mm(mm);
    down_read(&mm->mmap_sem);
    page = get_dsm_page(mm, norm_addr, local_svm, ULONG_MAX, TRY_TAG);
    up_read(&mm->mmap_sem);
    unuse_mm(mm);
    return page;
}
EXPORT_SYMBOL(dsm_trigger_page_pull);

