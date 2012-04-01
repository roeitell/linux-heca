/*
 * dsm_unmap.c
 *
 *  Created on: 1 Aug 2011
 *      Author: Benoit
 */

#include <dsm/dsm_core.h>

struct dsm_functions *funcs;

void reg_dsm_functions(
        struct dsm *(*_find_dsm)(u32 dsm_id),
        struct subvirtual_machine *(*_find_svm)(struct dsm* dsm, u32 svm_id),
        struct subvirtual_machine *(*_find_local_svm)(struct dsm *,
                struct mm_struct *),
        int(*request_dsm_page)(struct page *, struct subvirtual_machine *, 
                struct subvirtual_machine *, uint64_t, 
                int(*func)(struct tx_buf_ele *), int, 
                struct dsm_page_cache *)) {

    funcs = kmalloc(sizeof(*funcs), GFP_KERNEL);
    funcs->_find_dsm = _find_dsm;
    funcs->_find_svm = _find_svm;
    funcs->_find_local_svm = _find_local_svm;
    funcs->request_dsm_page = request_dsm_page;
}
EXPORT_SYMBOL(reg_dsm_functions);

void dereg_dsm_functions(void) {
    kfree(funcs);
}
EXPORT_SYMBOL(dereg_dsm_functions);

int dsm_flag_page_remote(struct mm_struct *mm, struct dsm *dsm, u32 descriptor,
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
    unsigned long addr = request_addr & PAGE_MASK;

    down_read(&mm->mmap_sem);

    retry:

    vma = find_vma(mm, addr);
    if (unlikely(!vma || vma->vm_start > addr)) {
        printk("[dsm_flag_page_remote] no VMA or bad VMA \n");
        goto out;
    }

    // ksm_flag = vma->vm_flags & VM_MERGEABLE;

    pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd_present(*pgd))) {
        printk("[dsm_flag_page_remote] no pgd \n");
        goto out;
    }

    pud = pud_offset(pgd, addr);
    if (unlikely(!pud_present(*pud))) {
        printk("[dsm_flag_page_remote] no pud \n");
        goto out;
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
        if (unlikely(pmd_trans_splitting(*pmd))) {
            spin_unlock(&mm->page_table_lock);
            wait_split_huge_page(vma->anon_vma, pmd);
        } else {
            spin_unlock(&mm->page_table_lock);
            split_huge_page_pmd(mm, pmd);
        }

    }

    // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock
    pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
    pte_entry = *pte;

    if (!pte_present(pte_entry)) {
        if (pte_none(pte_entry)) {
            set_pte_at(mm, addr, pte, swp_entry_to_pte(
                dsm_descriptor_to_swp_entry(descriptor, 0)));
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
                r = handle_mm_fault(mm, vma, addr, FAULT_FLAG_WRITE);
                if (r & VM_FAULT_ERROR) {
                    printk("[*] failed at faulting \n");
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

        r = ksm_madvise(vma, request_addr, request_addr + PAGE_SIZE,
        MADV_UNMERGEABLE, &vma->vm_flags);

        if (r) {
            printk("[dsm_extract_page] ksm_madvise ret : %d\n", r);

            // DSM1 : better ksm error handling required.
            return -EFAULT;
        }
    }

    if (!trylock_page(page)) {
        printk("[dsm_flag_page_remote] coudln't lock page \n");
        r = -EFAULT;
        goto out_pte_unlock;
    }

    flush_cache_page(vma, addr, pte_pfn(*pte));
    ptep_clear_flush_notify(vma, addr, pte);
    set_pte_at(mm, addr, pte, swp_entry_to_pte(dsm_descriptor_to_swp_entry( 
            descriptor, 0)));
    page_remove_rmap(page);

    dec_mm_counter(mm, MM_ANONPAGES);

    // this is a page flagging without data exchange so we can free the page
    if (likely(!page_mapped(page)))
        try_to_free_swap(page);

    unlock_page(page);
    put_page(page);

    out_pte_unlock: pte_unmap_unlock(pte, ptl);

    out: up_read(&mm->mmap_sem);
    return r;
}
EXPORT_SYMBOL(dsm_flag_page_remote);

int dsm_try_push_page(struct dsm *dsm, struct subvirtual_machine *local_svm,
        struct mm_struct *mm, u32 descriptor, struct svm_list svms,
        unsigned long addr) {

    spinlock_t *ptl;
    pte_t *pte;
    int r = 0, ret = 0;
    struct page *page = NULL;
    struct vm_area_struct *vma;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t pte_entry;
    swp_entry_t swp_e;
    struct dsm_page_cache *dpc;

    /*
    printk("[dsm_try_push_page] trying to push back page %p \n ", (void*) addr);
    */

    retry: vma = find_vma(mm, addr);
    if (unlikely(!vma || vma->vm_start > addr)) {
        printk("[dsm_try_push_page] no VMA or bad VMA \n");
        goto out;
    }

    pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd_present(*pgd))) {
        printk("[dsm_try_push_page] no pgd \n");
        goto out;
    }

    pud = pud_offset(pgd, addr);
    if (unlikely(!pud_present(*pud))) {
        printk("[dsm_try_push_page] no pud \n");
        goto out;
    }

    pmd = pmd_offset(pud, addr);
    if (unlikely(pmd_none(*pmd))) {
        printk("[dsm_try_push_page] no pmd error \n");
        goto out;
    }

    if (unlikely(pmd_bad(*pmd))) {
        pmd_clear_bad(pmd);
        printk("[dsm_try_push_page] bad pmd \n");
        goto out;
    }
    if (unlikely(pmd_trans_huge(*pmd))) {
        printk("[dsm_try_push_page] we have a huge pmd \n");
        spin_lock(&mm->page_table_lock);
        if (unlikely(pmd_trans_splitting(*pmd))) {
            spin_unlock(&mm->page_table_lock);
            wait_split_huge_page(vma->anon_vma, pmd);
        } else {
            spin_unlock(&mm->page_table_lock);
            split_huge_page_pmd(mm, pmd);
        }
        goto retry;
    }

    // we need to lock the tree before locking the pte because in page insert we do it in the same order => avoid deadlock
    pte = pte_offset_map(pmd, addr);
    pte_entry = *pte;
    if (unlikely(!pte_present(pte_entry))) {
        if (!pte_none(pte_entry)) {
            swp_e = pte_to_swp_entry(pte_entry);
            if (non_swap_entry(swp_e)) {
                if (is_migration_entry(swp_e)) {
                    migration_entry_wait(mm, pmd, addr);
                    goto retry;
                }
            }
        }
        printk(
                "[dsm_try_push_page] the pte is not present in the first place.. we exit \n");
        goto out;
    }

    pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (unlikely(!pte_same(*pte, pte_entry))) {
        pte_unmap_unlock(pte, ptl);
        goto retry;
    }
    page = vm_normal_page(vma, addr, *pte);
    if (!page) {
        // DSM3 : follow_page uses - goto bad_page; when !ZERO_PAGE..? wtf
        if (pte_pfn(*pte) == (unsigned long) (void *) ZERO_PAGE(0))
            goto bad_page;
        page = pte_page(*pte);
    }

    if (unlikely(PageTransHuge(page))) {
        printk("[dsm_try_push_page] we have a huge page \n");
        if (!PageHuge(page) && PageAnon(page)) {
            if (unlikely(split_huge_page(page))) {
                printk(
                        "[dsm_try_push_page] failed at splitting page \n");
                goto bad_page;
            }
        }
    }
    if (unlikely(PageKsm(page))) {
        printk("[dsm_try_push_page] KSM page\n");
        r = ksm_madvise(vma, addr, addr + PAGE_SIZE, MADV_UNMERGEABLE
                , &vma->vm_flags);
        if (r) {
            printk("[dsm_try_push_page] ksm_madvise ret : %d\n", r);
            // DSM1 : better ksm error handling required.
            goto bad_page;
        }
    }

    if (unlikely(!trylock_page(page))) {
        printk("[dsm_try_push_page] cannot lock page\n");
        goto bad_page;
    }

    dpc = dsm_push_cache_add(local_svm, addr, svms, svms.num);
    if (!dpc)
        goto bad_page;

    page_cache_get(page);
    flush_cache_page(vma, addr, pte_pfn(*pte));
    ptep_clear_flush_notify(vma, addr, pte);

    set_pte_at(mm, addr, pte, swp_entry_to_pte(
            dsm_descriptor_to_swp_entry(descriptor, 0)));

    page_remove_rmap(page);

    page_cache_get(page);
    dec_mm_counter(mm, MM_ANONPAGES);
// this is a page flagging without data exchange so we can free the page
    if (likely(!page_mapped(page)))
        try_to_free_swap(page);
//DSM1 do we need a put_page???/

    dpc->pages[0] = page;
    set_page_private(page, ULONG_MAX);
    unlock_page(page);
    pte_unmap_unlock(pte, ptl);

    /*
    printk(
            "[dsm_try_push_page] extracted page and added it to swap %p  \n ",
            (void*) page);
    */

    return ret;

    bad_page: pte_unmap_unlock(pte, ptl);

    out: ret = 1;
    return ret;
}
EXPORT_SYMBOL(dsm_try_push_page);

