/*
 * dsm_cache.c
 **  Created on: 5 Mar 2012
 *      Author: Roei
 */

#include <dsm/dsm_module.h>

static struct kmem_cache *dsm_cache_kmem;

static struct delayed_work dsm_cache_gc_work;
static struct list_head dsm_cache_alloced;
static struct list_head dsm_cache_to_remove;

static inline struct dsm_page_cache *dsm_alloc_pc(int npages, int nproc, 
        int tag) {
    struct dsm_page_cache *pc;

    pc = kmem_cache_alloc(dsm_cache_kmem, GFP_KERNEL);
    pc->flags = 0;
    set_bit(DSM_CACHE_ACTIVE, &pc->flags);
    pc->npages = npages;
    pc->nproc = nproc;
    pc->tag = tag;
    pc->fd.fault_state = VM_FAULT_MAJOR;
    if (npages > DSM_PAGE_CACHE_DEFAULT) {
        kfree(pc->pages);
        pc->pages = kzalloc(sizeof(struct page *)*npages, GFP_KERNEL);
    } else {
        memset(pc->pages, 0, sizeof(struct page *)*npages);
    }

    list_add_tail(&pc->list, &dsm_cache_alloced);
    return pc;
};

static inline void dsm_dealloc_pc(struct dsm_page_cache **pc) {
    if (*pc) {
        list_del(&((*pc)->list));
        kfree((*pc)->pages);
        kmem_cache_free(dsm_cache_kmem, *pc);
        *pc = NULL;
    }
};

/*
 * TODO: Locking on gc
 *  pc-wise (use existing lock)
 *  list-wise (rcu / seq)
 *
 */
static void dsm_cache_gc(struct work_struct *work) {
    struct list_head tmp, *cur, *next;
    struct dsm_page_cache *pc;

    tmp = dsm_cache_alloced;
    dsm_cache_alloced.next = NULL;
    dsm_cache_alloced.prev = NULL;

    /*
     * Set every page we safely can to be de-alloced in next iteration. All
     * other pages are marked as discarded, to give everyone some time before
     * we de-alloc them.
     *
     */
    list_for_each_safe(cur, next, &dsm_cache_alloced) {
        pc = list_entry(cur, struct dsm_page_cache, list);

        if (test_bit(DSM_CACHE_DISCARD, &pc->flags)) {
            list_del(cur);
            list_add(cur, &dsm_cache_to_remove);
        } else {
            pc->flags = 0;
            set_bit(DSM_CACHE_DISCARD, &pc->flags);
        }
    }

    list_for_each_safe(cur, next, &dsm_cache_to_remove) {
        pc = list_entry(cur, struct dsm_page_cache, list);
        dsm_dealloc_pc(&pc);
    }
    schedule_delayed_work(&dsm_cache_gc_work, HZ);
};

static void init_dsm_cache_elm(void *obj) {
    struct dsm_page_cache *pc = (struct dsm_page_cache *) obj;

    spin_lock_init(&pc->lock);
    pc->pages = kzalloc(sizeof(struct page *)*DSM_PAGE_CACHE_DEFAULT,
            GFP_KERNEL);
};

void init_dsm_cache_kmem(void) {
    dsm_cache_kmem = kmem_cache_create("dsm_page_cache",
        sizeof(struct dsm_page_cache), 0, SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY, 
        init_dsm_cache_elm);

    INIT_LIST_HEAD(&dsm_cache_alloced);
    INIT_LIST_HEAD(&dsm_cache_to_remove);

    INIT_DELAYED_WORK_DEFERRABLE(&dsm_cache_gc_work, dsm_cache_gc);
/*    schedule_delayed_work(&dsm_cache_gc_work, HZ);    */
}
EXPORT_SYMBOL(init_dsm_cache_kmem);

void destroy_dsm_cache_kmem(void) {
    kmem_cache_destroy(dsm_cache_kmem);
    cancel_delayed_work(&dsm_cache_gc_work);
}
EXPORT_SYMBOL(destroy_dsm_cache_kmem);

struct dsm_page_cache *dsm_cache_add(struct subvirtual_machine *svm, 
        unsigned long addr, int npages, int nproc, int tag) {
    struct dsm_page_cache *pc;
    int r;

    pc = dsm_alloc_pc(npages, nproc, tag);
    if (!pc)
        goto out;

    r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
    if (!r) {
        spin_lock_irq(&svm->page_cache_spinlock);
        r = radix_tree_insert(&svm->page_cache, addr, pc);
        spin_unlock_irq(&svm->page_cache_spinlock);
        radix_tree_preload_end();
    }
    if (r)
        dsm_dealloc_pc(&pc);

    out: return pc;
};

struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine *svm, 
       unsigned long addr) {
    void **ppc;
    struct dsm_page_cache *pc;

    rcu_read_lock();
    repeat: pc = NULL;
    ppc = radix_tree_lookup_slot(&svm->page_cache, addr);
    if (ppc) {
        pc = radix_tree_deref_slot(ppc);
        if (unlikely(!pc))
            goto out;
        if (radix_tree_exception(pc)) {
            if (radix_tree_deref_retry(pc))
                goto repeat;
            goto out;
        }
    }
    out: rcu_read_unlock();

    return pc;
};
EXPORT_SYMBOL(dsm_cache_get);

struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *svm, 
        unsigned long addr) {
    struct dsm_page_cache *pc;

    spin_lock_irq(&svm->page_cache_spinlock);
    pc = radix_tree_delete(&svm->page_cache, addr);
    spin_unlock_irq(&svm->page_cache_spinlock);

    return pc;
}
EXPORT_SYMBOL(dsm_cache_release);

