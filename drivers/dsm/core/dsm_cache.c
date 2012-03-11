/*
 * dsm_cache.c
 **  Created on: 5 Mar 2012
 *      Author: Roei
 */

#include <dsm/dsm_module.h>

static struct kmem_cache *dsm_cache_kmem;

static struct list_head dsm_cache_alloced;
static struct list_head dsm_cache_to_remove;

static inline struct dsm_page_cache *dsm_alloc_dpc(int npages, int nproc, 
        int tag, struct subvirtual_machine *svm) {
    struct dsm_page_cache *dpc;

    dpc = kmem_cache_alloc(dsm_cache_kmem, GFP_KERNEL);
    if (!dpc)
        goto out;

    atomic_set(&dpc->found, -1);
    dpc->npages = npages;
    atomic_set(&dpc->nproc, nproc);
    dpc->tag = tag;
    dpc->svm = svm;

    if (npages > DSM_PAGE_CACHE_DEFAULT) {
        kfree(dpc->pages);
        dpc->pages = kzalloc(sizeof(struct page *)*npages, GFP_KERNEL);
    }

    list_add_tail(&dpc->list, &dsm_cache_alloced);
    out: return dpc;
};

inline void dsm_dealloc_dpc(struct dsm_page_cache **dpc) {
    int i;

    if (*dpc) {
        list_del(&((*dpc)->list));
        for (i = 0; i < (*dpc)->npages; i++)
            (*dpc)->pages[i] = 0;
        kmem_cache_free(dsm_cache_kmem, *dpc);
        *dpc = NULL;
    }
};

static void init_dsm_cache_elm(void *obj) {
    struct dsm_page_cache *dpc = (struct dsm_page_cache *) obj;

    dpc->pages = kzalloc(sizeof(struct page *)*DSM_PAGE_CACHE_DEFAULT,
            GFP_KERNEL);
};

void init_dsm_cache_kmem(void) {
    dsm_cache_kmem = kmem_cache_create("dsm_page_cache",
        sizeof(struct dsm_page_cache), 0, SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY, 
        init_dsm_cache_elm);

    INIT_LIST_HEAD(&dsm_cache_alloced);
    INIT_LIST_HEAD(&dsm_cache_to_remove);
}
EXPORT_SYMBOL(init_dsm_cache_kmem);

void destroy_dsm_cache_kmem(void) {
    kmem_cache_destroy(dsm_cache_kmem);
}
EXPORT_SYMBOL(destroy_dsm_cache_kmem);

struct dsm_page_cache *dsm_cache_add(struct subvirtual_machine *svm, 
        unsigned long addr, int npages, int nproc, int tag) {
    struct dsm_page_cache *dpc;
    int r;

    dpc = dsm_alloc_dpc(npages, nproc, tag, svm);
    if (!dpc)
        goto out;

    r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
    if (!r) {
        spin_lock_irq(&svm->page_cache_spinlock);
        r = radix_tree_insert(&svm->page_cache, addr, dpc);
        spin_unlock_irq(&svm->page_cache_spinlock);
        radix_tree_preload_end();
    }
    if (r)
        dsm_dealloc_dpc(&dpc);

    out: return dpc;
};

struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine *svm, 
       unsigned long addr) {
    void **ppc;
    struct dsm_page_cache *dpc;

    rcu_read_lock();
    repeat: dpc = NULL;
    ppc = radix_tree_lookup_slot(&svm->page_cache, addr);
    if (ppc) {
        dpc = radix_tree_deref_slot(ppc);
        if (unlikely(!dpc))
            goto out;
        if (radix_tree_exception(dpc)) {
            if (radix_tree_deref_retry(dpc))
                goto repeat;
            goto out;
        }
        if (unlikely(dpc != *ppc))
            goto repeat;
    }
    out: rcu_read_unlock();

    return dpc;
};
EXPORT_SYMBOL(dsm_cache_get);

struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *svm, 
        unsigned long addr) {
    struct dsm_page_cache *dpc;

    spin_lock_irq(&svm->page_cache_spinlock);
    dpc = radix_tree_delete(&svm->page_cache, addr);
    spin_unlock_irq(&svm->page_cache_spinlock);

    return dpc;
}
EXPORT_SYMBOL(dsm_cache_release);

