/*
 * dsm_cache.c
 **  Created on: 5 Mar 2012
 *      Author: Roei
 */

#include <dsm/dsm_module.h>

static struct kmem_cache *dsm_cache_kmem;

inline struct dsm_page_cache *dsm_alloc_dpc(struct subvirtual_machine *svm,
        unsigned long addr, struct svm_list svms, int nproc, int tag) {
    struct dsm_page_cache *dpc;

    dpc = kmem_cache_alloc(dsm_cache_kmem, GFP_KERNEL);
    if (!dpc)
        goto out;

    atomic_set(&dpc->found, -1);
    atomic_set(&dpc->nproc, nproc);
    dpc->addr = addr;
    dpc->svms = svms;
    dpc->tag = tag;
    dpc->svm = svm;

    if (svms.num > DSM_PAGE_CACHE_DEFAULT) {
        kfree(dpc->pages);
        dpc->pages = kzalloc(sizeof(struct page *)*svms.num, GFP_KERNEL);
    }

    out: return dpc;
};

inline void dsm_dealloc_dpc(struct dsm_page_cache **dpc) {
    int i;

    if (*dpc) {
        for (i = 0; i < (*dpc)->svms.num; i++)
            (*dpc)->pages[i] = 0;
        kmem_cache_free(dsm_cache_kmem, *dpc);
        *dpc = NULL;
    }
};
EXPORT_SYMBOL(dsm_dealloc_dpc);

static void init_dsm_cache_elm(void *obj) {
    struct dsm_page_cache *dpc = (struct dsm_page_cache *) obj;

    dpc->pages = kzalloc(sizeof(struct page *)*DSM_PAGE_CACHE_DEFAULT,
            GFP_KERNEL);
};

void init_dsm_cache_kmem(void) {
    dsm_cache_kmem = kmem_cache_create("dsm_page_cache",
        sizeof(struct dsm_page_cache), 0, SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY, 
        init_dsm_cache_elm);
}
EXPORT_SYMBOL(init_dsm_cache_kmem);

void destroy_dsm_cache_kmem(void) {
    kmem_cache_destroy(dsm_cache_kmem);
}
EXPORT_SYMBOL(destroy_dsm_cache_kmem);

struct dsm_page_cache *dsm_push_cache_add(struct subvirtual_machine *svm,
        unsigned long addr, struct svm_list svms, int nproc) {
    struct dsm_page_cache *dpc = NULL, *rb_dpc;
    struct rb_node **new, *parent = NULL;

    write_seqlock(&svm->push_cache_lock);
    for (new = &svm->push_cache.rb_node; *new; ) {
        rb_dpc = rb_entry(*new, struct dsm_page_cache, rb_node);
        parent = *new;
        if (addr < rb_dpc->addr)
            new = &(*new)->rb_left;
        else if (addr > rb_dpc->addr)
            new = &(*new)->rb_right;
        else
            goto out;
    }

    dpc = dsm_alloc_dpc(svm, addr, svms, nproc, PUSH_TAG);
    dpc->bitmap = (1 << nproc)-1;
    rb_link_node(&dpc->rb_node, parent, new);
    rb_insert_color(&dpc->rb_node, &svm->push_cache);

    out: write_sequnlock(&svm->push_cache_lock);
    return dpc;
}

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

struct dsm_page_cache *dsm_push_cache_get(struct subvirtual_machine *svm,
        unsigned long addr) {
    struct rb_node *node;
    struct dsm_page_cache *dpc = NULL;
    unsigned long seq = 0;

    /*
     * FIXME: Modify to read_seqbegin(); insert rcu_read_lock, to allow
     * freeing on remove.
     */
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
    write_sequnlock(&svm->push_cache_lock);

    return dpc;
}

struct dsm_page_cache *dsm_cache_get_hold(struct subvirtual_machine *svm,
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
#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
        atomic_inc(&dpc->nproc);
#else
        if (!atomic_inc_not_zero(&dpc->nproc))
            goto repeat;
#endif
        if (unlikely(dpc != *ppc))
            goto repeat;
    }
    out: rcu_read_unlock();

    return dpc;
}

struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *svm, 
        unsigned long addr) {
    struct dsm_page_cache *dpc;

    spin_lock_irq(&svm->page_cache_spinlock);
    dpc = radix_tree_delete(&svm->page_cache, addr);
    spin_unlock_irq(&svm->page_cache_spinlock);

    return dpc;
}
EXPORT_SYMBOL(dsm_cache_release);

void dsm_push_cache_release(struct subvirtual_machine *svm,
        struct dsm_page_cache *dpc) {
    write_seqlock(&svm->push_cache_lock);
    rb_erase(&dpc->rb_node, &svm->push_cache);
    write_sequnlock(&svm->push_cache_lock);
}

