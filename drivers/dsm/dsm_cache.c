/*
 * dsm_cache.c
 **  Created on: 5 Mar 2012
 *      Author: Roei
 */

#include <dsm/dsm_module.h>

static struct kmem_cache *dsm_cache_kmem;

static inline void init_dsm_cache_elm(void *obj)
{
    struct dsm_page_cache *dpc = (struct dsm_page_cache *) obj;
    int i;

    for (i = 0; i < MAX_SVMS_PER_PAGE; i++)
        dpc->pages[i] = NULL;

}

void init_dsm_cache_kmem(void)
{
    dsm_cache_kmem = kmem_cache_create("dsm_page_cache",
            sizeof(struct dsm_page_cache), 0,
            SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY, init_dsm_cache_elm);
}
EXPORT_SYMBOL(init_dsm_cache_kmem);

void destroy_dsm_cache_kmem(void)
{
    kmem_cache_destroy(dsm_cache_kmem);
}
EXPORT_SYMBOL(destroy_dsm_cache_kmem);

struct dsm_page_cache *dsm_alloc_dpc(struct subvirtual_machine *svm,
        unsigned long addr, struct svm_list svms, int nproc, int tag)
{
    struct dsm_page_cache *dpc = kmem_cache_alloc(dsm_cache_kmem, GFP_ATOMIC);
    if (unlikely(!dpc))
        goto out;

    atomic_set(&dpc->found, -1);
    atomic_set(&dpc->nproc, nproc);
    atomic_set(&dpc->released, 0);
    dpc->addr = addr;
    dpc->svms = svms;
    dpc->tag = tag;
    dpc->svm = svm;

out:
    return dpc;
}


void dsm_dealloc_dpc(struct dsm_page_cache **dpc)
{
    int i;

    for (i = 0; i < (*dpc)->svms.num; i++)
        (*dpc)->pages[i] = 0;
    kmem_cache_free(dsm_cache_kmem, *dpc);
    *dpc = NULL;
}
EXPORT_SYMBOL(dsm_dealloc_dpc);

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
}


struct dsm_page_cache *dsm_cache_get_hold(struct subvirtual_machine *svm,
        unsigned long addr) {
    void **ppc;
    struct dsm_page_cache *dpc;

    rcu_read_lock();

repeat:
    dpc = NULL;
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
        VM_BUG_ON(in_interrupt());
#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT_COUNT
        VM_BUG_ON(!in_atomic());
# endif
        VM_BUG_ON(atomic_read(&dpc->nproc) == 0);
        atomic_inc(&dpc->nproc);
#else
        if (!atomic_inc_not_zero(&dpc->nproc))
            goto repeat;
#endif
        if (unlikely(dpc != *ppc))
            goto repeat;
    }
out:
    rcu_read_unlock();
    return dpc;
}

struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *svm,
        unsigned long addr)
{
    struct dsm_page_cache *dpc;

    spin_lock_irq(&svm->page_cache_spinlock);
    dpc = radix_tree_delete(&svm->page_cache, addr);
    spin_unlock_irq(&svm->page_cache_spinlock);

    return dpc;
}
EXPORT_SYMBOL(dsm_cache_release);

