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

    atomic_inc(&svm->refs);
    atomic_set(&dpc->found, -1);
    atomic_set(&dpc->nproc, nproc);
    dpc->released = 0;
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
    release_svm((*dpc)->svm);
    kmem_cache_free(dsm_cache_kmem, *dpc);
    *dpc = NULL;
}
EXPORT_SYMBOL(dsm_dealloc_dpc);

struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine *svm,
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
        if (unlikely(dpc != *ppc))
            goto repeat;
    }

out:
    rcu_read_unlock();
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


/*
 * Page pool
 *
 * Currently doesn't consider user-defined numa policy, as the page pool is
 * attached to a conn_element, and not to a local svm.
 * Also, page pool sizes are currently bloated.
 *
 */
static inline int dsm_map_page_in_ppe(struct page_pool_ele *ppe,
        struct page *page, struct conn_element *ele)
{
    ppe->mem_page = page;
    ppe->page_buf = (void *) ib_dma_map_page(ele->cm_id->device,
            ppe->mem_page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
    return ib_dma_mapping_error(ele->cm_id->device,
            (u64) (unsigned long) ppe->page_buf);
}

static inline void dsm_release_ppe(struct conn_element *ele,
        struct page_pool_ele *ppe)
{
    llist_add(&ppe->llnode, &ele->page_pool_elements);
}

static struct page_pool_ele *dsm_get_ppe(struct conn_element *ele)
{
    struct llist_node *llnode = NULL;
    struct page_pool_ele *ppe;

    do {
        while (llist_empty(&ele->page_pool_elements))
            cond_resched();

        spin_lock(&ele->page_pool_elements_lock);
        llnode = llist_del_first(&ele->page_pool_elements);
        spin_unlock(&ele->page_pool_elements_lock);
    } while (!llnode);

    ppe = container_of(llnode, struct page_pool_ele, llnode);
    return ppe;
}

static void dsm_page_pool_refill(struct work_struct *work)
{
    struct dsm_page_pool *pp;
    struct conn_element *ele;

    get_cpu();
    pp = container_of(work, struct dsm_page_pool, work);
    ele = pp->ele;
    while (pp->head) {
        struct page_pool_ele *ppe;
        struct page *page;

        ppe = dsm_get_ppe(ele);
        if (!ppe)
            break;

        page = alloc_pages_current(GFP_HIGHUSER_MOVABLE & ~__GFP_WAIT, 0);
        if (!page) {
            dsm_release_ppe(ele, ppe);
            break;
        }

        if (dsm_map_page_in_ppe(ppe, page, ele)) {
            page_cache_release(page);
            dsm_release_ppe(ele, ppe);
            break;
        }

        pp->buf[--pp->head] = ppe;
    }
    if (pp->head)
        schedule_work_on(pp->cpu, &pp->work);
    put_cpu();
}

/* svms erased, cm_id destroyed, work cancelled => no race conditions */
void dsm_destroy_page_pool(struct conn_element *ele)
{
    int i;
    struct page_pool_ele *ppe;

    /* destroy page pool */
    for_each_online_cpu(i) {
        struct dsm_page_pool *pp = per_cpu_ptr(ele->page_pool, i);
        cancel_work_sync(&pp->work); /* work offline, or spin_lock inside */
        while (pp->head != DSM_PAGE_POOL_SZ) {
            ppe = pp->buf[pp->head++];
            if (ppe->mem_page)
                page_cache_release(ppe->mem_page);
            kfree(ppe);
        }
    }

    /* destroy elements list */
    while (!llist_empty(&ele->page_pool_elements)) {
        struct llist_node *llnode = llist_del_first(&ele->page_pool_elements);
        ppe = container_of(llnode, struct page_pool_ele, llnode);
        kfree(ppe);
    }
}

int dsm_init_page_pool(struct conn_element *ele)
{
    int i;

    /* init elements list */
    spin_lock_init(&ele->page_pool_elements_lock);
    init_llist_head(&ele->page_pool_elements);
    for (i = 0; i < DSM_PAGE_POOL_SZ * (NR_CPUS + 1); i++) {
        struct page_pool_ele *ppe = kzalloc(sizeof(struct page_pool_ele),
                GFP_ATOMIC);
        if (!ppe)
            goto nomem;
        llist_add(&ppe->llnode, &ele->page_pool_elements);
    }

    /* init page pool */
    ele->page_pool = alloc_percpu(struct dsm_page_pool);
    if (!ele->page_pool)
        goto nomem;

    for_each_online_cpu(i) {
        struct dsm_page_pool *pp = per_cpu_ptr(ele->page_pool, i);
        pp->head = DSM_PAGE_POOL_SZ;
        pp->ele = ele; /* for container_of(work_struct) */
        pp->cpu = i;
        INIT_WORK(&pp->work, dsm_page_pool_refill);
        schedule_work_on(i, &pp->work);
    }
    return 0;

nomem:
    while (!llist_empty(&ele->page_pool_elements)) {
        struct llist_node *llnode = llist_del_first(&ele->page_pool_elements);
        struct page_pool_ele *ppe = container_of(llnode, struct page_pool_ele,
                llnode);
        kfree(ppe);
    }
    return -EFAULT;
}

struct page_pool_ele *dsm_fetch_ready_ppe(struct conn_element *ele)
{
    struct dsm_page_pool *pp;
    struct page_pool_ele *ppe = NULL;
    int i;

    i = get_cpu();
    pp = per_cpu_ptr(ele->page_pool, i);
    if (pp->head < DSM_PAGE_POOL_SZ)
        ppe = pp->buf[pp->head++];
    schedule_work_on(i, &pp->work);
    put_cpu();

    return ppe;
}

struct page_pool_ele *dsm_prepare_ppe(struct conn_element *ele,
        struct page *page)
{
    struct page_pool_ele *ppe;

    ppe = dsm_get_ppe(ele);
    if (dsm_map_page_in_ppe(ppe, page, ele))
        goto err;

    return ppe;

err:
    dsm_release_ppe(ele, ppe);
    return NULL;
}

void dsm_ppe_clear_release(struct conn_element *ele, struct page_pool_ele **ppe)
{
    if ((*ppe)->page_buf) {
        ib_dma_unmap_page(ele->cm_id->device, (u64) (*ppe)->page_buf,
                PAGE_SIZE, DMA_BIDIRECTIONAL);
        (*ppe)->page_buf = NULL;
    }
    if ((*ppe)->mem_page)
        page_cache_release((*ppe)->mem_page);
    dsm_release_ppe(ele, *ppe);
    *ppe = NULL;
}

