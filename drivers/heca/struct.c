/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include "core.h"
#include "trace.h"
#include "struct.h"
#include "push.h"
#include "base.h"

/* svm_descriptors */
static struct svm_list *sdsc;
static u32 sdsc_max;
static struct mutex sdsc_lock;
#define SDSC_MIN 0x10

static u64 dsm_descriptors_realloc(void)
{
    struct svm_list *new_sdsc, *old_sdsc = NULL;
    u32 new_sdsc_max;

    new_sdsc_max = sdsc_max + 256;
    new_sdsc = kzalloc(sizeof(struct svm_list) * new_sdsc_max, GFP_KERNEL);
    BUG_ON(!new_sdsc); /* TODO: handle failure, fail the calling ioctl */

    if (sdsc) {
        memcpy(new_sdsc, sdsc, sizeof(struct svm_list) * sdsc_max);
        old_sdsc = sdsc;
    }

    rcu_assign_pointer(sdsc, new_sdsc);
    sdsc_max = new_sdsc_max;

    if (old_sdsc) {
        synchronize_rcu();
        kfree(old_sdsc);
    }
    return sdsc_max;
}

void dsm_init_descriptors(void)
{
    mutex_init(&sdsc_lock);
    (void) dsm_descriptors_realloc();
}

void dsm_destroy_descriptors(void)
{
    int i;

    for (i = SDSC_MIN; i < sdsc_max; i++)
        if (sdsc[i].pp) {
            kfree(sdsc[i].pp);
            sdsc[i].pp = NULL;
        }
    kfree(sdsc);
    sdsc = NULL;
    sdsc_max = 0;
}

static void dsm_add_descriptor(struct dsm *dsm, u32 desc, u32 *svm_ids)
{
    u32 j;

    for (j = 0; svm_ids[j]; j++)
        ;
    sdsc[desc].num = j;
    BUG_ON(!sdsc[desc].num);
    sdsc[desc].pp = 
        kzalloc(sizeof(struct subvirtual_machine *) * j, GFP_KERNEL);
    BUG_ON(!sdsc[desc].pp); /* TODO: handle failure! */
    for (j = 0; svm_ids[j]; j++) {
        struct subvirtual_machine *svm = find_svm(dsm, svm_ids[j]);
        BUG_ON(!svm);
        BUG_ON(!svm->dsm);
        sdsc[desc].pp[j] = svm;
        release_svm(svm);
    }
}

static inline u32 dsm_entry_to_desc(swp_entry_t entry)
{
    u64 val = dsm_entry_to_val(entry);
    u32 desc = (u32) (val >> 24);
    BUG_ON(desc < SDSC_MIN);
    return desc;
}

static inline u32 dsm_entry_to_flags(swp_entry_t entry)
{
    u64 val = dsm_entry_to_val(entry);
    u32 flags = val & 0xFFFFFF;
    return flags;
}

u32 dsm_get_descriptor(struct dsm *dsm, u32 *svm_ids)
{
    u32 i, j;

    mutex_lock(&sdsc_lock);
    for (i = SDSC_MIN; i < sdsc_max && sdsc[i].num; i++) {
        for (j = 0; j < sdsc[i].num && sdsc[i].pp[j] && svm_ids[j] &&
                sdsc[i].pp[j]->svm_id == svm_ids[j]; j++)
            ;
        if (j == sdsc[i].num && !svm_ids[j])
            break;
    }

    if (i >= sdsc_max)
        (void) dsm_descriptors_realloc();

    if (!sdsc[i].num)
        dsm_add_descriptor(dsm, i, svm_ids);

    mutex_unlock(&sdsc_lock);
    return i;
}

inline pte_t dsm_descriptor_to_pte(u32 dsc, u32 flags)
{
    u64 val = dsc;
    swp_entry_t swp_e = val_to_dsm_entry((val << 24) | flags);
    BUG_ON(dsc < SDSC_MIN || dsc >= sdsc_max);
    return swp_entry_to_pte(swp_e);
}

inline struct svm_list dsm_descriptor_to_svms(u32 dsc)
{
    BUG_ON(dsc < SDSC_MIN || dsc >= sdsc_max);
    return rcu_dereference(sdsc)[dsc];
}

/* arrive with dsm mutex held! */
void remove_svm_from_descriptors(struct subvirtual_machine *svm)
{
    int i;

    for (i = SDSC_MIN; i < sdsc_max && sdsc[i].num; i++) {
        struct svm_list svms;
        int j;

        rcu_read_lock();
        svms = dsm_descriptor_to_svms(i);
        rcu_read_unlock();

        /*
         * We can either walk the entire page table, removing references to this
         * descriptor; change the descriptor in-place (which will require
         * complex locking everywhere); or hack - leave a "hole" in the arr to
         * signal svm down.
         */
        for_each_valid_svm (svms, j) {
            if (svms.pp[j]->svm_id == svm->svm_id) {
                svms.pp[j] = NULL;
                break;
            }
        }
    }
}

int swp_entry_to_dsm_data(swp_entry_t entry, struct dsm_swp_data *dsd)
{
    u32 desc = dsm_entry_to_desc(entry);
    int i, ret = 0;

    BUG_ON(!dsd);
    memset(dsd, 0, sizeof (*dsd));
    dsd->flags = dsm_entry_to_flags(entry);

    rcu_read_lock();
    dsd->svms = dsm_descriptor_to_svms(desc);
    BUG_ON(!dsd->svms.num);
    for_each_valid_svm(dsd->svms, i) {
        dsd->dsm = dsd->svms.pp[i]->dsm;
        goto out;
    }
    ret = -ENODATA;

out:
    rcu_read_unlock();
    return ret;
}

int dsm_swp_entry_same(swp_entry_t entry, swp_entry_t entry2)
{
    u32 desc = dsm_entry_to_desc(entry);
    u32 desc2 = dsm_entry_to_desc(entry2);
    return desc == desc2;
}

void dsm_clear_swp_entry_flag(struct mm_struct *mm, unsigned long addr,
        pte_t orig_pte, int pos)
{
    struct dsm_pte_data pd;
    spinlock_t *ptl;
    swp_entry_t arch, entry;
    u32 desc, flags;

    /* If PTE_PRESENT flag is set, pte hasn't changed - no need to clear anything*/
    if (pte_present(orig_pte))
        return;

    if (unlikely(dsm_extract_pte_data(&pd, mm, addr)))
        return;

    pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
    if (unlikely(!pte_same(*(pd.pte), orig_pte)))
        goto out;

    arch = __pte_to_swp_entry(orig_pte);
    entry = swp_entry(__swp_type(arch), __swp_offset(arch));
    desc = dsm_entry_to_desc(entry);
    flags = dsm_entry_to_flags(entry);

    clear_bit(pos, (volatile long unsigned int *) &flags);
    set_pte_at(mm, addr, pd.pte, dsm_descriptor_to_pte(desc, flags));

out:
    pte_unmap_unlock(pd.pte, ptl);
}

/* dsm page cache */
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

void destroy_dsm_cache_kmem(void)
{
    kmem_cache_destroy(dsm_cache_kmem);
}

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

struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine *svm,
        unsigned long addr)
{
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
        unsigned long addr)
{
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

static inline struct page_pool_ele *dsm_try_get_ppe(struct conn_element *ele)
{
    struct llist_node *llnode;
    struct page_pool_ele *ppe = NULL;

    spin_lock(&ele->page_pool_elements_lock);
    llnode = llist_del_first(&ele->page_pool_elements);
    spin_unlock(&ele->page_pool_elements_lock);

    if (likely(llnode))
        ppe = container_of(llnode, struct page_pool_ele, llnode);

    return ppe;
}

static struct page_pool_ele *dsm_get_ppe(struct conn_element *ele)
{
    struct page_pool_ele *ppe;

retry:
    /* FIXME: when flushing dsm_requests we might be mutex_locked */
    while (llist_empty(&ele->page_pool_elements))
        cond_resched();

    ppe = dsm_try_get_ppe(ele);
    if (unlikely(!ppe))
        goto retry;

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

        ppe = dsm_try_get_ppe(ele);
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

