/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include <linux/pagemap.h>
#include "ioctl.h"
#include "trace.h"
#include "struct.h"
#include "push.h"
#include "base.h"

/* hproc_descriptors */
static struct heca_process_list *shsc;
static u32 shsc_max;
static struct mutex shsc_lock;
#define SDSC_MIN 0x10

/* heca page cache */
static struct kmem_cache *heca_cache_kmem;

/*
 * page_readers
 *
 * every maintained page has an entry in this tree, specifying which read-copies
 * were issued, if at all.
 */
static struct kmem_cache *heca_reader_kmem;

static u64 heca_descriptors_realloc(void)
{
        struct heca_process_list *new_shsc, *old_shsc = NULL;
        u32 new_shsc_max;

        new_shsc_max = shsc_max + 256;
        new_shsc = kzalloc(sizeof(struct heca_process_list) * new_shsc_max,
                        GFP_KERNEL);
        BUG_ON(!new_shsc); /* TODO: handle failure, fail the calling ioctl */

        if (shsc) {
                memcpy(new_shsc, shsc,
                                sizeof(struct heca_process_list) * shsc_max);
                old_shsc = shsc;
        }

        rcu_assign_pointer(shsc, new_shsc);
        shsc_max = new_shsc_max;

        if (old_shsc) {
                synchronize_rcu();
                kfree(old_shsc);
        }
        return shsc_max;
}

void heca_init_descriptors(void)
{
        mutex_init(&shsc_lock);
        (void) heca_descriptors_realloc();
}

void heca_destroy_descriptors(void)
{
        int i;

        for (i = SDSC_MIN; i < shsc_max; i++)
                kfree(shsc[i].ids);
        kfree(shsc);
        shsc = NULL;
        shsc_max = 0;
}

static int heca_add_descriptor(u32 hspace_id, u32 desc, u32 *hproc_ids)
{
        u32 j;

        for (j = 0; hproc_ids[j]; j++)
                ;
        shsc[desc].num = j;
        BUG_ON(!shsc[desc].num);

        shsc[desc].hspace_id = hspace_id;

        /* recycle used descriptor? */
        if (shsc[desc].ids)
                kfree(shsc[desc].ids);

        shsc[desc].ids = kzalloc(sizeof(u32) * j, GFP_KERNEL);
        if (unlikely(!shsc[desc].ids))
                return -EFAULT;

        for (j = 0; hproc_ids[j]; j++)
                shsc[desc].ids[j] = hproc_ids[j];

        return 0;
}

static inline u32 heca_entry_to_desc(swp_entry_t entry)
{
        u64 val = heca_entry_to_val(entry);
        u32 desc = (u32) (val >> 24);
        BUG_ON(desc < SDSC_MIN);
        return desc;
}

static inline u32 heca_entry_to_flags(swp_entry_t entry)
{
        u64 val = heca_entry_to_val(entry);
        u32 flags = val & 0xFFFFFF;
        return flags;
}

/*
 * FIXME: we support descriptor recycling - if we encounter an empty descriptor
 * we will reuse it. and yet, if a page is unmapped to this descriptor, it might
 * result in a deadlock when we fault on the page. so we either don't recycle
 * descriptors, or walk the page table when a descriptor is dead (on remove_hproc)
 * or solve otherwise.
 */
u32 heca_get_descriptor(u32 hspace_id, u32 *hproc_ids)
{
        u32 i, j;

retry:
        mutex_lock(&shsc_lock);
        for (i = SDSC_MIN; i < shsc_max && shsc[i].num; i++) {
                if (shsc[i].hspace_id != hspace_id)
                        continue;

                /* don't use changed descriptors! */
                for (j = 0; j < shsc[i].num && shsc[i].ids[j] && hproc_ids[j] &&
                                shsc[i].ids[j] == hproc_ids[j]; j++)
                        ;

                /* found? */
                if (j == shsc[i].num && !hproc_ids[j])
                        goto out;
        }

        if (i >= shsc_max)
                (void) heca_descriptors_realloc();

        if (unlikely(heca_add_descriptor(hspace_id, i, hproc_ids))) {
                mutex_unlock(&shsc_lock);
                might_sleep();
                cond_resched();
                goto retry;
        }

out:
        mutex_unlock(&shsc_lock);
        return i;
}

inline pte_t heca_descriptor_to_pte(u32 hsc, u32 flags)
{
        u64 val = hsc;
        swp_entry_t swp_e = val_to_heca_entry((val << 24) | flags);
        BUG_ON(hsc < SDSC_MIN || hsc >= shsc_max);
        return swp_entry_to_pte(swp_e);
}

inline struct heca_process_list heca_descriptor_to_hprocs(u32 hsc)
{
        BUG_ON(hsc < SDSC_MIN || hsc >= shsc_max);
        return rcu_dereference(shsc)[hsc];
}

/* arrive with hspace mutex held! */
void remove_hproc_from_descriptors(struct heca_process *hproc)
{
        int i;

        for (i = SDSC_MIN; i < shsc_max && shsc[i].num; i++) {
                struct heca_process_list hprocs;
                int j;

                rcu_read_lock();
                hprocs = heca_descriptor_to_hprocs(i);
                rcu_read_unlock();

                /*
                 * We can either walk the entire page table, removing references to this
                 * descriptor; change the descriptor in-place (which will require
                 * complex locking everywhere); or hack - leave a "hole" in the arr to
                 * signal hproc down.
                 */
                for_each_valid_hproc (hprocs, j) {
                        if (hprocs.ids[j] == hproc->hproc_id) {
                                hprocs.ids[j] = 0;
                                break;
                        }
                }
        }
}

int swp_entry_to_heca_data(swp_entry_t entry, struct heca_swp_data *hsd)
{
        u32 desc = heca_entry_to_desc(entry);
        int ret = 0;

        BUG_ON(!hsd);
        memset(hsd, 0, sizeof (*hsd));
        hsd->flags = heca_entry_to_flags(entry);

        rcu_read_lock();
        hsd->hprocs = heca_descriptor_to_hprocs(desc);
        rcu_read_unlock();

        if (unlikely(!hsd->hprocs.num || !hsd->hprocs.hspace_id))
                ret = -ENODATA;

        return ret;
}

int heca_swp_entry_same(swp_entry_t entry, swp_entry_t entry2)
{
        u32 desc = heca_entry_to_desc(entry);
        u32 desc2 = heca_entry_to_desc(entry2);
        return desc == desc2;
}

void heca_clear_swp_entry_flag(struct mm_struct *mm, unsigned long addr,
                pte_t orig_pte, int pos)
{
        struct heca_pte_data pd;
        spinlock_t *ptl;
        swp_entry_t arch, entry;
        u32 desc, flags;

        /* If PTE_PRESENT flag is set, pte hasn't changed - no need to clear anything*/
        if (pte_present(orig_pte))
                return;

        if (unlikely(heca_extract_pte_data(&pd, mm, addr)))
                return;

        pd.pte = pte_offset_map_lock(mm, pd.pmd, addr, &ptl);
        if (unlikely(!pte_same(*(pd.pte), orig_pte)))
                goto out;

        arch = __pte_to_swp_entry(orig_pte);
        entry = swp_entry(__swp_type(arch), __swp_offset(arch));
        desc = heca_entry_to_desc(entry);
        flags = heca_entry_to_flags(entry);

        clear_bit(pos, (volatile long unsigned int *) &flags);
        set_pte_at(mm, addr, pd.pte, heca_descriptor_to_pte(desc, flags));

out:
        pte_unmap_unlock(pd.pte, ptl);
}

static inline void init_heca_cache_elm(void *obj)
{
        struct heca_page_cache *hpc = (struct heca_page_cache *) obj;
        int i;

        for (i = 0; i < MAX_HPROCS_PER_PAGE; i++)
                hpc->pages[i] = NULL;
}

void init_heca_cache_kmem(void)
{
        heca_cache_kmem = kmem_cache_create("heca_page_cache",
                        sizeof(struct heca_page_cache), 0,
                        SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY,
                        init_heca_cache_elm);
}

void destroy_heca_cache_kmem(void)
{
        kmem_cache_destroy(heca_cache_kmem);
}

/* assuming we hold the hproc, we inc its refcount again for the dpc */
struct heca_page_cache *heca_alloc_hpc(struct heca_process *hproc,
                unsigned long addr, struct heca_process_list hprocs, int nproc, int tag)
{
        struct heca_page_cache *hpc = kmem_cache_alloc(heca_cache_kmem,
                        GFP_ATOMIC);
        if (unlikely(!hpc))
                goto out;

        atomic_inc(&hproc->refs);
        atomic_set(&hpc->found, -1);
        atomic_set(&hpc->nproc, nproc);
        hpc->released = 0;
        hpc->addr = addr;
        hpc->hprocs = hprocs;
        hpc->tag = tag;
        hpc->hproc = hproc;
        hpc->redirect_hproc_id = 0;

out:
        return hpc;
}

void heca_dealloc_hpc(struct heca_page_cache **hpc)
{
        int i;

        for (i = 0; i < (*hpc)->hprocs.num; i++)
                (*hpc)->pages[i] = 0;
        release_hproc((*hpc)->hproc);
        kmem_cache_free(heca_cache_kmem, *hpc);
        *hpc = NULL;
}

struct heca_page_cache *heca_cache_get(struct heca_process *hproc,
                unsigned long addr)
{
        void **ppc;
        struct heca_page_cache *hpc;

        rcu_read_lock();

repeat:
        hpc = NULL;
        ppc = radix_tree_lookup_slot(&hproc->page_cache, addr);
        if (ppc) {
                hpc = radix_tree_deref_slot(ppc);
                if (unlikely(!hpc))
                        goto out;
                if (radix_tree_exception(hpc)) {
                        if (radix_tree_deref_retry(hpc))
                                goto repeat;
                        goto out;
                }
                if (unlikely(hpc != *ppc))
                        goto repeat;
        }

out:
        rcu_read_unlock();
        return hpc;
}


struct heca_page_cache *heca_cache_get_hold(struct heca_process *hproc,
                unsigned long addr)
{
        void **ppc;
        struct heca_page_cache *hpc;

        rcu_read_lock();

repeat:
        hpc = NULL;
        ppc = radix_tree_lookup_slot(&hproc->page_cache, addr);
        if (ppc) {
                hpc = radix_tree_deref_slot(ppc);
                if (unlikely(!hpc))
                        goto out;

                if (radix_tree_exception(hpc)) {
                        if (radix_tree_deref_retry(hpc))
                                goto repeat;
                        goto out;
                }
                VM_BUG_ON(in_interrupt());
#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT_COUNT
                VM_BUG_ON(!in_atomic());
# endif
                VM_BUG_ON(atomic_read(&hpc->nproc) == 0);
                atomic_inc(&hpc->nproc);
#else
                if (!atomic_inc_not_zero(&hpc->nproc))
                        goto repeat;
#endif
                if (unlikely(hpc != *ppc))
                        goto repeat;
        }
out:
        rcu_read_unlock();
        return hpc;
}

int heca_cache_add(struct heca_process *hproc, unsigned long addr, int nproc,
                int tag, struct heca_page_cache **hpc)
{
        struct heca_process_list hprocs;
        int r = 0;

        hprocs.num = 0;
        hprocs.ids = NULL;

        do {
                *hpc = heca_alloc_hpc(hproc, addr, hprocs, nproc, tag);
                if (unlikely(!*hpc))
                        return -ENOMEM;

                r = radix_tree_preload(GFP_ATOMIC);
                if (unlikely(r))
                        break;

                spin_lock_irq(&hproc->page_cache_spinlock);
                r = radix_tree_insert(&hproc->page_cache, addr, hpc);
                spin_unlock_irq(&hproc->page_cache_spinlock);
                radix_tree_preload_end();

                if (likely(!r))
                        return 0;

                heca_dealloc_hpc(hpc);
                *hpc = heca_cache_get(hproc, addr);
                if (unlikely(*hpc)) /* do not dealloc! */
                        return -EEXIST;

        } while (r != -ENOMEM);

        if (*hpc)
                heca_dealloc_hpc(hpc);
        return r;
}

struct heca_page_cache *heca_cache_release(struct heca_process *hproc,
                unsigned long addr)
{
        struct heca_page_cache *hpc;

        spin_lock_irq(&hproc->page_cache_spinlock);
        hpc = radix_tree_delete(&hproc->page_cache, addr);
        spin_unlock_irq(&hproc->page_cache_spinlock);

        return hpc;
}

/*
 * Page pool
 *
 * Currently doesn't consider user-defined numa policy, as the page pool is
 * attached to a conn_element, and not to a local hproc.
 * Also, page pool sizes are currently bloated.
 *
 */
static inline int heca_map_page_in_ppe(struct heca_page_pool_element *ppe,
                struct page *page, struct heca_connection *conn)
{
        ppe->mem_page = page;
        ppe->page_buf = (void *) ib_dma_map_page(conn->cm_id->device,
                        ppe->mem_page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
        return ib_dma_mapping_error(conn->cm_id->device,
                        (u64) (unsigned long) ppe->page_buf);
}

static inline void heca_release_ppe(struct heca_connection *conn,
                struct heca_page_pool_element *ppe)
{
        llist_add(&ppe->llnode, &conn->page_pool_elements);
}

static inline struct heca_page_pool_element *heca_try_get_ppe(
                struct heca_connection *conn)
{
        struct llist_node *llnode;
        struct heca_page_pool_element *ppe = NULL;

        spin_lock(&conn->page_pool_elements_lock);
        llnode = llist_del_first(&conn->page_pool_elements);
        spin_unlock(&conn->page_pool_elements_lock);

        if (likely(llnode))
                ppe = container_of(llnode, struct heca_page_pool_element,
                                llnode);

        return ppe;
}

static struct heca_page_pool_element *heca_get_ppe(struct heca_connection *conn)
{
        struct heca_page_pool_element *ppe;

retry:
        /* FIXME: when flushing heca_requests we might be mutex_locked */
        while (llist_empty(&conn->page_pool_elements))
                cond_resched();

        ppe = heca_try_get_ppe(conn);
        if (unlikely(!ppe))
                goto retry;

        return ppe;
}

static void heca_page_pool_refill(struct work_struct *work)
{
        struct heca_space_page_pool *pp;
        struct heca_connection *conn;

        get_cpu();
        pp = container_of(work, struct heca_space_page_pool, work);
        conn = pp->connection;
        while (pp->head) {
                struct heca_page_pool_element *ppe;
                struct page *page;

                ppe = heca_try_get_ppe(conn);
                if (!ppe)
                        break;

                page = alloc_pages_current(GFP_HIGHUSER_MOVABLE & ~__GFP_WAIT,
                                0);
                if (!page) {
                        heca_release_ppe(conn, ppe);
                        break;
                }

                if (heca_map_page_in_ppe(ppe, page, conn)) {
                        page_cache_release(page);
                        heca_release_ppe(conn, ppe);
                        break;
                }

                pp->hspace_page_pool[--pp->head] = ppe;
        }
        if (pp->head)
                schedule_work_on(pp->cpu, &pp->work);
        put_cpu();
}

/* hprocs erased, cm_id destroyed, work cancelled => no race conditions */
void heca_destroy_page_pool(struct heca_connection *conn)
{
        int i;
        struct heca_page_pool_element *ppe;

        /* destroy page pool */
        for_each_online_cpu(i) {
                struct heca_space_page_pool *pp = per_cpu_ptr(conn->page_pool,
                                i);
                cancel_work_sync(&pp->work); /* work offline, or spin_lock inside */
                while (pp->head != HSPACE_PAGE_POOL_SZ) {
                        ppe = pp->hspace_page_pool[pp->head++];
                        if (ppe->mem_page)
                                page_cache_release(ppe->mem_page);
                        kfree(ppe);
                }
        }

        /* destroy elements list */
        while (!llist_empty(&conn->page_pool_elements)) {
                struct llist_node *llnode = llist_del_first(&conn->page_pool_elements);
                ppe = container_of(llnode, struct heca_page_pool_element,
                                llnode);
                kfree(ppe);
        }
}

int heca_init_page_pool(struct heca_connection *conn)
{
        int i;

        /* init elements list */
        spin_lock_init(&conn->page_pool_elements_lock);
        init_llist_head(&conn->page_pool_elements);
        for (i = 0; i < HSPACE_PAGE_POOL_SZ * (NR_CPUS + 1); i++) {
                struct heca_page_pool_element *ppe = kzalloc(sizeof(struct heca_page_pool_element),
                                GFP_ATOMIC);
                if (!ppe)
                        goto nomem;
                llist_add(&ppe->llnode, &conn->page_pool_elements);
        }

        /* init page pool */
        conn->page_pool = alloc_percpu(struct heca_space_page_pool);
        if (!conn->page_pool)
                goto nomem;

        for_each_online_cpu(i) {
                struct heca_space_page_pool *pp = per_cpu_ptr(conn->page_pool,
                                i);
                pp->head = HSPACE_PAGE_POOL_SZ;
                pp->connection = conn; /* for container_of(work_struct) */
                pp->cpu = i;
                INIT_WORK(&pp->work, heca_page_pool_refill);
                schedule_work_on(i, &pp->work);
        }
        return 0;

nomem:
        while (!llist_empty(&conn->page_pool_elements)) {
                struct llist_node *llnode = llist_del_first(&conn->page_pool_elements);
                struct heca_page_pool_element *ppe = container_of(llnode,
                                struct heca_page_pool_element, llnode);
                kfree(ppe);
        }
        return -EFAULT;
}

struct heca_page_pool_element *heca_fetch_ready_ppe(
                struct heca_connection *conn)
{
        struct heca_space_page_pool *pp;
        struct heca_page_pool_element *ppe = NULL;
        int i;

        i = get_cpu();
        pp = per_cpu_ptr(conn->page_pool, i);
        if (pp->head < HSPACE_PAGE_POOL_SZ)
                ppe = pp->hspace_page_pool[pp->head++];
        schedule_work_on(i, &pp->work);
        put_cpu();

        return ppe;
}

struct heca_page_pool_element *heca_prepare_ppe(struct heca_connection *conn,
                struct page *page)
{
        struct heca_page_pool_element *ppe;

        ppe = heca_get_ppe(conn);
        if (heca_map_page_in_ppe(ppe, page, conn))
                goto err;

        return ppe;

err:
        heca_release_ppe(conn, ppe);
        return NULL;
}

void heca_ppe_clear_release(struct heca_connection *conn,
                struct heca_page_pool_element **ppe)
{
        if ((*ppe)->page_buf) {
                ib_dma_unmap_page(conn->cm_id->device, (u64) (*ppe)->page_buf,
                                PAGE_SIZE, DMA_BIDIRECTIONAL);
                (*ppe)->page_buf = NULL;
        }
        if ((*ppe)->mem_page)
                page_cache_release((*ppe)->mem_page);
        heca_release_ppe(conn, *ppe);
        *ppe = NULL;
}



static inline void init_heca_reader_elm(void *obj)
{
        ((struct heca_page_reader *) obj)->next = NULL;
}

void init_heca_reader_kmem(void)
{
        heca_reader_kmem = kmem_cache_create("heca_reader_cache",
                        sizeof(struct heca_page_reader), 0, SLAB_TEMPORARY,
                        init_heca_reader_elm);
}

void destroy_heca_reader_kmem(void)
{
        kmem_cache_destroy(heca_reader_kmem);
}

inline void heca_free_page_reader(struct heca_page_reader *dpr)
{
        kmem_cache_free(heca_reader_kmem, dpr);
}

struct heca_page_reader *heca_delete_readers(struct heca_process *hproc,
                unsigned long addr)
{
        struct heca_page_reader *hpr;

        spin_lock_irq(&hproc->page_readers_spinlock);
        hpr = radix_tree_delete(&hproc->page_readers, addr);
        spin_unlock_irq(&hproc->page_readers_spinlock);

        return hpr;
}

struct heca_page_reader *heca_lookup_readers(struct heca_process *hproc,
                unsigned long addr)
{
        struct heca_page_reader *hpr;
        void **ppc;

        rcu_read_lock();

repeat:
        hpr = NULL;
        ppc = radix_tree_lookup_slot(&hproc->page_readers, addr);
        if (ppc) {
                hpr = radix_tree_deref_slot(ppc);
                if (unlikely(!hpr))
                        goto out;
                if (radix_tree_exception(hpr)) {
                        if (radix_tree_deref_retry(hpr))
                                goto repeat;
                        goto out;
                }
                if (unlikely(hpr != *ppc))
                        goto repeat;
        }

out:
        rcu_read_unlock();
        return hpr;
}

int heca_add_reader(struct heca_process *hproc, unsigned long addr,
                u32 hproc_id)
{
        int r;
        struct heca_page_reader *hpr, *head;

retry:
        r = radix_tree_preload(GFP_ATOMIC);
        if (unlikely(r)) {
                cond_resched();
                goto retry;
        }

        spin_lock_irq(&hproc->page_readers_spinlock);
        head = heca_lookup_readers(hproc, addr);

        /* already exists? */
        for (hpr = head; hpr; hpr = hpr->next) {
                if (hpr->hproc_id == hproc_id)
                        goto unlock;
        }

        /* try alloc */
        hpr = kmem_cache_alloc(heca_reader_kmem, GFP_ATOMIC);
        if (unlikely(!hpr)) {
                spin_unlock_irq(&hproc->page_readers_spinlock);
                radix_tree_preload_end();
                cond_resched();
                goto retry;
        }
        hpr->hproc_id = hproc_id;

        /* TODO: optimize a bit for big clusters */
        if (head) {
                hpr->next = head->next;
                head->next = hpr;
        } else {
                r = radix_tree_insert(&hproc->page_readers, addr, hpr);
        }
        BUG_ON(r);

unlock:
        spin_unlock_irq(&hproc->page_readers_spinlock);
        radix_tree_preload_end();

        return r;
}

/*
 * page_maintainers
 *
 * this tree is for tracking the maintainers of local read-copies; when we
 * write fault on a read-copy, we remember who gave it to us, and can ask them
 * to invalidate the page and pass maintenance to us.
 *
 * we abuse the radix tree and keep u32 instead of pointers, in the same
 * fashion swap entries are stored there.
 */
static inline void *maintainer_id_to_node(u32 hproc_id)
{
        unsigned long val;

        val = hproc_id << RADIX_TREE_EXCEPTIONAL_SHIFT;
        return (void *)(val | RADIX_TREE_EXCEPTIONAL_ENTRY);
}

static inline u32 node_to_maintainer_id(void *node)
{
        return (u32)(((unsigned long) node) >> RADIX_TREE_EXCEPTIONAL_SHIFT);
}

int heca_flag_page_read(struct heca_process *hproc, unsigned long addr,
                u32 hproc_id)
{
        int r = radix_tree_preload(GFP_ATOMIC);
        if (unlikely(r))
                goto out;

        spin_lock_irq(&hproc->page_maintainers_spinlock);
        r = radix_tree_insert(&hproc->page_maintainers, addr,
                        maintainer_id_to_node(hproc_id));
        spin_unlock_irq(&hproc->page_maintainers_spinlock);
        radix_tree_preload_end();

out:
        return r;
}

u32 heca_lookup_page_read(struct heca_process *hproc, unsigned long addr)
{
        u32 *node, hproc_id = 0;
        void **pval;

        rcu_read_lock();
repeat:
        node = NULL;
        pval = radix_tree_lookup_slot(&hproc->page_maintainers, addr);
        if (pval) {
                node = radix_tree_deref_slot(pval);
                if (unlikely(!node))
                        goto out;

                if (unlikely(!radix_tree_exceptional_entry(node))) {
                        if (radix_tree_exception(node)) {
                                if (radix_tree_deref_retry(node))
                                        goto repeat;
                                goto out;
                        }
                        if (node != *pval)
                                goto repeat;
                }
                hproc_id = node_to_maintainer_id(node);
        }
out:
        rcu_read_unlock();
        return hproc_id;
}

u32 heca_extract_page_read(struct heca_process *hproc, unsigned long addr)
{
        u32 *node, hproc_id = 0;

        spin_lock_irq(&hproc->page_maintainers_spinlock);
        node = radix_tree_delete(&hproc->page_maintainers, addr);
        spin_unlock_irq(&hproc->page_maintainers_spinlock);

        if (node)
                hproc_id = node_to_maintainer_id(node);

        return hproc_id;
}

