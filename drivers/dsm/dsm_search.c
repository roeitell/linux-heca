/*
 * rb.c
 **  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>
#include <dsm/dsm_trace.h>

static struct dsm_module_state *dsm_state;

struct dsm_module_state *create_dsm_module_state(void)
{
    dsm_state = kzalloc(sizeof(struct dsm_module_state), GFP_KERNEL);
    BUG_ON(!(dsm_state));
    INIT_RADIX_TREE(&dsm_state->dsm_tree_root, GFP_KERNEL & ~__GFP_WAIT);
    INIT_RADIX_TREE(&dsm_state->mm_tree_root, GFP_KERNEL & ~__GFP_WAIT);
    INIT_LIST_HEAD(&dsm_state->dsm_list);
    mutex_init(&dsm_state->dsm_state_mutex);
    dsm_state->dsm_tx_wq = alloc_workqueue("dsm_rx_wq",
            WQ_HIGHPRI | WQ_MEM_RECLAIM , 0);
    dsm_state->dsm_rx_wq = alloc_workqueue("dsm_tx_wq",
            WQ_HIGHPRI | WQ_MEM_RECLAIM , 0);
    return dsm_state;
}
EXPORT_SYMBOL(create_dsm_module_state);

void destroy_dsm_module_state(void)
{
    mutex_destroy(&dsm_state->dsm_state_mutex);
    destroy_workqueue(dsm_state->dsm_tx_wq);
    destroy_workqueue(dsm_state->dsm_rx_wq);
    kfree(dsm_state);
}
EXPORT_SYMBOL(destroy_dsm_module_state);

inline struct dsm_module_state *get_dsm_module_state(void)
{
    return dsm_state;
}
EXPORT_SYMBOL(get_dsm_module_state);

struct dsm *find_dsm(u32 id)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    struct dsm *dsm;
    struct dsm **dsmp;
    struct radix_tree_root *root;

    rcu_read_lock();
    root = &dsm_state->dsm_tree_root;
repeat: 
    dsm = NULL;
    dsmp = (struct dsm **) radix_tree_lookup_slot(root, (unsigned long) id);
    if (dsmp) {
        dsm = radix_tree_deref_slot((void **) dsmp);
        if (unlikely(!dsm))
            goto out;
        if (radix_tree_exception(dsm)) {
            if (radix_tree_deref_retry(dsm))
                goto repeat;
        }
    }
out: 
    rcu_read_unlock();
    return dsm;
}
EXPORT_SYMBOL(find_dsm);

inline void release_svm(struct subvirtual_machine *svm)
{
    atomic_dec(&svm->refs);
    if (atomic_cmpxchg(&svm->refs, 1, 0) == 1) {
        trace_release_svm(svm->svm_id);
        delete_svm_sysfs_entry(&svm->svm_sysfs.svm_kobject);
        synchronize_rcu();
        kfree(svm);
    }
}

static struct subvirtual_machine *_find_svm_in_tree(
        struct radix_tree_root *root, unsigned long svm_id)
{
    struct subvirtual_machine *svm;
    struct subvirtual_machine **svmp;

    rcu_read_lock();
repeat:
    svm = NULL;
    svmp = (struct subvirtual_machine **) radix_tree_lookup_slot(root,
            (unsigned long) svm_id);
    if (svmp) {
        svm = radix_tree_deref_slot((void**) svmp);
        if (unlikely(!svm))
            goto out;
        if (radix_tree_exception(svm)) {
            if (radix_tree_deref_retry(svm))
                goto repeat;
        }
#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT_COUNT
        BUG_ON(!in_atomic());
# endif
        BUG_ON(atomic_read(&svm->refs) == 0);
        atomic_inc(&svm->refs);
#else
        if (!atomic_inc_not_zero(&svm->refs))
            goto repeat;
#endif
    }

out: 
    rcu_read_unlock();
    return svm;
}

inline struct subvirtual_machine *find_svm(struct dsm *dsm, u32 svm_id)
{
    return _find_svm_in_tree(&dsm->svm_tree_root, (unsigned long) svm_id);
}
EXPORT_SYMBOL(find_svm);

inline struct subvirtual_machine *find_local_svm_in_dsm(struct dsm *dsm,
        struct mm_struct *mm)
{
    return _find_svm_in_tree(&dsm->svm_mm_tree_root, (unsigned long) mm);
}
EXPORT_SYMBOL(find_local_svm_in_dsm);

inline struct subvirtual_machine *find_local_svm(struct mm_struct *mm)
{
    return _find_svm_in_tree(&get_dsm_module_state()->mm_tree_root,
            (unsigned long) mm);
}
EXPORT_SYMBOL(find_local_svm);

void insert_rb_conn(struct conn_element *ele)
{
    struct rcm *rcm = get_dsm_module_state()->rcm;
    struct rb_root *root;
    struct rb_node **new, *parent = NULL;
    struct conn_element *this;

    write_seqlock(&rcm->conn_lock);
    root = &rcm->root_conn;
    new = &root->rb_node;
    while (*new) {
        this = rb_entry(*new, struct conn_element, rb_node);
        parent = *new;
        if (ele->remote_node_ip < this->remote_node_ip)
            new = &((*new)->rb_left);
        else if (ele->remote_node_ip > this->remote_node_ip)
            new = &((*new)->rb_right);
    }
    rb_link_node(&ele->rb_node, parent, new);
    rb_insert_color(&ele->rb_node, root);
    write_sequnlock(&rcm->conn_lock);
}
EXPORT_SYMBOL(insert_rb_conn);

// Return NULL if no element contained within tree.
struct conn_element *search_rb_conn(int node_ip)
{
    struct rcm *rcm = get_dsm_module_state()->rcm;
    struct rb_root *root;
    struct rb_node *node;
    struct conn_element *this = 0;
    unsigned long seq;

    do {
        seq = read_seqbegin(&rcm->conn_lock);
        root = &rcm->root_conn;
        for (node = root->rb_node; node; this = 0) {
            this = rb_entry(node, struct conn_element, rb_node);

            if (node_ip < this->remote_node_ip)
                node = node->rb_left;
            else if (node_ip > this->remote_node_ip)
                node = node->rb_right;
            else
                break;
        }
    } while (read_seqretry(&rcm->conn_lock, seq));

    return this;
}
EXPORT_SYMBOL(search_rb_conn);

void erase_rb_conn(struct conn_element *ele)
{
    struct rcm *rcm = get_dsm_module_state()->rcm;

    write_seqlock(&rcm->conn_lock);
    rb_erase(&ele->rb_node, &rcm->root_conn);
    write_sequnlock(&rcm->conn_lock);
}
EXPORT_SYMBOL(erase_rb_conn);

void destroy_mrs(struct subvirtual_machine *svm)
{
    struct rb_root *root = &svm->mr_tree_root;

    do {
        struct memory_region *mr;
        struct rb_node *node;

        write_seqlock(&svm->mr_seq_lock);
        node = rb_first(root);
        if (!node) {
            write_sequnlock(&svm->mr_seq_lock);
            break;
        }
        mr = rb_entry(node, struct memory_region, rb_node);
        rb_erase(&mr->rb_node, root);
        write_sequnlock(&svm->mr_seq_lock);
        synchronize_rcu();
        kfree(mr);
    } while(1);
}

int insert_mr(struct subvirtual_machine *svm, struct memory_region *mr)
{
    struct rb_root *root = &svm->mr_tree_root;
    struct rb_node **new = &root->rb_node, *parent = NULL;
    struct memory_region *this;
    int r;

    r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
    if (r)
        goto fail;

    write_seqlock(&svm->mr_seq_lock);

    /* insert to radix tree */
    r = radix_tree_insert(&svm->mr_id_tree_root, (unsigned long) mr->mr_id,
            mr);
    if (r)
        goto out;

    /* insert to rb tree */
    while (*new) {
        this = rb_entry(*new, struct memory_region, rb_node);
        parent = *new;
        if (mr->addr < this->addr)
            new = &((*new)->rb_left);
        else if (mr->addr > this->addr)
            new = &((*new)->rb_right);
    }

    rb_link_node(&mr->rb_node, parent, new);
    rb_insert_color(&mr->rb_node, root);
out:
    radix_tree_preload_end();
    write_sequnlock(&svm->mr_seq_lock);
fail:
    return r;
}
EXPORT_SYMBOL(insert_mr);

struct memory_region *find_mr(struct subvirtual_machine *svm,
        u32 id)
{
    struct memory_region *mr, **mrp;
    struct radix_tree_root *root;

    rcu_read_lock();
    root = &svm->mr_id_tree_root;
repeat:
    mr = NULL;
    mrp = (struct memory_region **) radix_tree_lookup_slot(root,
            (unsigned long) id);
    if (mrp) {
        mr = radix_tree_deref_slot((void **) mrp);
        if (unlikely(!mr))
            goto out;
        if (radix_tree_exception(mr)) {
            if (radix_tree_deref_retry(mr))
                goto repeat;
        }
    }
out: 
    rcu_read_unlock();
    return mr;
}

// Return NULL if no element contained within tree.
struct memory_region *search_mr(struct subvirtual_machine *svm,
        unsigned long addr)
{
    struct rb_root *root = &svm->mr_tree_root;
    struct rb_node *node;
    struct memory_region *this = svm->mr_cache;
    unsigned long seq;

    /* try to follow cache hint */
    if (likely(this)) {
        if (addr >= this->addr && addr < this->addr + this->sz)
            goto out;
    }

    do {
        seq = read_seqbegin(&svm->mr_seq_lock);
        for (node = root->rb_node; node; this = 0) {
            this = rb_entry(node, struct memory_region, rb_node);

            if (addr < this->addr)
                node = node->rb_left;
            else if (addr > this->addr)
                if (addr < (this->addr + this->sz))
                    break;
                else
                    node = node->rb_right;
            else
                break;
        }
    } while (read_seqretry(&svm->mr_seq_lock, seq));

    if (likely(this))
        svm->mr_cache = this;

out:
    return this;
}
EXPORT_SYMBOL(search_mr);

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

void dsm_init_descriptors(void) {
    mutex_init(&sdsc_lock);
    (void) dsm_descriptors_realloc();
}
EXPORT_SYMBOL(dsm_init_descriptors);

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
EXPORT_SYMBOL(dsm_destroy_descriptors);

void dsm_add_descriptor(struct dsm *dsm, u32 desc, u32 *svm_ids)
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
EXPORT_SYMBOL(dsm_add_descriptor);

u32 dsm_entry_to_desc(swp_entry_t entry)
{
    u64 val = dsm_entry_to_val(entry);
    u32 desc = (u32) (val >> 24);
    BUG_ON(desc < SDSC_MIN);
    return desc;
}
EXPORT_SYMBOL(dsm_entry_to_desc);

u32 dsm_entry_to_flags(swp_entry_t entry)
{
    u64 val = dsm_entry_to_val(entry);
    u32 flags = val & 0xFFFFFF;
    return flags;
}
EXPORT_SYMBOL(dsm_entry_to_flags);

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
EXPORT_SYMBOL(dsm_get_descriptor);

inline pte_t dsm_descriptor_to_pte(u32 dsc, u32 flags)
{
    u64 val = dsc;
    swp_entry_t swp_e = val_to_dsm_entry((val << 24) | flags);
    return swp_entry_to_pte(swp_e);
}

struct svm_list dsm_descriptor_to_svms(u32 dsc)
{
    return rcu_dereference(sdsc)[dsc];
}
EXPORT_SYMBOL(dsm_descriptor_to_svms);

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
EXPORT_SYMBOL(swp_entry_to_dsm_data);

int dsm_swp_entry_same(swp_entry_t entry, swp_entry_t entry2)
{
    u32 desc = dsm_entry_to_desc(entry);
    u32 desc2 = dsm_entry_to_desc(entry2);
    return desc == desc2;
}
EXPORT_SYMBOL(dsm_swp_entry_same);

void dsm_clear_swp_entry_flag(struct mm_struct *mm, unsigned long addr,
        pte_t *pte, int pos)
{
    pte_t tmp_pte = *pte;
    swp_entry_t arch = __pte_to_swp_entry(tmp_pte);
    swp_entry_t entry = swp_entry(__swp_type(arch), __swp_offset(arch));
    u64 desc = dsm_entry_to_desc(entry);
    u32 flags = dsm_entry_to_flags(entry);

    clear_bit(pos, (volatile long unsigned int *) &flags);
    set_pte_at(mm, addr, pte, dsm_descriptor_to_pte(desc, flags));
}
EXPORT_SYMBOL(dsm_clear_swp_entry_flag);

