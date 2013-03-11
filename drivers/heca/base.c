/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Steve Walsh <steve.walsh@sap.com> 2012 (c)
 */
#include <linux/pagemap.h>
#include "ioctl.h"
#include "trace.h"
#include "struct.h"
#include "base.h"
#include "conn.h"
#include "pull.h"
#include "push.h"
#include "sysfs.h"
#include "ops.h"
#include "task.h"

/*
 * dsm_module_state funcs
 */
static struct dsm_module_state *dsm_state;

inline struct dsm_module_state *get_dsm_module_state(void)
{
    return dsm_state;
}

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

void destroy_dsm_module_state(void)
{
    mutex_destroy(&dsm_state->dsm_state_mutex);
    destroy_workqueue(dsm_state->dsm_tx_wq);
    destroy_workqueue(dsm_state->dsm_rx_wq);
    kfree(dsm_state);
}

/*
 * conn_element funcs
 */
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

void erase_rb_conn(struct conn_element *ele)
{
    struct rcm *rcm = get_dsm_module_state()->rcm;

    write_seqlock(&rcm->conn_lock);
    rb_erase(&ele->rb_node, &rcm->root_conn);
    write_sequnlock(&rcm->conn_lock);
}

/*
 * dsm funcs
 */
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

void remove_dsm(struct dsm *dsm)
{
    struct subvirtual_machine *svm;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    struct list_head *pos, *n;

    BUG_ON(!dsm);

    heca_printk(KERN_DEBUG "<enter> dsm=%d", dsm->dsm_id);

    list_for_each_safe (pos, n, &dsm->svm_list) {
        svm = list_entry(pos, struct subvirtual_machine, svm_ptr);
        remove_svm(dsm->dsm_id, svm->svm_id);
    }

    mutex_lock(&dsm_state->dsm_state_mutex);
    list_del(&dsm->dsm_ptr);
    radix_tree_delete(&dsm_state->dsm_tree_root, (unsigned long) dsm->dsm_id);
    mutex_unlock(&dsm_state->dsm_state_mutex);
    synchronize_rcu();

    delete_dsm_sysfs_entry(&dsm->dsm_kobject);

    mutex_lock(&dsm_state->dsm_state_mutex);
    kfree(dsm);
    mutex_unlock(&dsm_state->dsm_state_mutex);

    heca_printk(KERN_DEBUG "<exit>");
}

/* FIXME: just a dummy lock so that radix_tree functions work */
DEFINE_SPINLOCK(dsm_lock);

int create_dsm(struct private_data *priv_data, __u32 dsm_id)
{
    int r = 0;
    struct dsm *found_dsm, *new_dsm = NULL;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    /* already exists? (first check; the next one is under lock */
    found_dsm = find_dsm(dsm_id);
    if (found_dsm) {
        heca_printk("we already have the dsm in place");
        return -EEXIST;
    }

    /* allocate a new dsm */
    new_dsm = kzalloc(sizeof(*new_dsm), GFP_KERNEL);
    if (!new_dsm) {
        heca_printk("can't allocate");
        return -ENOMEM;
    }
    new_dsm->dsm_id = dsm_id;
    mutex_init(&new_dsm->dsm_mutex);
    INIT_RADIX_TREE(&new_dsm->svm_tree_root, GFP_KERNEL & ~__GFP_WAIT);
    INIT_RADIX_TREE(&new_dsm->svm_mm_tree_root, GFP_KERNEL & ~__GFP_WAIT);
    INIT_LIST_HEAD(&new_dsm->svm_list);
    new_dsm->nb_local_svm = 0;

    while (1) {
        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (!r)
            break;

        if (r == -ENOMEM) {
            heca_printk("radix_tree_preload: ENOMEM retrying ...");
            mdelay(2);
            continue;
        }

        heca_printk("radix_tree_preload: failed %d", r);
        goto failed;
    }

    /* TODO: move this spin lock to be part of dsm_state */
    spin_lock(&dsm_lock);
    r = radix_tree_insert(&dsm_state->dsm_tree_root,
            (unsigned long) new_dsm->dsm_id, new_dsm);
    spin_unlock(&dsm_lock);
    radix_tree_preload_end();

    if (r) {
        heca_printk("radix_tree_insert: failed %d", r);
        goto failed;
    }

    r = create_dsm_sysfs_entry(new_dsm, dsm_state);
    if (r) {
        heca_printk("create_dsm_sysfs_entry: failed %d", r);
        goto err_delete;
    }

    priv_data->dsm = new_dsm;
    list_add(&new_dsm->dsm_ptr, &dsm_state->dsm_list);
    heca_printk("registered dsm %p, dsm_id : %u, res: %d",
            new_dsm, dsm_id, r);
    return r;

err_delete:
    radix_tree_delete(&dsm_state->dsm_tree_root,
            (unsigned long) dsm_id);
failed:
    kfree(new_dsm);
    return r;
}

/*
 * svm funcs
 */
static void destroy_svm_mrs(struct subvirtual_machine *svm);

static inline int is_svm_local(struct subvirtual_machine *svm)
{
    return !!svm->mm;
}

static inline int grab_svm(struct subvirtual_machine *svm)
{
#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT_COUNT
    BUG_ON(!in_atomic());
# endif
    BUG_ON(atomic_read(&svm->refs) == 0);
    atomic_inc(&svm->refs);
#else
    if (!atomic_inc_not_zero(&svm->refs))
        return -1;
#endif
    return 0;
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

        if (grab_svm(svm))
            goto repeat;

    }

out:
    rcu_read_unlock();
    return svm;
}

inline struct subvirtual_machine *find_svm(struct dsm *dsm, u32 svm_id)
{
    return _find_svm_in_tree(&dsm->svm_tree_root, (unsigned long) svm_id);
}

inline struct subvirtual_machine *find_local_svm_in_dsm(struct dsm *dsm,
        struct mm_struct *mm)
{
    return _find_svm_in_tree(&dsm->svm_mm_tree_root, (unsigned long) mm);
}

inline struct subvirtual_machine *find_local_svm_from_mm(struct mm_struct *mm)
{
    return _find_svm_in_tree(&get_dsm_module_state()->mm_tree_root,
            (unsigned long) mm);
}

static int insert_svm_to_radix_trees(struct dsm_module_state *dsm_state,
        struct dsm *dsm, struct subvirtual_machine *new_svm)
{
    int r;

preload:
    r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
    if (r) {
        if (r == -ENOMEM) {
            heca_printk(KERN_ERR "radix_tree_preload: ENOMEM retrying ...");
            mdelay(2);
            goto preload;
        }
        heca_printk(KERN_ERR "radix_tree_preload: failed %d", r);
        goto out;
    }

    /* FIXME: use dsm_state global spinlock here! */
    spin_lock(&dsm_lock);
    r = radix_tree_insert(&dsm->svm_tree_root,
            (unsigned long) new_svm->svm_id, new_svm);
    if (r)
        goto unlock;

    if (is_svm_local(new_svm)) {
        r = radix_tree_insert(&dsm->svm_mm_tree_root,
                (unsigned long) new_svm->mm, new_svm);
        if (r)
            goto unlock;

        r = radix_tree_insert(&dsm_state->mm_tree_root,
                (unsigned long) new_svm->mm, new_svm);
    }

unlock:
    spin_unlock(&dsm_lock);

    radix_tree_preload_end();
    if (r) {
        heca_printk(KERN_ERR "failed radix_tree_insert %d", r);
        radix_tree_delete(&dsm->svm_tree_root, (unsigned long) new_svm->svm_id);
        if (is_svm_local(new_svm)) {
            radix_tree_delete(&dsm->svm_mm_tree_root,
                    (unsigned long) new_svm->mm);
            radix_tree_delete(&dsm_state->mm_tree_root,
                    (unsigned long) new_svm->mm);
        }
    }

out:
    return r;
}

int create_svm(struct hecaioc_svm *svm_info)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int r = 0;
    struct dsm *dsm;
    struct subvirtual_machine *found_svm, *new_svm = NULL;

    /* allocate a new svm */
    new_svm = kzalloc(sizeof(*new_svm), GFP_KERNEL);
    if (!new_svm) {
        heca_printk(KERN_ERR "failed kzalloc");
        return -ENOMEM;
    }

    /* grab dsm lock */
    mutex_lock(&dsm_state->dsm_state_mutex);
    dsm = find_dsm(svm_info->dsm_id);
    if (dsm)
        mutex_lock(&dsm->dsm_mutex);
    mutex_unlock(&dsm_state->dsm_state_mutex);
    if (!dsm) {
        heca_printk(KERN_ERR "could not find dsm: %d", svm_info->dsm_id);
        r = -EFAULT;
        goto no_dsm;
    }

    /* already exists? */
    found_svm = find_svm(dsm, svm_info->svm_id);
    if (found_svm) {
        heca_printk(KERN_ERR "svm %d (dsm %d) already exists", svm_info->svm_id,
                svm_info->dsm_id);
        r = -EEXIST;
        goto out;
    }

    /* initial svm data */
    new_svm->svm_id = svm_info->svm_id;
    new_svm->is_local = svm_info->is_local;
    new_svm->pid = svm_info->pid;
    new_svm->dsm = dsm;
    atomic_set(&new_svm->refs, 2);

    /* register local svm */
    if (svm_info->is_local) {
        struct mm_struct *mm;
       
        mm = find_mm_by_pid(new_svm->pid);
        if (!mm) {
            heca_printk(KERN_ERR "can't find pid %d", new_svm->pid);
            r = -ESRCH;
            goto out;
        }

        found_svm = find_local_svm_from_mm(mm);
        if (found_svm) {
            heca_printk(KERN_ERR "svm already exists for current process");
            r = -EEXIST;
            goto out;
        }

        new_svm->mm = mm;
        new_svm->dsm->nb_local_svm++;
        new_svm->mr_tree_root = RB_ROOT;
        seqlock_init(&new_svm->mr_seq_lock);
        new_svm->mr_cache = NULL;

        init_llist_head(&new_svm->delayed_faults);
        INIT_DELAYED_WORK(&new_svm->delayed_gup_work, delayed_gup_work_fn);
        init_llist_head(&new_svm->deferred_gups);
        INIT_WORK(&new_svm->deferred_gup_work, deferred_gup_work_fn);

        spin_lock_init(&new_svm->page_cache_spinlock);
        INIT_RADIX_TREE(&new_svm->page_cache, GFP_ATOMIC);
        new_svm->push_cache = RB_ROOT;
        seqlock_init(&new_svm->push_cache_lock);
    }

    r = create_svm_sysfs_entry(new_svm);
    if (r) {
        heca_printk(KERN_ERR "failed create_svm_sysfs_entry %d", r);
        goto out;
    }

    /* register svm by id and mm_struct (must come before dsm_get_descriptor) */
    if (insert_svm_to_radix_trees(dsm_state, dsm, new_svm))
        goto out;
    list_add(&new_svm->svm_ptr, &dsm->svm_list);

    /* assign descriptor for remote svm */
    if (!is_svm_local(new_svm)) {
        u32 svm_ids[] = {new_svm->svm_id, 0};
        new_svm->descriptor = dsm_get_descriptor(dsm, svm_ids);
    }

out:
    mutex_unlock(&dsm->dsm_mutex);
    if (found_svm)
        release_svm(found_svm);
    if (r) {
        kfree(new_svm);
        new_svm = NULL;
        goto no_dsm;
    }

    if (!svm_info->is_local) {
        r = connect_svm(svm_info->dsm_id, svm_info->svm_id, 
            svm_info->remote.sin_addr.s_addr, svm_info->remote.sin_port);

        if (r) {
            heca_printk(KERN_ERR "connect_svm failed %d", r);
            goto out;
        }
    }
no_dsm:
    heca_printk(KERN_INFO "svm %p, res %d, dsm_id %u, svm_id: %u --> ret %d",
            new_svm, r, svm_info->dsm_id, svm_info->svm_id, r);
    return r;
}

inline void release_svm(struct subvirtual_machine *svm)
{
    atomic_dec(&svm->refs);
    if (atomic_cmpxchg(&svm->refs, 1, 0) == 1) {
        trace_free_svm(svm->svm_id);
        delete_svm_sysfs_entry(&svm->svm_kobject);
        synchronize_rcu();
        kfree(svm);
    }
}

/*
 * We dec page's refcount for every missing remote response (it would have
 * happened in dsm_ppe_clear_release after sending an answer to remote svm)
 */
static void surrogate_push_remote_svm(struct subvirtual_machine *svm,
        struct subvirtual_machine *remote_svm)
{
    struct rb_node *node;

    write_seqlock(&svm->push_cache_lock);
    for (node = rb_first(&svm->push_cache); node;) {
        struct dsm_page_cache *dpc;
        int i;

        dpc = rb_entry(node, struct dsm_page_cache, rb_node);
        node = rb_next(node);
        for_each_valid_svm(dpc->svms, i) {
            if (dpc->svms.pp[i] == remote_svm)
                goto surrogate;
        }
        continue;

surrogate:
        if (likely(test_and_clear_bit(i, &dpc->bitmap))) {
            page_cache_release(dpc->pages[0]);
            atomic_dec(&dpc->nproc);
            if (atomic_cmpxchg(&dpc->nproc, 1, 0) == 1 && find_first_bit(
                    &dpc->bitmap, dpc->svms.num) >= dpc->svms.num) {
                dsm_push_cache_release(dpc->svm, &dpc, 0);
            }
        }
    }
    write_sequnlock(&svm->push_cache_lock);
}

static void release_svm_push_elements(struct subvirtual_machine *svm)
{
    struct rb_node *node;

    write_seqlock(&svm->push_cache_lock);
    for (node = rb_first(&svm->push_cache); node;) {
        struct dsm_page_cache *dpc;
        int i;

        dpc = rb_entry(node, struct dsm_page_cache, rb_node);
        node = rb_next(node);
        for_each_valid_svm(dpc->svms, i) {
            if (test_and_clear_bit(i, &dpc->bitmap))
                page_cache_release(dpc->pages[0]);
        }
        dsm_push_cache_release(dpc->svm, &dpc, 0);
    }
    write_sequnlock(&svm->push_cache_lock);
}

/*
 * pull ops tx_elements are only released after a response has returned.
 * therefore we can catch them and surrogate for them by iterating the tx
 * buffer.
 */
static void release_svm_tx_elements(struct subvirtual_machine *svm,
        struct conn_element *ele)
{
    struct tx_buf_ele *tx_buf;
    int i;

    /* killed before it was first connected */
    if (!ele || !ele->tx_buffer.tx_buf)
        return;

    tx_buf = ele->tx_buffer.tx_buf;

    for (i = 0; i < ele->tx_buffer.len; i++) {
        struct tx_buf_ele *tx_e = &tx_buf[i];
        struct dsm_message *msg = tx_e->dsm_buf;

        if (msg->type & (REQUEST_PAGE | TRY_REQUEST_PAGE | PAGE_REQUEST_FAIL)
                && msg->dsm_id == svm->dsm->dsm_id
                && (msg->src_id == svm->svm_id || msg->dest_id == svm->svm_id)
                && atomic_cmpxchg(&tx_e->used, 1, 2) == 1) {
            struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;

            dsm_pull_req_failure(dpc);
            tx_e->wrk_req->dst_addr->mem_page = NULL;
            dsm_release_pull_dpc(&dpc);
            dsm_ppe_clear_release(ele, &tx_e->wrk_req->dst_addr);

            /* rdma processing already finished, we have to release ourselves */
            smp_mb();
            if (atomic_read(&tx_e->used) > 2)
                try_release_tx_element(ele, tx_e);
        }
    }
}

static void release_svm_queued_requests(struct subvirtual_machine *svm,
        struct tx_buffer *tx)
{
    struct dsm_request *req, *n;
    u32 svm_id = svm->svm_id;

    mutex_lock(&tx->flush_mutex);
    dsm_request_queue_merge(tx);
    list_for_each_entry_safe (req, n, &tx->ordered_request_queue, ordered_list){
        if (req->remote_svm_id == svm_id || req->local_svm_id == svm_id) {
            list_del(&req->ordered_list);
            if (req->dpc && req->dpc->tag == PULL_TAG)
                dsm_release_pull_dpc(&req->dpc);
            release_dsm_request(req);
        }
    }
    mutex_unlock(&tx->flush_mutex);
}

void remove_svm(u32 dsm_id, u32 svm_id)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    struct dsm *dsm;
    struct subvirtual_machine *svm = NULL;

    mutex_lock(&dsm_state->dsm_state_mutex);
    dsm = find_dsm(dsm_id);
    if (!dsm) {
        mutex_unlock(&dsm_state->dsm_state_mutex);
        return;
    }

    mutex_lock(&dsm->dsm_mutex);
    svm = find_svm(dsm, svm_id);
    if (!svm) {
        mutex_unlock(&dsm_state->dsm_state_mutex);
        goto out;
    }
    if (is_svm_local(svm)) {
        radix_tree_delete(&get_dsm_module_state()->mm_tree_root,
                (unsigned long) svm->mm);
    }
    mutex_unlock(&dsm_state->dsm_state_mutex);

    list_del(&svm->svm_ptr);
    radix_tree_delete(&dsm->svm_tree_root, (unsigned long) svm->svm_id);
    if (is_svm_local(svm)) {
        cancel_delayed_work_sync(&svm->delayed_gup_work);
        // to make sure everything is clean
        dequeue_and_gup_cleanup(svm);
        dsm->nb_local_svm--;
        radix_tree_delete(&dsm->svm_mm_tree_root,
                (unsigned long) svm->mm);
    }

    remove_svm_from_descriptors(svm);

    /*
     * there are three ways of catching and releasing hanged ops:
     *  - queued requests
     *  - tx elements (e.g, requests that were sent but not yet freed)
     *  - push cache
     */
    if (is_svm_local(svm)) {
        struct rb_root *root;
        struct rb_node *node;

        BUG_ON(!dsm_state->rcm);
        root = &dsm_state->rcm->root_conn;
        for (node = rb_first(root); node; node = rb_next(node)) {
            struct conn_element *ele;

            ele = rb_entry(node, struct conn_element, rb_node);
            BUG_ON(!ele);
            release_svm_queued_requests(svm, &ele->tx_buffer);
            release_svm_tx_elements(svm, ele);
        }
        release_svm_push_elements(svm);
        destroy_svm_mrs(svm);
    } else if (svm->ele) {
        struct subvirtual_machine *local_svm;

        release_svm_queued_requests(svm, &svm->ele->tx_buffer);
        release_svm_tx_elements(svm, svm->ele);

        /* potentially very expensive way to do this */
        list_for_each_entry (local_svm, &svm->dsm->svm_list, svm_ptr) {
            if (is_svm_local(local_svm))
                surrogate_push_remote_svm(local_svm, svm);
        }
    }

    atomic_dec(&svm->refs);
    release_svm(svm);

out:
    mutex_unlock(&dsm->dsm_mutex);
}



/*
 * memory_region funcs
 */
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

struct memory_region *search_mr_by_addr(struct subvirtual_machine *svm,
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

static int insert_mr(struct subvirtual_machine *svm, struct memory_region *mr)
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

static void destroy_svm_mrs(struct subvirtual_machine *svm)
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
        heca_printk(KERN_INFO "removing dsm_id: %u svm_id: %u, mr_id: %u",
                svm->dsm->dsm_id, svm->svm_id, mr->mr_id);
        synchronize_rcu();
        kfree(mr);
    } while(1);
}

static struct subvirtual_machine *find_local_svm_from_list(struct dsm *dsm)
{
    struct subvirtual_machine *tmp_svm;

    list_for_each_entry (tmp_svm, &dsm->svm_list, svm_ptr) {
        if (!is_svm_local(tmp_svm))
            continue;
        heca_printk(KERN_DEBUG "dsm %d local svm is %d", dsm->dsm_id,
                tmp_svm->svm_id);
        grab_svm(tmp_svm);
        return tmp_svm;
    }
    return NULL;
}

int create_mr(struct hecaioc_mr *udata)
{
    int ret = 0, i;
    struct dsm *dsm;
    struct memory_region *mr = NULL;
    struct subvirtual_machine *local_svm = NULL;

    dsm = find_dsm(udata->dsm_id);
    if (!dsm) {
        heca_printk(KERN_ERR "can't find dsm %d", udata->dsm_id);
        ret = -EFAULT;
        goto out;
    }

    local_svm = find_local_svm_from_list(dsm);
    if (!local_svm) {
        heca_printk(KERN_ERR "can't find local svm for dsm %d", udata->dsm_id);
        ret = -EFAULT;
        goto out;
    }

    /* FIXME: Validate against every kind of overlap! */
    if (search_mr_by_addr(local_svm, (unsigned long) udata->addr)) {
        heca_printk(KERN_ERR "mr already exists at addr 0x%lx", udata->addr);
        ret = -EEXIST;
        goto out;
    }

    mr = kzalloc(sizeof(struct memory_region), GFP_KERNEL);
    if (!mr) {
        heca_printk(KERN_ERR "can't allocate memory for MR");
        ret = -ENOMEM;
        goto out_free;
    }

    mr->mr_id = udata->mr_id;
    mr->addr = (unsigned long) udata->addr;
    mr->sz = udata->sz;

    if (insert_mr(local_svm, mr))
        goto out_free;
    
    mr->descriptor = dsm_get_descriptor(dsm, udata->svm_ids);
    if (!mr->descriptor) {
        heca_printk(KERN_ERR "can't find MR descriptor for svm_ids");
        ret = -EFAULT;
        goto out_free;
    }

    for (i = 0; udata->svm_ids[i]; i++) {
        struct subvirtual_machine *owner;
        u32 svm_id = udata->svm_ids[i];

        owner = find_svm(dsm, svm_id);
        if (!owner) {
            heca_printk(KERN_ERR "[i=%d] can't find svm %d", i, svm_id);
            ret = -EFAULT;
            goto out_remove_tree;
        }

        if (is_svm_local(owner)) {
            mr->flags |= MR_LOCAL;
        }

        release_svm(owner);
    }

    if (udata->flags & UD_COPY_ON_ACCESS)
        mr->flags |= MR_COPY_ON_ACCESS;

    if (!(mr->flags & MR_LOCAL) && (udata->flags & UD_AUTO_UNMAP)) {
        ret = unmap_range(dsm, mr->descriptor, local_svm->pid, mr->addr,
                mr->sz);
    }

    create_mr_sysfs_entry(dsm, mr);
    goto out;

out_remove_tree:
    rb_erase(&mr->rb_node, &local_svm->mr_tree_root);
out_free:
    kfree(mr);
out:
    if (local_svm)
        release_svm(local_svm);
    heca_printk(KERN_INFO "id [%d] addr [0x%lx] sz [0x%lx]"
            " --> ret %d", udata->mr_id, udata->addr, udata->sz, ret);
    return ret;
}

int unmap_ps(struct hecaioc_ps *udata)
{
    int r = -EFAULT;
    struct dsm *dsm = NULL;
    struct subvirtual_machine *local_svm = NULL;
    struct memory_region *mr = NULL;
    struct mm_struct *mm = find_mm_by_pid(udata->pid);

    if (!mm) {
        heca_printk(KERN_ERR "can't find pid %d", udata->pid);
        goto out;
    }

    local_svm = find_local_svm_from_mm(mm);
    if (!local_svm)
        goto out;

    dsm = local_svm->dsm;

    mr = search_mr_by_addr(local_svm, (unsigned long) udata->addr);
    if (!mr)
        goto out;

    r = unmap_range(dsm, mr->descriptor, udata->pid, (unsigned long)
            udata->addr, udata->sz);

out:
    if (local_svm)
        release_svm(local_svm);
    return r;
}

int pushback_ps(struct hecaioc_ps *udata)
{
    int r = -EFAULT;
    unsigned long addr, start_addr;
    struct dsm *dsm;
    struct memory_region *mr;
    struct page *page;
    struct subvirtual_machine *local_svm = NULL;
    struct mm_struct *mm = find_mm_by_pid(udata->pid);

    if (!mm) {
        heca_printk(KERN_ERR "can't find pid %d", udata->pid);
        goto out;
    }

    local_svm = find_local_svm_from_mm(mm);
    if (!local_svm)
        goto out;

    dsm = local_svm->dsm;

    addr = start_addr = ((unsigned long) udata->addr) & PAGE_MASK;
    while (addr < start_addr + udata->sz) {

        mr = search_mr_by_addr(local_svm, addr);
        if (!mr)
            goto out;

        page = dsm_find_normal_page(mm, addr);
        if (!page)
            goto out;

        r = dsm_request_page_pull(dsm, local_svm, page, addr, mm, mr);
        if (r)
            goto out;

        addr += PAGE_SIZE;
    }
out:
    if (local_svm)
        release_svm(local_svm);
    return r;
}

/*
 * rcm funcs
 */
int init_rcm(void)
{
    init_kmem_request_cache();
    init_kmem_deferred_gup_cache();
    init_dsm_cache_kmem();
    init_dsm_prefetch_cache_kmem();
    dsm_init_descriptors();
    return 0;
}

int fini_rcm(void)
{
    destroy_dsm_cache_kmem();
    destroy_dsm_prefetch_cache_kmem();
    destroy_kmem_request_cache();
    destroy_kmem_deferred_gup_cache();
    dsm_destroy_descriptors();
    return 0;
}

int destroy_rcm_listener(struct dsm_module_state *dsm_state);

int create_rcm_listener(struct dsm_module_state *dsm_state, unsigned long ip,
        unsigned short port)
{
    int ret = 0;
    struct rcm *rcm = kzalloc(sizeof(struct rcm), GFP_KERNEL);

    if (!rcm)
        return -ENOMEM;

    mutex_init(&rcm->rcm_mutex);
    seqlock_init(&rcm->conn_lock);
    rcm->node_ip = ip;
    rcm->root_conn = RB_ROOT;

    rcm->cm_id = rdma_create_id(server_event_handler, rcm, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(rcm->cm_id)) {
        rcm->cm_id = NULL;
        ret = PTR_ERR(rcm->cm_id);
        heca_printk(KERN_ERR "Failed rdma_create_id: %d", ret);
        goto failed;
    }

    rcm->sin.sin_family = AF_INET;
    rcm->sin.sin_addr.s_addr = rcm->node_ip;
    rcm->sin.sin_port = port;

    ret = rdma_bind_addr(rcm->cm_id, (struct sockaddr *)&rcm->sin);
    if (ret) {
        heca_printk(KERN_ERR "Failed rdma_bind_addr: %d", ret);
        goto failed;
    }

    rcm->pd = ib_alloc_pd(rcm->cm_id->device);
    if (IS_ERR(rcm->pd)) {
        ret = PTR_ERR(rcm->pd);
        rcm->pd = NULL;
        heca_printk(KERN_ERR "Failed id_alloc_pd: %d", ret);
        goto failed;
    }

    rcm->listen_cq = ib_create_cq(rcm->cm_id->device, listener_cq_handle, NULL,
            rcm, 2, 0);
    if (IS_ERR(rcm->listen_cq)) {
        ret = PTR_ERR(rcm->listen_cq);
        rcm->listen_cq = NULL;
        heca_printk(KERN_ERR "Failed ib_create_cq: %d", ret);
        goto failed;
    }

    if ((ret = ib_req_notify_cq(rcm->listen_cq, IB_CQ_NEXT_COMP))) {
        heca_printk(KERN_ERR "Failed ib_req_notify_cq: %d", ret);
        goto failed;
    }

    rcm->mr = ib_get_dma_mr(rcm->pd, IB_ACCESS_LOCAL_WRITE |
            IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
    if (IS_ERR(rcm->mr)) {
        ret = PTR_ERR(rcm->mr);
        rcm->mr = NULL;
        heca_printk(KERN_ERR "Failed ib_get_dma_mr: %d", ret);
        goto failed;
    }

    dsm_state->rcm = rcm;

    ret = rdma_listen(rcm->cm_id, 2);
    if (ret)
        heca_printk(KERN_ERR "Failed rdma_listen: %d", ret);
    return 0;

failed:
    destroy_rcm_listener(dsm_state);
    return ret;
}

static int rcm_disconnect(struct rcm *rcm)
{
    struct rb_root *root = &rcm->root_conn;
    struct rb_node *node = rb_first(root);
    struct conn_element *ele;

    while (node) {
        ele = rb_entry(node, struct conn_element, rb_node);
        node = rb_next(node);
        if (atomic_cmpxchg(&ele->alive, 1, 0)) {
            rdma_disconnect(ele->cm_id);
            destroy_connection(ele);
        }
    }

    while (rb_first(root))
        ;

    return 0;
}

int destroy_rcm_listener(struct dsm_module_state *dsm_state)
{
    int rc = 0;
    struct rcm *rcm = dsm_state->rcm;

    heca_printk(KERN_DEBUG "<enter>");

    if (!rcm)
        goto done;

    rcm_disconnect(rcm);

    if (!rcm->cm_id)
        goto destroy;

    if (rcm->cm_id->qp) {
        ib_destroy_qp(rcm->cm_id->qp);
        rcm->cm_id->qp = NULL;
    }

    if (rcm->listen_cq) {
        ib_destroy_cq(rcm->listen_cq);
        rcm->listen_cq = NULL;
    }

    if (rcm->mr) {
        ib_dereg_mr(rcm->mr);
        rcm->mr = NULL;
    }

    if (rcm->pd) {
        ib_dealloc_pd(rcm->pd);
        rcm->pd = NULL;
    }

    rdma_destroy_id(rcm->cm_id);
    rcm->cm_id = NULL;

destroy:
    mutex_destroy(&rcm->rcm_mutex);
    kfree(rcm);
    dsm_state->rcm = NULL;

done:
    heca_printk(KERN_DEBUG "<exit> %d", rc);
    return rc;
}


