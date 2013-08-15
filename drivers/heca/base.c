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
 * conn_element funcs
 */
struct heca_connection *search_rb_conn(int node_ip)
{
        struct heca_connections_manager *hcm = get_dsm_module_state()->hcm;
        struct rb_root *root;
        struct rb_node *node;
        struct heca_connection *this = 0;
        unsigned long seq;

        do {
                seq = read_seqbegin(&hcm->connections_lock);
                root = &hcm->connections_rb_tree_root;
                for (node = root->rb_node; node; this = 0) {
                        this = rb_entry(node, struct heca_connection, rb_node);

                        if (node_ip < this->remote_node_ip)
                                node = node->rb_left;
                        else if (node_ip > this->remote_node_ip)
                                node = node->rb_right;
                        else
                                break;
                }
        } while (read_seqretry(&hcm->connections_lock, seq));

        return this;
}

void insert_rb_conn(struct heca_connection *conn)
{
        struct heca_connections_manager *hcm = get_dsm_module_state()->hcm;
        struct rb_root *root;
        struct rb_node **new, *parent = NULL;
        struct heca_connection *this;

        write_seqlock(&hcm->connections_lock);
        root = &hcm->connections_rb_tree_root;
        new = &root->rb_node;
        while (*new) {
                this = rb_entry(*new, struct heca_connection, rb_node);
                parent = *new;
                if (conn->remote_node_ip < this->remote_node_ip)
                        new = &((*new)->rb_left);
                else if (conn->remote_node_ip > this->remote_node_ip)
                        new = &((*new)->rb_right);
        }
        rb_link_node(&conn->rb_node, parent, new);
        rb_insert_color(&conn->rb_node, root);
        write_sequnlock(&hcm->connections_lock);
}

void erase_rb_conn(struct heca_connection *conn)
{
        struct heca_connections_manager *hcm = get_dsm_module_state()->hcm;

        write_seqlock(&hcm->connections_lock);
        rb_erase(&conn->rb_node, &hcm->connections_rb_tree_root);
        write_sequnlock(&hcm->connections_lock);
}

/*
 * heca_space funcs
 */
struct heca_space *find_hspace(u32 id)
{
        struct heca_module_state *heca_state = get_dsm_module_state();
        struct heca_space *hspace;
        struct heca_space **hspacep;
        struct radix_tree_root *root;

        rcu_read_lock();
        root = &heca_state->hspaces_tree_root;
repeat:
        hspace = NULL;
        hspacep = (struct heca_space **) radix_tree_lookup_slot(root,
                        (unsigned long) id);
        if (hspacep) {
                hspace = radix_tree_deref_slot((void **) hspacep);
                if (unlikely(!hspace))
                        goto out;
                if (radix_tree_exception(hspace)) {
                        if (radix_tree_deref_retry(hspace))
                                goto repeat;
                }
        }
out:
        rcu_read_unlock();
        return hspace;
}

void remove_hspace(struct heca_space *hspace)
{
        struct heca_process *hproc;
        struct heca_module_state *heca_state = get_dsm_module_state();
        struct list_head *pos, *n;

        BUG_ON(!hspace);

        heca_printk(KERN_DEBUG "<enter> hspace=%d", hspace->hspace_id);

        list_for_each_safe (pos, n, &hspace->hprocs_list) {
                hproc = list_entry(pos, struct heca_process, hproc_ptr);
                remove_hproc(hspace->hspace_id, hproc->hproc_id);
        }

        mutex_lock(&heca_state->heca_state_mutex);
        list_del(&hspace->hspace_ptr);
        radix_tree_delete(&heca_state->hspaces_tree_root,
                        (unsigned long) hspace->hspace_id);
        mutex_unlock(&heca_state->heca_state_mutex);
        synchronize_rcu();

        delete_dsm_sysfs_entry(&hspace->hspace_kobject);

        mutex_lock(&heca_state->heca_state_mutex);
        kfree(hspace);
        mutex_unlock(&heca_state->heca_state_mutex);

        heca_printk(KERN_DEBUG "<exit>");
}


int create_hspace(__u32 hspace_id)
{
        int r = 0;
        struct heca_space *found_hspace, *new_hspace = NULL;
        struct heca_module_state *heca_state = get_dsm_module_state();

        /* already exists? (first check; the next one is under lock */
        found_hspace = find_hspace(hspace_id);
        if (found_hspace) {
                heca_printk("we already have the hspace in place");
                return -EEXIST;
        }

        /* allocate a new dsm */
        new_hspace = kzalloc(sizeof(*new_hspace), GFP_KERNEL);
        if (!new_hspace) {
                heca_printk("can't allocate");
                return -ENOMEM;
        }
        new_hspace->hspace_id = hspace_id;
        mutex_init(&new_hspace->hspace_mutex);
        INIT_RADIX_TREE(&new_hspace->hprocs_tree_root,
                        GFP_KERNEL & ~__GFP_WAIT);
        INIT_RADIX_TREE(&new_hspace->hprocs_mm_tree_root,
                        GFP_KERNEL & ~__GFP_WAIT);
        INIT_LIST_HEAD(&new_hspace->hprocs_list);
        new_hspace->nb_local_hprocs = 0;

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

        spin_lock(&heca_state->radix_lock);
        r = radix_tree_insert(&heca_state->hspaces_tree_root,
                        (unsigned long) new_hspace->hspace_id, new_hspace);
        spin_unlock(&heca_state->radix_lock);
        radix_tree_preload_end();

        if (r) {
                heca_printk("radix_tree_insert: failed %d", r);
                goto failed;
        }

        r = create_dsm_sysfs_entry(new_hspace, heca_state);
        if (r) {
                heca_printk("create_dsm_sysfs_entry: failed %d", r);
                goto err_delete;
        }

        list_add(&new_hspace->hspace_ptr, &heca_state->hspaces_list);
        heca_printk("registered hspace %p, hspace_id : %u, res: %d",
                        new_hspace, hspace_id, r);
        return r;

err_delete:
        radix_tree_delete(&heca_state->hspaces_tree_root,
                        (unsigned long) hspace_id);
failed:
        kfree(new_hspace);
        return r;
}

/*
 * svm funcs
 */
static void destroy_svm_mrs(struct heca_process *hproc);

static inline int is_svm_local(struct heca_process *svm)
{
        return !!svm->mm;
}

static inline int grab_svm(struct heca_process *hproc)
{
#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT_COUNT
        BUG_ON(!in_atomic());
# endif
        BUG_ON(atomic_read(&hproc->refs) == 0);
        atomic_inc(&hproc->refs);
#else
        if (!atomic_inc_not_zero(&hproc->refs))
                return -1;
#endif
        return 0;
}

static struct heca_process *_find_svm_in_tree(
                struct radix_tree_root *root, unsigned long hproc_id)
{
        struct heca_process *hproc;
        struct heca_process **hprocp;

        rcu_read_lock();
repeat:
        hproc = NULL;
        hprocp = (struct heca_process **) radix_tree_lookup_slot(root,
                        (unsigned long) hproc_id);
        if (hprocp) {
                hproc = radix_tree_deref_slot((void**) hprocp);
                if (unlikely(!hproc))
                        goto out;
                if (radix_tree_exception(hproc)) {
                        if (radix_tree_deref_retry(hproc))
                                goto repeat;
                }

                if (grab_svm(hproc))
                        goto repeat;

        }

out:
        rcu_read_unlock();
        return hproc;
}

inline struct heca_process *find_hproc(struct heca_space *hspace, u32 hproc_id)
{
        return _find_svm_in_tree(&hspace->hprocs_tree_root,
                        (unsigned long) hproc_id);
}

inline struct heca_process *find_local_hproc_in_hspace(struct heca_space *hspace,
                struct mm_struct *mm)
{
        return _find_svm_in_tree(&hspace->hprocs_mm_tree_root,
                        (unsigned long) mm);
}

inline struct heca_process *find_local_hproc_from_mm(struct mm_struct *mm)
{
        struct heca_module_state *mod = get_dsm_module_state();

        return (likely(mod)) ?
                _find_svm_in_tree(&mod->mm_tree_root, (unsigned long) mm) :
                NULL;
}

static int insert_svm_to_radix_trees(struct heca_module_state *heca_state,
                struct heca_space *hspace, struct heca_process *new_hproc)
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


        spin_lock(&heca_state->radix_lock);
        r = radix_tree_insert(&hspace->hprocs_tree_root,
                        (unsigned long) new_hproc->hproc_id, new_hproc);
        if (r)
                goto unlock;

        if (is_svm_local(new_hproc)) {
                r = radix_tree_insert(&hspace->hprocs_mm_tree_root,
                                (unsigned long) new_hproc->mm, new_hproc);
                if (r)
                        goto unlock;

                r = radix_tree_insert(&heca_state->mm_tree_root,
                                (unsigned long) new_hproc->mm, new_hproc);
        }

unlock:
        spin_unlock(&heca_state->radix_lock);

        radix_tree_preload_end();
        if (r) {
                heca_printk(KERN_ERR "failed radix_tree_insert %d", r);
                radix_tree_delete(&hspace->hprocs_tree_root,
                                (unsigned long) new_hproc->hproc_id);
                if (is_svm_local(new_hproc)) {
                        radix_tree_delete(&hspace->hprocs_mm_tree_root,
                                        (unsigned long) new_hproc->mm);
                        radix_tree_delete(&heca_state->mm_tree_root,
                                        (unsigned long) new_hproc->mm);
                }
        }

out:
        return r;
}

int create_hproc(struct hecaioc_hproc *hproc_info)
{
        struct heca_module_state *heca_state = get_dsm_module_state();
        int r = 0;
        struct heca_space *hspace;
        struct heca_process *found_hproc, *new_hproc = NULL;

        /* allocate a new hproc */
        new_hproc = kzalloc(sizeof(*new_hproc), GFP_KERNEL);
        if (!new_hproc) {
                heca_printk(KERN_ERR "failed kzalloc");
                return -ENOMEM;
        }

        /* grab hspace lock */
        mutex_lock(&heca_state->heca_state_mutex);
        hspace = find_hspace(hproc_info->hspace_id);
        if (hspace)
                mutex_lock(&hspace->hspace_mutex);
        mutex_unlock(&heca_state->heca_state_mutex);
        if (!hspace) {
                heca_printk(KERN_ERR "could not find hspace: %d",
                                hproc_info->hspace_id);
                r = -EFAULT;
                goto no_hspace;
        }

        /* already exists? */
        found_hproc = find_hproc(hspace, hproc_info->hproc_id);
        if (found_hproc) {
                heca_printk(KERN_ERR "hproc %d (hspace %d) already exists",
                                hproc_info->hproc_id, hproc_info->hspace_id);
                r = -EEXIST;
                goto out;
        }

        /* initial hproc data */
        new_hproc->hproc_id = hproc_info->hproc_id;
        new_hproc->is_local = hproc_info->is_local;
        new_hproc->pid = hproc_info->pid;
        new_hproc->hspace = hspace;
        atomic_set(&new_hproc->refs, 2);

        /* register local hproc */
        if (hproc_info->is_local) {
                struct mm_struct *mm;

                mm = find_mm_by_pid(new_hproc->pid);
                if (!mm) {
                        heca_printk(KERN_ERR "can't find pid %d",
                                        new_hproc->pid);
                        r = -ESRCH;
                        goto out;
                }

                found_hproc = find_local_hproc_from_mm(mm);
                if (found_hproc) {
                        heca_printk(KERN_ERR "Hproc already exists for current process");
                        r = -EEXIST;
                        goto out;
                }

                new_hproc->mm = mm;
                new_hproc->hspace->nb_local_hprocs++;
                new_hproc->hmr_tree_root = RB_ROOT;
                seqlock_init(&new_hproc->hmr_seq_lock);
                new_hproc->hmr_cache = NULL;

                init_llist_head(&new_hproc->delayed_gup);
                INIT_DELAYED_WORK(&new_hproc->delayed_gup_work,
                                delayed_gup_work_fn);
                init_llist_head(&new_hproc->deferred_gups);
                INIT_WORK(&new_hproc->deferred_gup_work, deferred_gup_work_fn);

                spin_lock_init(&new_hproc->page_cache_spinlock);
                spin_lock_init(&new_hproc->page_readers_spinlock);
                spin_lock_init(&new_hproc->page_maintainers_spinlock);
                INIT_RADIX_TREE(&new_hproc->page_cache, GFP_ATOMIC);
                INIT_RADIX_TREE(&new_hproc->page_readers, GFP_ATOMIC);
                INIT_RADIX_TREE(&new_hproc->page_maintainers, GFP_ATOMIC);
                new_hproc->push_cache = RB_ROOT;
                seqlock_init(&new_hproc->push_cache_lock);
        }

        r = create_svm_sysfs_entry(new_hproc);
        if (r) {
                heca_printk(KERN_ERR "failed create_svm_sysfs_entry %d", r);
                goto out;
        }

        /* register hproc by id and mm_struct (must come before dsm_get_descriptor) */
        if (insert_svm_to_radix_trees(heca_state, hspace, new_hproc))
                goto out;
        list_add(&new_hproc->hproc_ptr, &hspace->hprocs_list);

        /* assign descriptor for remote hproc */
        if (!is_svm_local(new_hproc)) {
                u32 hproc_ids[] = {new_hproc->hproc_id, 0};
                new_hproc->descriptor = dsm_get_descriptor(hspace->hspace_id,
                                hproc_ids);
        }

out:
        mutex_unlock(&hspace->hspace_mutex);
        if (found_hproc)
                release_hproc(found_hproc);

        if (r) {
                kfree(new_hproc);
                new_hproc = NULL;
                goto no_hspace;
        }

        if (!hproc_info->is_local) {
                r = connect_svm(hproc_info->hspace_id, hproc_info->hproc_id,
                                hproc_info->remote.sin_addr.s_addr,
                                hproc_info->remote.sin_port);

                if (r) {
                        heca_printk(KERN_ERR "connect_hproc failed %d", r);
                        kfree(new_hproc);
                        new_hproc = NULL;
                }
        }
no_hspace:
        heca_printk(KERN_INFO "hproc %p, res %d, hspace_id %u, hproc_id: %u --> ret %d",
                        new_hproc, r, hproc_info->hspace_id,
                        hproc_info->hproc_id, r);
        return r;
}

inline void release_hproc(struct heca_process *hproc)
{
        atomic_dec(&hproc->refs);
        if (atomic_cmpxchg(&hproc->refs, 1, 0) == 1) {
                trace_free_svm(hproc->hproc_id);
                delete_svm_sysfs_entry(&hproc->hproc_kobject);
                synchronize_rcu();
                kfree(hproc);
        }
}

/*
 * We dec page's refcount for every missing remote response (it would have
 * happened in dsm_ppe_clear_release after sending an answer to remote hproc)
 */
static void surrogate_push_remote_svm(struct heca_process *hproc,
                struct heca_process *remote_hproc)
{
        struct rb_node *node;

        write_seqlock(&hproc->push_cache_lock);
        for (node = rb_first(&hproc->push_cache); node;) {
                struct heca_page_cache *hpc;
                int i;
                hpc = rb_entry(node, struct heca_page_cache, rb_node);
                node = rb_next(node);
                for (i = 0; i < hpc->hprocs.num; i++) {
                        if (hpc->hprocs.ids[i] == remote_hproc->hproc_id)
                                goto surrogate;
                }
                continue;

surrogate:
                if (likely(test_and_clear_bit(i, &hpc->bitmap))) {
                        page_cache_release(hpc->pages[0]);
                        atomic_dec(&hpc->nproc);
                        if (atomic_cmpxchg(&hpc->nproc, 1, 0) ==
                                        1 && find_first_bit(&hpc->bitmap,
                                                hpc->hprocs.num) >= hpc->hprocs.num)
                                dsm_push_cache_release(hpc->hproc, &hpc, 0);
                }
        }
        write_sequnlock(&hproc->push_cache_lock);
}

static void release_svm_push_elements(struct heca_process *hproc)
{
        struct rb_node *node;

        write_seqlock(&hproc->push_cache_lock);
        for (node = rb_first(&hproc->push_cache); node;) {
                struct heca_page_cache *hpc;
                int i;

                hpc = rb_entry(node, struct heca_page_cache, rb_node);
                node = rb_next(node);
                /*
                 * dpc->svms has a pointer to the descriptor ids array, which already
                 * changed. we need to rely on the bitmap right now.
                 */
                for (i = 0; i < hpc->hprocs.num; i++) {
                        if (test_and_clear_bit(i, &hpc->bitmap))
                                page_cache_release(hpc->pages[0]);
                }
                dsm_push_cache_release(hpc->hproc, &hpc, 0);
        }
        write_sequnlock(&hproc->push_cache_lock);
}

/*
 * pull ops tx_elements are only released after a response has returned.
 * therefore we can catch them and surrogate for them by iterating the tx
 * buffer.
 */
static void release_svm_tx_elements(struct heca_process *hproc,
                struct heca_connection *conn)
{
        struct tx_buffer_element *tx_buf;
        int i;

        /* killed before it was first connected */
        if (!conn || !conn->tx_buffer.tx_buf)
                return;

        tx_buf = conn->tx_buffer.tx_buf;

        for (i = 0; i < conn->tx_buffer.len; i++) {
                struct tx_buffer_element *tx_e = &tx_buf[i];
                struct heca_message *msg = tx_e->hmsg_buffer;
                int types = MSG_REQ_PAGE | MSG_REQ_PAGE_TRY |
                        MSG_RES_PAGE_FAIL | MSG_REQ_READ;

                if (msg->type & types && msg->dsm_id == hproc->hspace->hspace_id
                                && (msg->src_id == hproc->hproc_id
                                || msg->dest_id == hproc->hproc_id)
                                && atomic_cmpxchg(&tx_e->used, 1, 2) == 1) {
                        struct heca_page_cache *dpc = tx_e->wrk_req->hpc;

                        dsm_pull_req_failure(dpc);
                        tx_e->wrk_req->dst_addr->mem_page = NULL;
                        dsm_release_pull_dpc(&dpc);
                        dsm_ppe_clear_release(conn, &tx_e->wrk_req->dst_addr);

                        /* rdma processing already finished, we have to release ourselves */
                        smp_mb();
                        if (atomic_read(&tx_e->used) > 2)
                                try_release_tx_element(conn, tx_e);
                }
        }
}

static void release_svm_queued_requests(struct heca_process *hproc,
                struct tx_buffer *tx)
{
        struct heca_request *req, *n;
        u32 hproc_id = hproc->hproc_id;

        mutex_lock(&tx->flush_mutex);
        dsm_request_queue_merge(tx);
        list_for_each_entry_safe (req, n,
                        &tx->ordered_request_queue, ordered_list){
                if (req->remote_hproc_id == hproc_id ||
                                req->local_hproc_id == hproc_id) {
                        list_del(&req->ordered_list);
                        if (req->hpc && req->hpc->tag == PULL_TAG)
                                dsm_release_pull_dpc(&req->hpc);
                        release_dsm_request(req);
                }
        }
        mutex_unlock(&tx->flush_mutex);
}

void remove_hproc(u32 hspace_id, u32 hproc_id)
{
        struct heca_module_state *heca_state = get_dsm_module_state();
        struct heca_space *hspace;
        struct heca_process *hproc = NULL;

        mutex_lock(&heca_state->heca_state_mutex);
        hspace = find_hspace(hspace_id);
        if (!hspace) {
                mutex_unlock(&heca_state->heca_state_mutex);
                return;
        }

        mutex_lock(&hspace->hspace_mutex);
        hproc = find_hproc(hspace, hproc_id);
        if (!hproc) {
                mutex_unlock(&heca_state->heca_state_mutex);
                goto out;
        }
        if (is_svm_local(hproc)) {
                radix_tree_delete(&get_dsm_module_state()->mm_tree_root,
                                (unsigned long) hproc->mm);
        }
        mutex_unlock(&heca_state->heca_state_mutex);

        list_del(&hproc->hproc_ptr);
        radix_tree_delete(&hspace->hprocs_tree_root, (unsigned long) hproc->hproc_id);
        if (is_svm_local(hproc)) {
                cancel_delayed_work_sync(&hproc->delayed_gup_work);
                // to make sure everything is clean
                dequeue_and_gup_cleanup(hproc);
                hspace->nb_local_hprocs--;
                radix_tree_delete(&hspace->hprocs_mm_tree_root,
                                (unsigned long) hproc->mm);
        }

        remove_svm_from_descriptors(hproc);

        /*
         * we removed the svm from all descriptors and trees, so we won't make any
         * new operations concerning it. now we only have to make sure to cancel
         * all pending operations involving this svm, and it will be safe to remove
         * it.
         *
         * we cannot actually hold until every operation is complete, so we rely on
         * refcounting. and yet we try to catch every operation, and be a surrogate
         * for it, if possible; otherwise we just trust it to drop the refcount when
         * it finishes. the main point is catching all operations, not leaving
         * anything unattended (thus creating a resource leak).
         *
         * we catch all pending operations using (by order) the queued requests
         * lists, the tx elements buffers, and the push caches of svms.
         *
         * FIXME: what about pull operations, in which we remove_svm() after
         * find_svm(), but before tx_dsm_send()??? We can't disable preemption
         * there, but we might lookup_svm() after we send, and handle the case in
         * which it isn't!
         * FIXME: the same problem is valid for push operations!
         */
        if (is_svm_local(hproc)) {
                struct rb_root *root;
                struct rb_node *node;

                if (heca_state->hcm) {
                        root = &heca_state->hcm->connections_rb_tree_root;
                        for (node = rb_first(root);
                                        node; node = rb_next(node)) {
                                struct heca_connection *ele;

                                ele = rb_entry(node,
                                                struct heca_connection, rb_node);
                                BUG_ON(!ele);
                                release_svm_queued_requests(hproc,
                                                &ele->tx_buffer);
                                release_svm_tx_elements(hproc, ele);
                        }
                }
                release_svm_push_elements(hproc);
                destroy_svm_mrs(hproc);
        } else if (hproc->connection) {
                struct heca_process *local_svm;

                release_svm_queued_requests(hproc, &hproc->connection->tx_buffer);
                release_svm_tx_elements(hproc, hproc->connection);

                /* potentially very expensive way to do this */
                list_for_each_entry (local_svm, &hproc->hspace->hprocs_list, hproc_ptr) {
                        if (is_svm_local(local_svm))
                                surrogate_push_remote_svm(local_svm, hproc);
                }
        }

        atomic_dec(&hproc->refs);
        release_hproc(hproc);

out:
        mutex_unlock(&hspace->hspace_mutex);
}

struct heca_process *find_any_hproc(struct heca_space *hspace, struct heca_process_list hprocs)
{
        int i;
        struct heca_process *hproc;

        for_each_valid_hproc(hprocs, i) {
                hproc = find_hproc(hspace, hprocs.ids[i]);
                if (likely(hproc))
                        return hproc;
        }

        return NULL;
}


/*
 * memory_region funcs
 */
struct heca_memory_region *find_heca_mr(struct heca_process *hproc,
                u32 id)
{
        struct heca_memory_region *mr, **mrp;
        struct radix_tree_root *root;

        rcu_read_lock();
        root = &hproc->hmr_id_tree_root;
repeat:
        mr = NULL;
        mrp = (struct heca_memory_region **) radix_tree_lookup_slot(root,
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

struct heca_memory_region *search_heca_mr_by_addr(struct heca_process *hproc,
                unsigned long addr)
{
        struct rb_root *root = &hproc->hmr_tree_root;
        struct rb_node *node;
        struct heca_memory_region *this = hproc->hmr_cache;
        unsigned long seq;

        /* try to follow cache hint */
        if (likely(this)) {
                if (addr >= this->addr && addr < this->addr + this->sz)
                        goto out;
        }

        do {
                seq = read_seqbegin(&hproc->hmr_seq_lock);
                for (node = root->rb_node; node; this = 0) {
                        this = rb_entry(node, struct heca_memory_region, rb_node);

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
        } while (read_seqretry(&hproc->hmr_seq_lock, seq));

        if (likely(this))
                hproc->hmr_cache = this;

out:
        return this;
}

static int insert_mr(struct heca_process *hproc, struct heca_memory_region *mr)
{
        struct rb_root *root = &hproc->hmr_tree_root;
        struct rb_node **new = &root->rb_node, *parent = NULL;
        struct heca_memory_region *this;
        int r;

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
                goto fail;

        write_seqlock(&hproc->hmr_seq_lock);

        /* insert to radix tree */
        r = radix_tree_insert(&hproc->hmr_id_tree_root, (unsigned long) mr->hmr_id,
                        mr);
        if (r)
                goto out;

        /* insert to rb tree */
        while (*new) {
                this = rb_entry(*new, struct heca_memory_region, rb_node);
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
        write_sequnlock(&hproc->hmr_seq_lock);
fail:
        return r;
}

static void destroy_svm_mrs(struct heca_process *hproc)
{
        struct rb_root *root = &hproc->hmr_tree_root;

        do {
                struct heca_memory_region *mr;
                struct rb_node *node;

                write_seqlock(&hproc->hmr_seq_lock);
                node = rb_first(root);
                if (!node) {
                        write_sequnlock(&hproc->hmr_seq_lock);
                        break;
                }
                mr = rb_entry(node, struct heca_memory_region, rb_node);
                rb_erase(&mr->rb_node, root);
                write_sequnlock(&hproc->hmr_seq_lock);
                heca_printk(KERN_INFO "removing dsm_id: %u svm_id: %u, mr_id: %u",
                                hproc->hspace->hspace_id, hproc->hproc_id, mr->hmr_id);
                synchronize_rcu();
                kfree(mr);
        } while(1);
}

static struct heca_process *find_local_svm_from_list(struct heca_space *hspace)
{
        struct heca_process *tmp_hproc;

        list_for_each_entry (tmp_hproc, &hspace->hprocs_list, hproc_ptr) {
                if (!is_svm_local(tmp_hproc))
                        continue;
                heca_printk(KERN_DEBUG "hspace %d local hproc is %d", hspace->hspace_id,
                                tmp_hproc->hproc_id);
                grab_svm(tmp_hproc);
                return tmp_hproc;
        }
        return NULL;
}

int create_heca_mr(struct hecaioc_hmr *udata)
{
        int ret = 0, i;
        struct heca_space *hspace;
        struct heca_memory_region *mr = NULL;
        struct heca_process *local_hproc = NULL;

        hspace = find_hspace(udata->hspace_id);
        if (!hspace) {
                heca_printk(KERN_ERR "can't find dsm %d", udata->hspace_id);
                ret = -EFAULT;
                goto out;
        }

        local_hproc = find_local_svm_from_list(hspace);
        if (!local_hproc) {
                heca_printk(KERN_ERR "can't find local hproc for hspace %d",
                                udata->hspace_id);
                ret = -EFAULT;
                goto out;
        }

        /* FIXME: Validate against every kind of overlap! */
        if (search_heca_mr_by_addr(local_hproc, (unsigned long) udata->addr)) {
                heca_printk(KERN_ERR "mr already exists at addr 0x%lx",
                                udata->addr);
                ret = -EEXIST;
                goto out;
        }

        mr = kzalloc(sizeof(struct heca_memory_region), GFP_KERNEL);
        if (!mr) {
                heca_printk(KERN_ERR "can't allocate memory for MR");
                ret = -ENOMEM;
                goto out_free;
        }

        mr->hmr_id = udata->hmr_id;
        mr->addr = (unsigned long) udata->addr;
        mr->sz = udata->sz;

        if (insert_mr(local_hproc, mr)){
                heca_printk(KERN_ERR "insert MR failed  addr 0x%lx",
                                udata->addr);
                ret = -EFAULT;
                goto out_free;
        }
        mr->descriptor = dsm_get_descriptor(hspace->hspace_id, udata->hproc_ids);
        if (!mr->descriptor) {
                heca_printk(KERN_ERR "can't find MR descriptor for hproc_ids");
                ret = -EFAULT;
                goto out_remove_tree;
        }

        for (i = 0; udata->hproc_ids[i]; i++) {
                struct heca_process *owner;
                u32 svm_id = udata->hproc_ids[i];

                owner = find_hproc(hspace, svm_id);
                if (!owner) {
                        heca_printk(KERN_ERR "[i=%d] can't find hproc %d",
                                        i, svm_id);
                        ret = -EFAULT;
                        goto out_remove_tree;
                }

                if (is_svm_local(owner)) {
                        mr->flags |= MR_LOCAL;
                }

                release_hproc(owner);
        }

        if (udata->flags & UD_COPY_ON_ACCESS) {
                mr->flags |= MR_COPY_ON_ACCESS;
                if (udata->flags & UD_SHARED)
                        goto out_remove_tree;
        } else if (udata->flags & UD_SHARED) {
                mr->flags |= MR_SHARED;
        }

        if (!(mr->flags & MR_LOCAL) && (udata->flags & UD_AUTO_UNMAP)) {
                ret = unmap_range(hspace, mr->descriptor, local_hproc->pid, mr->addr,
                                mr->sz);
        }

        create_mr_sysfs_entry(local_hproc, mr);
        goto out;

out_remove_tree:
        rb_erase(&mr->rb_node, &local_hproc->hmr_tree_root);
out_free:
        kfree(mr);
out:
        if (local_hproc)
                release_hproc(local_hproc);
        heca_printk(KERN_INFO "id [%d] addr [0x%lx] sz [0x%lx] --> ret %d",
                        udata->hmr_id, udata->addr, udata->sz, ret);
        return ret;
}

int unmap_ps(struct hecaioc_ps *udata)
{
        int r = -EFAULT;
        struct heca_space *hspace = NULL;
        struct heca_process *local_hproc = NULL;
        struct heca_memory_region *mr = NULL;
        struct mm_struct *mm = find_mm_by_pid(udata->pid);

        if (!mm) {
                heca_printk(KERN_ERR "can't find pid %d", udata->pid);
                goto out;
        }

        local_hproc = find_local_hproc_from_mm(mm);
        if (!local_hproc)
                goto out;

        hspace = local_hproc->hspace;

        mr = search_heca_mr_by_addr(local_hproc, (unsigned long) udata->addr);
        if (!mr)
                goto out;

        r = unmap_range(hspace, mr->descriptor, udata->pid, (unsigned long)
                        udata->addr, udata->sz);

out:
        if (local_hproc)
                release_hproc(local_hproc);
        return r;
}

int pushback_ps(struct hecaioc_ps *udata)
{
        int r = -EFAULT;
        unsigned long addr, start_addr;
        struct page *page;
        struct mm_struct *mm = find_mm_by_pid(udata->pid);

        if (!mm) {
                heca_printk(KERN_ERR "can't find pid %d", udata->pid);
                goto out;
        }

        addr = start_addr = ((unsigned long) udata->addr) & PAGE_MASK;
        for (addr = start_addr; addr < start_addr + udata->sz;
                        addr += PAGE_SIZE) {
                page = dsm_find_normal_page(mm, addr);
                if (!page || !trylock_page(page))
                        continue;

                r = !push_back_if_remote_dsm_page(page);
                if (r)
                        unlock_page(page);
        }

out:
        return r;
}

/*
 * rcm funcs
 */
int init_hcm(void)
{
        init_kmem_request_cache();
        init_kmem_deferred_gup_cache();
        init_dsm_cache_kmem();
        init_dsm_reader_kmem();
        init_dsm_prefetch_cache_kmem();
        dsm_init_descriptors();
        return 0;
}

int fini_hcm(void)
{
        destroy_dsm_cache_kmem();
        destroy_dsm_prefetch_cache_kmem();
        destroy_kmem_request_cache();
        destroy_kmem_deferred_gup_cache();
        dsm_destroy_descriptors();
        return 0;
}

int destroy_hcm_listener(struct heca_module_state *heca_state);

int create_hcm_listener(struct heca_module_state *heca_state, unsigned long ip,
                unsigned short port)
{
        int ret = 0;
        struct heca_connections_manager *hcm = kzalloc(sizeof(struct heca_connections_manager), GFP_KERNEL);

        if (!hcm)
                return -ENOMEM;

        mutex_init(&hcm->hcm_mutex);
        seqlock_init(&hcm->connections_lock);
        hcm->node_ip = ip;
        hcm->connections_rb_tree_root = RB_ROOT;

        hcm->cm_id = rdma_create_id(server_event_handler, hcm, RDMA_PS_TCP,
                        IB_QPT_RC);
        if (IS_ERR(hcm->cm_id)) {
                hcm->cm_id = NULL;
                ret = PTR_ERR(hcm->cm_id);
                heca_printk(KERN_ERR "Failed rdma_create_id: %d", ret);
                goto failed;
        }

        hcm->sin.sin_family = AF_INET;
        hcm->sin.sin_addr.s_addr = hcm->node_ip;
        hcm->sin.sin_port = port;

        ret = rdma_bind_addr(hcm->cm_id, (struct sockaddr *)&hcm->sin);
        if (ret) {
                heca_printk(KERN_ERR "Failed rdma_bind_addr: %d", ret);
                goto failed;
        }

        hcm->pd = ib_alloc_pd(hcm->cm_id->device);
        if (IS_ERR(hcm->pd)) {
                ret = PTR_ERR(hcm->pd);
                hcm->pd = NULL;
                heca_printk(KERN_ERR "Failed id_alloc_pd: %d", ret);
                goto failed;
        }

        hcm->listen_cq = ib_create_cq(hcm->cm_id->device, listener_cq_handle,
                        NULL, hcm, 2, 0);
        if (IS_ERR(hcm->listen_cq)) {
                ret = PTR_ERR(hcm->listen_cq);
                hcm->listen_cq = NULL;
                heca_printk(KERN_ERR "Failed ib_create_cq: %d", ret);
                goto failed;
        }

        if ((ret = ib_req_notify_cq(hcm->listen_cq, IB_CQ_NEXT_COMP))) {
                heca_printk(KERN_ERR "Failed ib_req_notify_cq: %d", ret);
                goto failed;
        }

        hcm->mr = ib_get_dma_mr(hcm->pd, IB_ACCESS_LOCAL_WRITE |
                        IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
        if (IS_ERR(hcm->mr)) {
                ret = PTR_ERR(hcm->mr);
                hcm->mr = NULL;
                heca_printk(KERN_ERR "Failed ib_get_dma_mr: %d", ret);
                goto failed;
        }

        heca_state->hcm = hcm;

        ret = rdma_listen(hcm->cm_id, 2);
        if (ret)
                heca_printk(KERN_ERR "Failed rdma_listen: %d", ret);
        return 0;

failed:
        destroy_hcm_listener(heca_state);
        return ret;
}

static int rcm_disconnect(struct heca_connections_manager *hcm)
{
        struct rb_root *root = &hcm->connections_rb_tree_root;
        struct rb_node *node = rb_first(root);
        struct heca_connection *conn;

        while (node) {
                conn = rb_entry(node, struct heca_connection, rb_node);
                node = rb_next(node);
                if (atomic_cmpxchg(&conn->alive, 1, 0)) {
                        rdma_disconnect(conn->cm_id);
                        destroy_connection(conn);
                }
        }

        while (rb_first(root))
                ;

        return 0;
}

int destroy_hcm_listener(struct heca_module_state *heca_state)
{
        int rc = 0;
        struct heca_connections_manager *hcm = heca_state->hcm;

        heca_printk(KERN_DEBUG "<enter>");

        if (!hcm)
                goto done;

        if (!list_empty(&heca_state->hspaces_list)) {
                heca_printk(KERN_INFO "can't delete hcm - hspaces exist");
                rc = -EBUSY;
        }

        rcm_disconnect(hcm);

        if (!hcm->cm_id)
                goto destroy;

        if (hcm->cm_id->qp) {
                ib_destroy_qp(hcm->cm_id->qp);
                hcm->cm_id->qp = NULL;
        }

        if (hcm->listen_cq) {
                ib_destroy_cq(hcm->listen_cq);
                hcm->listen_cq = NULL;
        }

        if (hcm->mr) {
                ib_dereg_mr(hcm->mr);
                hcm->mr = NULL;
        }

        if (hcm->pd) {
                ib_dealloc_pd(hcm->pd);
                hcm->pd = NULL;
        }

        rdma_destroy_id(hcm->cm_id);
        hcm->cm_id = NULL;

destroy:
        mutex_destroy(&hcm->hcm_mutex);
        kfree(hcm);
        heca_state->hcm = NULL;

done:
        heca_printk(KERN_DEBUG "<exit> %d", rc);
        return rc;
}


