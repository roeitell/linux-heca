/*
 * Benoit Hudzia <benoit.hudzia@sap.com>
 * Aidan Shribman <aidan.shribman@sap.com>
 */

#include <linux/list.h>
#include <linux/delay.h>
#include <linux/dsm_hook.h>
#include <dsm/dsm_mem.h>
#include <dsm/dsm_module.h>

static char *ip = 0;
static int port = 0;

module_param(ip, charp, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ip, "The ip of the machine running this module - will be used"
       " as node_id.");
module_param(port, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(port, "The port on the machine running this module - used for"
       " DSM_RDMA communication.");

static inline int is_svm_local(struct subvirtual_machine *svm)
{
    return !!svm->mm;
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

void remove_dsm(struct dsm *dsm)
{
    struct subvirtual_machine *svm;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    struct list_head *pos, *n;

    dsm_printk("removing dsm %d", dsm->dsm_id);

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
}

/* FIXME: just a dummy lock so that radix_tree functions work */
DEFINE_SPINLOCK(dsm_lock); 

static int register_dsm(struct private_data *priv_data, void __user *argp)
{
    int r = 0;
    struct svm_data svm_info;
    struct dsm *found_dsm, *new_dsm = NULL;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk("reading data from userspace failed");
        return -EFAULT;
    }

    /* already exists? (first check; the next one is under lock */
    found_dsm = find_dsm(svm_info.dsm_id);
    if (found_dsm) {
        dsm_printk("we already have the dsm in place");
        return -EEXIST;
    }

    /* allocate a new dsm */
    new_dsm = kzalloc(sizeof(*new_dsm), GFP_KERNEL);
    if (!new_dsm) {
        dsm_printk("can't allocate");
        return -ENOMEM;
    }
    new_dsm->dsm_id = svm_info.dsm_id;
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
            dsm_printk("radix_tree_preload: ENOMEM retrying ...");
            mdelay(2);
            continue;
        }

        dsm_printk("radix_tree_preload: failed %d", r);
        goto failed;
    }

    /* TODO: move this spin lock to be part of dsm_state */
    spin_lock(&dsm_lock);
    r = radix_tree_insert(&dsm_state->dsm_tree_root,
		    (unsigned long) new_dsm->dsm_id, new_dsm);
    spin_unlock(&dsm_lock);
    radix_tree_preload_end();

    if (r) {
        dsm_printk("radix_tree_insert: failed %d", r);
        goto failed;
    }

    r = create_dsm_sysfs_entry(new_dsm, dsm_state);
    if (r) {
        dsm_printk("create_dsm_sysfs_entry: failed %d", r);
        goto err_delete;
    }

    priv_data->dsm = new_dsm;
    list_add(&new_dsm->dsm_ptr, &dsm_state->dsm_list);
    dsm_printk("registered dsm %p,  dsm_id : %u, res: %d \n",
            new_dsm, svm_info.dsm_id, r);
    return r;

err_delete:
    radix_tree_delete(&dsm_state->dsm_tree_root,
            (unsigned long) svm_info.dsm_id);
failed:
    kfree(new_dsm);
    return r;
}

int is_svm_current(struct subvirtual_machine *svm)
{
    return !!(svm->mm && svm->mm == current->mm);
}

static int insert_svm_to_radix_trees(struct dsm_module_state *dsm_state,
        struct dsm *dsm, struct subvirtual_machine *new_svm)
{
    int r;

preload:
    r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
    if (r) {
        if (r == -ENOMEM) {
            dsm_printk(KERN_ERR "radix_tree_preload: ENOMEM retrying ...");
            mdelay(2);
            goto preload;
        }
        dsm_printk(KERN_ERR "radix_tree_preload: failed %d\n", r);
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
        printk(KERN_ERR "failed radix_tree_insert %d\n", r);
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

static int register_svm(struct private_data *priv_data, void __user *argp)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int r = 0;
    struct dsm *dsm;
    struct subvirtual_machine *found_svm, *new_svm = NULL;
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk("failed to copy from user");
        return -EFAULT;
    }

    /* allocate a new svm */
    new_svm = kzalloc(sizeof(*new_svm), GFP_KERNEL);
    if (!new_svm) {
        dsm_printk(KERN_ERR "failed kzalloc");
        return -ENOMEM;
    }

    /* grab dsm lock */
    mutex_lock(&dsm_state->dsm_state_mutex);
    dsm = find_dsm(svm_info.dsm_id);
    if (dsm)
        mutex_lock(&dsm->dsm_mutex);
    mutex_unlock(&dsm_state->dsm_state_mutex);
    if (!dsm) {
        dsm_printk(KERN_ERR "could not find dsm: %d", svm_info.dsm_id);
        r = -EFAULT;
        goto no_dsm;
    }

    /* already exists? */
    found_svm = find_svm(dsm, svm_info.svm_id);
    if (found_svm) {
        dsm_printk(KERN_ERR "svm %d (dsm %d) already exists",
            svm_info.svm_id, svm_info.dsm_id);
        r = -EEXIST;
        goto out;
    }

    /* initial svm data */
    new_svm->svm_id = svm_info.svm_id;
    new_svm->dsm = dsm;
    atomic_set(&new_svm->refs, 2);

    /* register local svm */
    if (svm_info.local) {
        /* current process already registered an svm? */
        found_svm = find_local_svm(current->mm);
        if (found_svm) {
            dsm_printk(KERN_ERR "svm already exists for current process\n");
            r = -EEXIST;
            goto out;
        }

        new_svm->mm = current->mm;
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
        dsm_printk(KERN_ERR "failed create_svm_sysfs_entry %d", r);
        goto out;
    }

    /* register svm by id and mm_struct (must come before dsm_get_descriptor) */
    if (insert_svm_to_radix_trees(dsm_state, dsm, new_svm))
        goto out;
    list_add(&new_svm->svm_ptr, &dsm->svm_list);

    /* assign descriptor for remote svm */
    if (!is_svm_local(new_svm)) {
        u32 svm_id[] = {new_svm->svm_id, 0};
        new_svm->descriptor = dsm_get_descriptor(dsm, svm_id);
    }

out:
    mutex_unlock(&dsm->dsm_mutex);
    if (found_svm)
        release_svm(found_svm);
    if (r)
        kfree(new_svm);

no_dsm:
    dsm_printk(KERN_INFO "svm %p, res %d, dsm_id %u, svm_id: %u --> ret %d",
            new_svm, r, svm_info.dsm_id, svm_info.svm_id, r);
    return r;
}

static int connect_svm(struct private_data *priv_data, void __user *argp)
{
    int r = 0, ip_addr;
    struct dsm *dsm;
    struct subvirtual_machine *svm;
    struct svm_data svm_info;
    struct conn_element *cele;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    r = copy_from_user((void *) &svm_info, argp, sizeof svm_info);
    if (r) {
        dsm_printk(KERN_ERR "copy_from_user failed: %d", r);
        return -EFAULT;
    }

    dsm = find_dsm(svm_info.dsm_id);
    if (!dsm) {
        dsm_printk(KERN_ERR "can't find dsm %d", svm_info.dsm_id);
        return -EFAULT;
    }

    dsm_printk(KERN_ERR "connecting to dsm_id: %u [%p], svm_id: %u\n",
        svm_info.dsm_id, dsm, svm_info.svm_id);

    mutex_lock(&dsm->dsm_mutex);
    svm = find_svm(dsm, svm_info.svm_id);
    if (!svm) {
        dsm_printk(KERN_ERR "Can't find svm %d", svm_info.svm_id);
        goto no_svm;
    }

    ip_addr = inet_addr(svm_info.ip);
    cele = search_rb_conn(ip_addr);
    if (cele) {
        dsm_printk(KERN_ERR "has existing connection to %pI4", &ip_addr);
        /* BUG_ON(svm->ele != cele); */
        goto done;
    }

    r = create_connection(dsm_state->rcm, &svm_info);
    if (r) {
        dsm_printk(KERN_ERR "create_connection failed %d", r);
        goto failed;
    }

    might_sleep();
    cele = search_rb_conn(ip_addr);
    if (!cele) {
        dsm_printk(KERN_ERR "conneciton does not exist", r);
        r = -ENOLINK;
        goto failed;
    }

    wait_for_completion(&cele->completion);
    if (!atomic_read(&cele->alive)) {
        dsm_printk(KERN_ERR "conneciton is not alive ... aborting");
        r = -ENOLINK;
        goto failed;
    }

done:
    svm->ele = cele;

failed:
    release_svm(svm);
no_svm:
    mutex_unlock(&dsm->dsm_mutex);
    dsm_printk(KERN_INFO "dsm %d svm %d svm_connect ip %pI4: %d",
        svm_info.dsm_id, svm_info.svm_id, &ip_addr, r);
    return r;
}

static int do_unmap_range(struct dsm *dsm, int dsc, void *start, void *end)
{
    int r = 0;
    unsigned long it;

    for (it = (unsigned long)start; it < (unsigned long)end; it += PAGE_SIZE) {
        r = dsm_flag_page_remote(current->mm, dsm, dsc, it);
        if (r)
            break;
    }

    return r;
}

static int unmap_range(struct private_data *priv_data, void __user *argp)
{
    int r = -EFAULT;
    struct unmap_data udata;
    struct dsm *dsm;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    dsm = find_dsm(udata.dsm_id);
    if (!dsm)
        goto out;

    r = do_unmap_range(dsm, dsm_get_descriptor(dsm, udata.svm_ids), udata.addr,
            udata.addr + udata.sz - 1);

out:
    return r;
}

static int register_mr(struct private_data *priv_data, void __user *argp)
{
    int ret = 0, i;
    struct dsm *dsm;
    struct subvirtual_machine *svm = NULL;
    struct memory_region *mr;
    struct unmap_data udata;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    dsm = find_dsm(udata.dsm_id);
    if (!dsm) {
        dsm_printk(KERN_ERR "can't find dsm %d", udata.dsm_id);
        ret = -EFAULT;
        goto out;
    }

    svm = find_local_svm_in_dsm(dsm, current->mm);
    if (!svm) {
        dsm_printk(KERN_ERR "local svm not registered\n");
        ret = -EFAULT;
        goto out;
    }

    /* FIXME: Validate against every kind of overlap! */
    if (search_mr(svm, (unsigned long) udata.addr)) {
        dsm_printk(KERN_ERR "mr already exists at addr 0x%lx", udata.addr);
        ret = -EEXIST;
        goto out;
    }

    mr = kzalloc(sizeof(struct memory_region), GFP_KERNEL);
    if (!mr) {
        dsm_printk(KERN_ERR "can't allocate memory for MR");
        ret = -ENOMEM;
        goto out_free;
    }

    mr->mr_id = udata.id;
    mr->addr = (unsigned long) udata.addr;
    mr->sz = udata.sz;
    mr->local = DSM_REMOTE_MR;
    if (insert_mr(svm, mr))
        goto out_free;

    mr->descriptor = dsm_get_descriptor(dsm, udata.svm_ids);
    if (!mr->descriptor) {
        dsm_printk(KERN_ERR "can't find MR descriptor for svm_ids");
        ret = -EFAULT;
        goto out_free;
    }

    for (i = 0; udata.svm_ids[i]; i++) {
        struct subvirtual_machine *owner;
        u32 svm_id = udata.svm_ids[i];

        owner = find_svm(dsm, svm_id);
        if (!owner) {
            dsm_printk(KERN_ERR "[i=%d] can't find svm %d", i, svm_id);
            ret = -EFAULT;
            goto out_remove_tree;
        }

        if (is_svm_local(owner))
            mr->local = DSM_LOCAL_MR;

        release_svm(owner);
    }

    if (udata.unmap) {
        if (mr->local == DSM_LOCAL_MR) {
            dsm_printk(KERN_ERR "could not unmap local mr\n");
        } else {
            ret = do_unmap_range(dsm, mr->descriptor, udata.addr,
                    udata.addr + udata.sz - 1);
        }
    }

    release_svm(svm);

    dsm_printk(KERN_INFO "register_mr: id[%d] svm[%d] addr[%lu] sz [0x%lx]"
            " --> ret %d", mr->mr_id, svm->svm_id, mr->addr, mr->sz, ret);

    return ret;

out_remove_tree:
    rb_erase(&mr->rb_node, &svm->mr_tree_root);
out_free:
    kfree(mr);
out:
    if (svm)
        release_svm(svm);
    dsm_printk(KERN_INFO "register_mr failed : id [%d] addr [0x%lx] sz [0x%lx]"
            " svm[0] [0x%x] --> ret %d", udata.id, udata.addr, udata.sz,
            *udata.svm_ids, ret);
    return -1;
}

static int pushback_page(struct private_data *priv_data, void __user *argp)
{
    int r = -EFAULT;
    unsigned long addr;
    struct dsm *dsm;
    struct unmap_data udata;
    struct memory_region *mr;
    struct page *page;
    struct subvirtual_machine *local_svm = NULL;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    addr =((unsigned long) udata.addr) & PAGE_MASK;

    dsm = find_dsm(udata.dsm_id);
    if (!dsm)
        goto out;

    local_svm = find_local_svm_in_dsm(dsm, current->mm);
    if (!local_svm)
        goto out;

    mr = search_mr(local_svm, addr);
    if (!mr)
        goto out;

    page = dsm_find_normal_page(current->mm, addr);
    if (!page)
        goto out;

    r = dsm_request_page_pull(dsm, local_svm, page, addr, current->mm, mr);

out:
    if (local_svm)
        release_svm(local_svm);
    return r;
}

static int open(struct inode *inode, struct file *f)
{
    struct private_data *data;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    data = kmalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -EFAULT;

    mutex_lock(&dsm_state->dsm_state_mutex);
    f->private_data = (void *) data;
    mutex_unlock(&dsm_state->dsm_state_mutex);

    return 0;
}

static int release(struct inode *inode, struct file *f)
{
    struct private_data *data = (struct private_data *) f->private_data;
    struct dsm *dsm = data->dsm;
    struct list_head *pos = NULL;
    u32 remove, svm_id;

    if (!dsm)
        return 1;

    rcu_read_lock();
    remove = 0;
    list_for_each (pos, &dsm->svm_list) {
        struct subvirtual_machine *svm = list_entry(pos,
                struct subvirtual_machine, svm_ptr);
        if (svm->mm == current->mm) {
            svm_id = svm->svm_id;
            remove = 1;
            break;
        }
    }
    rcu_read_unlock();

    if (remove)
        remove_svm(dsm->dsm_id, svm_id);

    if (data->dsm->nb_local_svm == 0) {
        remove_dsm(data->dsm);
        printk("[Release ] last local svm , freeing the dsm\n");
    }
    kfree(data);

    return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
    struct private_data *priv_data = (struct private_data *) f->private_data;
    void __user *argp = (void __user *) arg;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    int r = -1;

    if (!dsm_state->rcm)
        goto out;

    switch (ioctl) {
        case DSM_DSM:
            r = register_dsm(priv_data, argp);
            break;
        case DSM_SVM:
            if (priv_data->dsm)
                r = register_svm(priv_data, argp);
            break;
        case DSM_CONNECT:
            if (priv_data->dsm)
                r = connect_svm(priv_data, argp);
            break;
        case DSM_MR:
            if (priv_data->dsm)
                r = register_mr(priv_data, argp);
            break;
        case DSM_UNMAP_RANGE:
            if (priv_data->dsm)
                r = unmap_range(priv_data, argp);
            break;
        /*
         * devel/debug
         */
        case DSM_TRY_PUSH_BACK_PAGE: {
            r = pushback_page(priv_data, argp);
            break;
        }
        default: {
            r = -EFAULT;
            break;
        }
    }

out: 
    return r;
}

static struct file_operations rdma_fops = { .owner = THIS_MODULE,
    .release = release, .unlocked_ioctl = ioctl, .open = open,
    .llseek = noop_llseek, };
static struct miscdevice rdma_misc = { MISC_DYNAMIC_MINOR, "rdma",
    &rdma_fops, };

const struct dsm_hook_struct my_dsm_hook = {
    .name = "DSM",
    .fetch_page = dsm_swap_wrapper,
    .pushback_page = push_back_if_remote_dsm_page,
    .is_congested = dsm_is_congested,
};

static int dsm_init(void)
{
    struct dsm_module_state *dsm_state = create_dsm_module_state();

    dsm_zero_pfn_init();

    printk("[dsm_init] ip : %s\n", ip);
    printk("[dsm_init] port : %d\n", port);

    if (create_rcm(dsm_state, ip, port))
        goto err;

    if (dsm_sysfs_setup(dsm_state)) {
        destroy_rcm(dsm_state);
    }

    rdma_listen(dsm_state->rcm->cm_id, 2);
    dsm_hook_write(&my_dsm_hook);
err: 
    return misc_register(&rdma_misc);
}
module_init(dsm_init);

static void dsm_exit(void)
{
    struct dsm *dsm = NULL;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    dsm_hook_write(NULL);

    dsm_zero_pfn_exit();

    while (!list_empty(&dsm_state->dsm_list)) {
        dsm = list_first_entry(&dsm_state->dsm_list, struct dsm, dsm_ptr);
        remove_dsm(dsm);
    }

    dsm_sysfs_cleanup(dsm_state);
    destroy_rcm(dsm_state);

    misc_deregister(&rdma_misc);
    destroy_dsm_module_state();
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("Benoit Hudzia");
MODULE_DESCRIPTION("Distributed Shared memory Module");
MODULE_LICENSE("GPL");

