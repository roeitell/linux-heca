/*
 1 * rdma.c
 *
 *  Created on: 22 Jun 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

static char *ip = 0;
static int port = 0;

static void reset_dsm_page_stats(struct dsm_page_stats * stats) {
    atomic64_set(&stats->nb_page_pull, 0);
    atomic64_set(&stats->nb_page_pull_fail, 0);
    atomic64_set(&stats->nb_page_push_request, 0);
    atomic64_set(&stats->nb_page_requested, 0);
    atomic64_set(&stats->nb_page_sent, 0);
    atomic64_set(&stats->nb_page_redirect, 0);
    atomic64_set(&stats->nb_err, 0);
    atomic64_set(&stats->nb_page_request_success, 0);
    atomic64_set(&stats->nb_page_requested_prefetch, 0);

}
static void reset_svm_stats(struct svm_sysfs *sysfs) {
    reset_dsm_page_stats(&sysfs->stats);    
}

static void reset_msg_stats(struct msg_stats *stats) {
    atomic64_set(&stats->err, 0);
    atomic64_set(&stats->page_info_update, 0);
    atomic64_set(&stats->page_request_reply, 0);
    atomic64_set(&stats->request_page, 0);
    atomic64_set(&stats->request_page_pull, 0);
    atomic64_set(&stats->try_request_page, 0);
    atomic64_set(&stats->try_request_page_fail, 0);
    atomic64_set(&stats->page_request_redirect, 0);

}

void reset_dsm_connection_stats(struct con_element_sysfs *sysfs) {
    reset_msg_stats(&sysfs->rx_stats);
    reset_msg_stats(&sysfs->tx_stats);
}

void remove_svm(struct dsm *dsm, u32 svm_id) {
    struct subvirtual_machine *svm;
    struct tx_buf_ele *tx_buf;
    int i;

    mutex_lock(&dsm->dsm_mutex);
    svm = find_svm(dsm, svm_id);
    if (!svm)   // protect against concurrent calls to remove_svm
        goto out;

    radix_tree_delete(&dsm->svm_tree_root, (unsigned long) svm->svm_id);
    if (svm->priv) {
        dsm->nb_local_svm--;
        radix_tree_delete(&dsm->svm_mm_tree_root, (unsigned long) svm->svm_id);
    }

    if (svm->ele) {
        tx_buf = svm->ele->tx_buffer.tx_buf;
        for (i = 0; i < TX_BUF_ELEMENTS_NUM; i++) {
            if (tx_buf[i].used && tx_buf[i].dsm_msg->dsm_id == dsm->dsm_id &&
                    (tx_buf[i].dsm_msg->src_id == svm->svm_id ||
                     tx_buf[i].dsm_msg->dest_id == svm->svm_id)) {
                release_tx_element(svm->ele, &tx_buf[i]);
            }
        }
    }

    synchronize_rcu();
    delete_svm_sysfs_entry(&svm->svm_sysfs.svm_kobject);

    INIT_WORK(&svm->dtor, clean_svm_data);
    queue_work(get_dsm_module_state()->dsm_wq, &svm->dtor);

    out: mutex_unlock(&dsm->dsm_mutex);
}

void remove_dsm(struct dsm *dsm) {
    struct subvirtual_machine *svm;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    struct list_head *pos, *n;

    printk("[remove_dsm] removing dsm %d  \n", dsm->dsm_id);

    if (!atomic_cmpxchg(&dsm->dtor, 0, 1)) {
        mutex_lock(&dsm_state->dsm_state_mutex);
        list_del(&dsm->dsm_ptr);
        radix_tree_delete(&dsm_state->dsm_tree_root,
                (unsigned long) dsm->dsm_id);
        mutex_unlock(&dsm_state->dsm_state_mutex);
        synchronize_rcu();
    }

    if (!list_empty(&dsm->svm_list)) {
        list_for_each_safe (pos, n, &dsm->svm_list) {
            svm = list_entry(pos, struct subvirtual_machine, svm_ptr);
            remove_svm(dsm, svm->svm_id);
        }
    } else {
        destroy_mrs(dsm, 1);

        delete_dsm_sysfs_entry(&dsm->dsm_kobject);
        kfree(dsm);
    }
}

static int register_dsm(struct private_data *priv_data, void __user *argp) {
    int r = -EFAULT;
    char id[11];
    struct svm_data svm_info;
    struct dsm * found_dsm, *new_dsm = NULL;

    struct dsm_module_state *dsm_state = get_dsm_module_state();

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        printk("[register_dsm] reading data from userspace failed \n");
        return r;
    }

    mutex_lock(&dsm_state->dsm_state_mutex);

    do {
        found_dsm = find_dsm(svm_info.dsm_id);
        if (found_dsm) {
            printk("[register_dsm] we already have the dsm in place \n");
            break;
        }

        new_dsm = kzalloc(sizeof(*new_dsm), GFP_KERNEL);
        if (!new_dsm)
            break;

        new_dsm->dsm_id = svm_info.dsm_id;
        mutex_init(&new_dsm->dsm_mutex);
        seqlock_init(&new_dsm->mr_seq_lock);
        INIT_RADIX_TREE(&new_dsm->svm_tree_root, GFP_KERNEL);
        INIT_RADIX_TREE(&new_dsm->svm_mm_tree_root, GFP_KERNEL);
        INIT_LIST_HEAD(&new_dsm->svm_list);
        new_dsm->mr_tree_root = RB_ROOT;
        new_dsm->nb_local_svm = 0;
        atomic_set(&new_dsm->dtor, 0);

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
            break;
        r = radix_tree_insert(&dsm_state->dsm_tree_root,
                (unsigned long) svm_info.dsm_id, new_dsm);
        if (likely(!r)) {
            radix_tree_preload_end();
            scnprintf(id, 11, "%x", new_dsm->dsm_id);
            priv_data->dsm = new_dsm;
            //TODO catch error
            create_dsm_sysfs_entry(&new_dsm->dsm_kobject,
                dsm_state->dsm_kobjects.domains_kobject, id);
            list_add(&new_dsm->dsm_ptr, &dsm_state->dsm_list);
            printk("[DSM_DSM]\n registered dsm %p,  dsm_id : %u, res: %d \n",
                    new_dsm, svm_info.dsm_id, r);
            goto exit;
        }
        radix_tree_preload_end();

    } while (r != -ENOMEM);
    if (new_dsm) {
        kfree(new_dsm);
    }

    exit:

    mutex_unlock(&dsm_state->dsm_state_mutex);
    return r;

}

static int register_svm(struct private_data *priv_data, void __user *argp) {
    int r = -EFAULT;
    struct dsm *dsm;
    char charid[11];
    struct subvirtual_machine *found_svm, *new_svm = NULL;
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
        return r;

    dsm = find_dsm(svm_info.dsm_id);
    BUG_ON(!dsm);

    mutex_lock(&priv_data->dsm->dsm_mutex);
    do {
        found_svm = find_svm(dsm, svm_info.svm_id);
        if (found_svm)
            break;

        new_svm = kzalloc(sizeof(*new_svm), GFP_KERNEL);
        if (!new_svm)
            break;

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
            break;

        r = radix_tree_insert(&priv_data->dsm->svm_tree_root,
                (unsigned long) svm_info.svm_id, new_svm);
        if (likely(!r)) {
            //the following should never fail as we locked the dsm and we made sure that we add the ID first
            r = radix_tree_insert(&priv_data->dsm->svm_mm_tree_root,
                    (unsigned long) priv_data->mm, new_svm);

            radix_tree_preload_end();

            new_svm->priv = priv_data;
            priv_data->svm = new_svm;
            priv_data->offset = svm_info.offset;
            new_svm->svm_id = svm_info.svm_id;
            new_svm->ele = NULL;
            new_svm->dsm = priv_data->dsm;
            new_svm->dsm->nb_local_svm++;
            new_svm->status = 0;
            reset_svm_stats(&new_svm->svm_sysfs);
            scnprintf(charid, 11, "%x", new_svm->svm_id);
            //TODO catch error
            create_svm_sysfs_entry(&new_svm->svm_sysfs,
                &new_svm->dsm->dsm_kobject, charid, "local");

            spin_lock_init(&new_svm->page_cache_spinlock);
            INIT_RADIX_TREE(&new_svm->page_cache, GFP_ATOMIC);
            INIT_LIST_HEAD(&new_svm->mr_list);
            list_add(&new_svm->svm_ptr, &priv_data->dsm->svm_list);
            printk(
                    "[DSM_SVM]\n\t registered svm %p , res : %d\n\tdsm_id : %u\n\tsvm_id : %u\n",
                    new_svm, r, svm_info.dsm_id, svm_info.svm_id);
            goto exit;

        }
        radix_tree_preload_end();

    } while (r != -ENOMEM);
    if (new_svm) {
        kfree(new_svm);
    }
    exit:

    mutex_unlock(&priv_data->dsm->dsm_mutex);
    return r;

}

static int connect_svm(struct private_data *priv_data, void __user *argp)
{
    char charid[11];
    int r = -EFAULT;
    struct dsm *dsm;
    struct subvirtual_machine *found_svm, *new_svm = NULL;
    struct svm_data svm_info;
    struct conn_element *cele;
    int ip_addr;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
        return r;

    dsm = find_dsm(svm_info.dsm_id);
    BUG_ON(!dsm);

    mutex_lock(&priv_data->dsm->dsm_mutex);
    do {
        found_svm = find_svm(dsm, svm_info.svm_id);
        if (found_svm)
            break;

        new_svm = kzalloc(sizeof(*new_svm), GFP_KERNEL);
        if (!new_svm)
            break;

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
            break;
        r = radix_tree_insert(&priv_data->dsm->svm_tree_root,
                (unsigned long) svm_info.svm_id, new_svm);
        radix_tree_preload_end();

        if (likely(!r)) {
            u32 svm_id[2] = {svm_info.svm_id, 0};

            new_svm->svm_id = svm_info.svm_id;
            new_svm->priv = NULL;
            new_svm->dsm = priv_data->dsm;
            new_svm->descriptor = dsm_get_descriptor(dsm, svm_id);

            reset_svm_stats(&new_svm->svm_sysfs);
            spin_lock_init(&new_svm->page_cache_spinlock);
            scnprintf(charid, 11, "%x", new_svm->svm_id);
            //TODO catch error
            create_svm_sysfs_entry(&new_svm->svm_sysfs,
                &new_svm->dsm->dsm_kobject, charid, svm_info.ip);
            INIT_LIST_HEAD(&new_svm->mr_list);
            list_add(&new_svm->svm_ptr, &priv_data->dsm->svm_list);
            ip_addr = inet_addr(svm_info.ip);

            // Check for connection
            cele = search_rb_conn(ip_addr);
            if (!cele) {
                r = create_connection(dsm_state->rcm, &svm_info);
                if (r)
                    goto connect_fail;

                might_sleep();
                cele = search_rb_conn(ip_addr);
                if (!cele) {
                    r = -ENOLINK;
                    goto connect_fail;
                }
                wait_for_completion(&cele->completion);
            } 
            new_svm->ele = cele;

            printk(
                    "[DSM_CONNECT] connecting svm \n\tdsm_id : %u\n\tsvm_id : %u\n\tres : %d\n",
                    svm_info.dsm_id, svm_info.svm_id, r);
            goto exit;
        }

    } while (r != -ENOMEM);
    if (new_svm) {
        kfree(new_svm);
    }
    exit:

    mutex_unlock(&priv_data->dsm->dsm_mutex);
    return r;
    connect_fail:
    //TODO  we need to remove here
    mutex_unlock(&priv_data->dsm->dsm_mutex);
    return r;
}

static int register_mr(struct private_data *priv_data, void __user *argp) {
    int r = -EFAULT, j;
    struct dsm *dsm;
    struct memory_region *mr;
    struct unmap_data udata;
    unsigned long i, end;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    printk("[DSM_MR] addr [%lu] sz [%zu]\n", udata.addr, udata.sz);

    dsm = find_dsm(udata.dsm_id);
    BUG_ON(!dsm);

//     Make sure specific MR not already created.
    if (search_mr(dsm, udata.addr))
        goto out;

    mr = kzalloc(sizeof(struct memory_region), GFP_KERNEL);
    if (!mr)
        goto out;
 
    mr->addr = udata.addr;
    mr->sz = udata.sz;
    mr->descriptor = dsm_get_descriptor(dsm, udata.svm_ids);

    insert_mr(dsm, mr);
    for (j = 0; udata.svm_ids[j]; j++) {
        struct subvirtual_machine *svm = find_svm(dsm, udata.svm_ids[j]);
        if (!svm)
            goto out;

        if (svm->priv && svm->priv->mm == current->mm) {
            if (j == 0)
                r = 0;
            goto out;
        }
    }

    r = 0;
    i = udata.addr;
    for (end = i + udata.sz - 1; i < end; i += PAGE_SIZE) {
        r = dsm_flag_page_remote(current->mm, dsm, mr->descriptor, i);
        if (r)
            break;
    }

    out: return r;
}

static int unmap_range(struct private_data *priv_data, void __user *argp) {

    int r = -EFAULT, j;

    struct dsm *dsm;
    struct subvirtual_machine *svm = NULL;
    struct unmap_data udata;
    unsigned long i = 0, end = 0;
    u32 descriptor;

    printk("[DSM_UNMAP_RANGE]\n");

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    dsm = find_dsm(udata.dsm_id);
    BUG_ON(!dsm);
    
    for (j = 0; udata.svm_ids[j]; j++) {
        svm = find_svm(dsm, udata.svm_ids[j]);
        if (!svm) {
            printk("[UNMAP_RANGE] could not find the route element \n");
            r = -1;
            printk("[UNMAP_RANGE] dsm_id : %d - vm_id : %d\n", udata.dsm_id,
                udata.svm_ids[j]);
            goto out;
        }

        if (priv_data->svm->dsm->dsm_id != svm->dsm->dsm_id) {
            printk("[UNMAP_RANGE] DSM id not same, bad id  \n");
            r = -1;
            goto out;
        }
    }

    descriptor = dsm_get_descriptor(dsm, udata.svm_ids);

    i = udata.addr;
    end = i + udata.sz;
    while (i < end) {
        r = dsm_flag_page_remote(current->mm, dsm, descriptor, i);
        if (r)
            break;

        i += PAGE_SIZE;
    }
    printk("[?] unmapped #pages : %lu\n", (i-udata.addr)/PAGE_SIZE);
    r = 0;

    out: return r;
}

static int unmap_page(struct private_data *priv_data, void __user *argp) {

    int r = -EFAULT, i;
    u32 descriptor;

    struct dsm *dsm;
    struct subvirtual_machine *svm = NULL;
    struct unmap_data udata;

    printk("[DSM_UNMAP_PAGE]\n");

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        goto out;
    }

    dsm = find_dsm(udata.dsm_id);
    BUG_ON(!dsm);

    for (i = 0; udata.svm_ids[i]; i++) {
        svm = find_svm(dsm, udata.svm_ids[i]);
        if (!svm) {
            printk("[UNMAP_PAGE] could not find the route element \n");
            r = -1;
            printk("[unmap page 1] dsm_id : %d - vm_id : %d\n", udata.dsm_id,
                    udata.svm_ids[i]);
            goto out;
        }
    }

    if (priv_data->svm->dsm->dsm_id != svm->dsm->dsm_id) {
        printk("[UNMAP_PAGE] DSM id not same, bad id  \n");
        r = -1;
        goto out;
    }

    descriptor = dsm_get_descriptor(dsm, udata.svm_ids);

    r = dsm_flag_page_remote(current->mm, dsm, descriptor, udata.addr);

    out: return r;
}

static int pushback_page(struct private_data *priv_data, void __user *argp)
{
    int r = -EFAULT;
    unsigned long addr;
    struct dsm *dsm;
    struct unmap_data udata;

    printk("[DSM_TRY_PUSH_BACK_PAGE]\n");
    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    dsm = find_dsm(udata.dsm_id);
    BUG_ON(!dsm);

    addr = udata.addr & PAGE_MASK;
    if (!dsm_cache_get(priv_data->svm, addr)) {
        r = dsm_request_page_pull(dsm, current->mm, priv_data->svm, udata.addr);
    }
    else {
        r = 0;
    }

    out: return r;
}

static int open(struct inode *inode, struct file *f) {
    struct private_data *data;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    data = kmalloc(sizeof(*data), GFP_KERNEL);
    data->svm = NULL;
    data->offset = 0;

    if (!data)
        return -EFAULT;

    mutex_lock(&dsm_state->dsm_state_mutex);
    data->mm = current->mm;
    f->private_data = (void *) data;
    mutex_unlock(&dsm_state->dsm_state_mutex);

    return 0;
}

static int release(struct inode *inode, struct file *f) {
    struct private_data *data = (struct private_data *) f->private_data;

    if (!data->svm)
        return 1;
    remove_svm(data->dsm, data->svm->svm_id);
    if (data->dsm->nb_local_svm == 0) {
        remove_dsm(data->dsm);
        printk("[Release ] last local svm , freeing the dsm\n");
    }
    kfree(data);

    return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg) {

    struct private_data *priv_data = (struct private_data *) f->private_data;
    void __user *argp = (void __user *) arg;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    int r = -1;
    struct conn_element *cele;
    int ip_addr;
    struct svm_data svm_info;
 
    if (!dsm_state->rcm)
        goto out;

    switch (ioctl) {
        case DSM_DSM: {
            r = register_dsm(priv_data, argp);
            break;
        }
        case DSM_SVM: {
            if (priv_data->dsm)
                r = register_svm(priv_data, argp);
            break;
        }
        case DSM_MR: {
            if (priv_data->dsm)
                r = register_mr(priv_data, argp);
            break;
        }
        case DSM_CONNECT: {
            if (priv_data->dsm)
                r = connect_svm(priv_data, argp);
            break;
        }
        case DSM_UNMAP_RANGE: {
            r = unmap_range(priv_data, argp);
            break;
        }
        case UNMAP_PAGE: {
            r = unmap_page(priv_data, argp);
            break;
        }
        case DSM_TRY_PUSH_BACK_PAGE: {
            r = pushback_page(priv_data, argp);
            break;
        }
        case DSM_GEN_STAT: {
            if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
                goto out;

            ip_addr = inet_addr(svm_info.ip);
            cele = search_rb_conn(ip_addr);

            if (likely(cele)) {
                reset_dsm_connection_stats(&cele->sysfs);
            }
            break;
        }
        case DSM_GET_STAT: {
            if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
                goto out;

            ip_addr = inet_addr(svm_info.ip);
            cele = search_rb_conn(ip_addr);
            break;
        }
         default: {
            r = -EFAULT;
            break;
        }
    }

    out: return r;
}

static struct file_operations rdma_fops = { .owner = THIS_MODULE, .release =
        release, .unlocked_ioctl = ioctl, .open = open, .llseek = noop_llseek,
};

static struct miscdevice rdma_misc = { MISC_DYNAMIC_MINOR, "rdma", &rdma_fops,

};

module_param(ip, charp, S_IRUGO|S_IWUSR);
module_param(port, int, S_IRUGO|S_IWUSR);

MODULE_PARM_DESC( ip,
        "The ip of the machine running this module - will be used as node_id.");
MODULE_PARM_DESC(
        port,
        "The port on the machine running this module - used for DSM_RDMA communication.");

static int dsm_init(void) {
    struct dsm_module_state *dsm_state = create_dsm_module_state();

    reg_dsm_functions(&find_dsm, &find_svm, &find_local_svm, &request_dsm_page);

    printk("[dsm_init] ip : %s\n", ip);
    printk("[dsm_init] port : %d\n", port);

    if (create_rcm(dsm_state, ip, port))
        goto err;

    if (dsm_sysf_setup(dsm_state)) {
        dereg_dsm_functions();
        destroy_rcm(dsm_state);
    }

    rdma_listen(dsm_state->rcm->cm_id, 2);
    err: return misc_register(&rdma_misc);
}
module_init(dsm_init);

static void dsm_exit(void) {
    struct dsm * dsm = NULL;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    while (!list_empty(&dsm_state->dsm_list)) {
        dsm = list_first_entry(&dsm_state->dsm_list, struct dsm, dsm_ptr );
        remove_dsm(dsm);
    }

    dereg_dsm_functions();
    dsm_sysf_cleanup(dsm_state);
    destroy_rcm(dsm_state);

    misc_deregister(&rdma_misc);
    destroy_dsm_module_state();
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
MODULE_LICENSE("GPL");
