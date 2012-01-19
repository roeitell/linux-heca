/*
 1 * rdma.c
 *
 *  Created on: 22 Jun 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

static char *ip = 0;
static int port = 0;

static int register_dsm(struct private_data *priv_data, void __user *argp) {
    int r = -EFAULT;
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
        new_dsm = kmalloc(sizeof(*new_dsm), GFP_KERNEL);
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
        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
            break;

        r = radix_tree_insert(&dsm_state->dsm_tree_root,
                (unsigned long) svm_info.dsm_id, new_dsm);
        if (likely(!r)) {
            radix_tree_preload_end();
            priv_data->dsm = new_dsm;
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
    struct dsm_vm_id id;
    struct subvirtual_machine *found_svm, *new_svm = NULL;
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
        return r;

    id.dsm_id = svm_info.dsm_id;
    id.svm_id = svm_info.svm_id;

    mutex_lock(&priv_data->dsm->dsm_mutex);
    do {
        found_svm = find_svm(&id);
        if (found_svm)
            break;

        new_svm = kmalloc(sizeof(*new_svm), GFP_KERNEL);
        if (!new_svm)
            break;

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
            break;

        r = radix_tree_insert(&priv_data->dsm->svm_tree_root,
                (unsigned long) id.svm_id, new_svm);
        if (likely(!r)) {
            //the following should never fail as we locked the dsm and we made sure that we add the ID first
            r = radix_tree_insert(&priv_data->dsm->svm_mm_tree_root,
                    (unsigned long) priv_data->mm, new_svm);

            radix_tree_preload_end();

            new_svm->priv = priv_data;
            priv_data->svm = new_svm;
            priv_data->offset = svm_info.offset;
            new_svm->id.dsm_id = svm_info.dsm_id;
            new_svm->id.svm_id = svm_info.svm_id;
            new_svm->ele = NULL;
            new_svm->dsm = priv_data->dsm;
            new_svm->dsm->nb_local_svm++;
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
    int r = -EFAULT;
    struct dsm_vm_id id;
    struct subvirtual_machine *found_svm, *new_svm = NULL;
    struct svm_data svm_info;
    struct conn_element *cele;
    int ip_addr;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
        return r;

    id.dsm_id = svm_info.dsm_id;
    id.svm_id = svm_info.svm_id;

    mutex_lock(&priv_data->dsm->dsm_mutex);
    do {
        found_svm = find_svm(&id);
        if (found_svm)
            break;

        new_svm = kmalloc(sizeof(*new_svm), GFP_KERNEL);
        if (!new_svm)
            break;

        r = radix_tree_preload(GFP_HIGHUSER_MOVABLE & GFP_KERNEL);
        if (r)
            break;

        r = radix_tree_insert(&priv_data->dsm->svm_tree_root,
                (unsigned long) id.svm_id, new_svm);
        if (likely(!r)) {
            radix_tree_preload_end();

            new_svm->id.dsm_id = svm_info.dsm_id;
            new_svm->id.svm_id = svm_info.svm_id;
            new_svm->priv = NULL;
            new_svm->dsm = priv_data->dsm;
            INIT_LIST_HEAD(&new_svm->mr_list);
            list_add(&new_svm->svm_ptr, &priv_data->dsm->svm_list);
            ip_addr = inet_addr(svm_info.ip);

            // Check for connection

            cele = search_rb_conn(ip_addr);

            if (!cele) {
                r = create_connection(dsm_state->rcm, &svm_info);
                if (r)
                    goto connect_fail;

            }

            might_sleep();
            cele = search_rb_conn(ip_addr);
            if (!cele) {
                r = -ENOLINK;
                goto connect_fail;
            }
            wait_for_completion(&cele->completion);
            new_svm->ele = cele;
            printk(
                    "[DSM_SVM]\n\t connecting svm \n\tdsm_id : %u\n\tsvm_id : %u\n\tres : %d\n",
                    svm_info.dsm_id, svm_info.svm_id, r);
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
    connect_fail:
    //TODO  we need to remove here
    mutex_unlock(&priv_data->dsm->dsm_mutex);
    return r;

}

static int register_mr(struct private_data *priv_data, void __user *argp) {
    int r = -EFAULT;
    struct dsm_vm_id id;
    struct memory_region *mr;
    struct subvirtual_machine *svm;
    struct mr_data mr_info;
    unsigned long i, end;

    printk("[DSM_MR]\n");

    if (copy_from_user((void *) &mr_info, argp, sizeof mr_info))
        goto out;

    id.dsm_id = mr_info.dsm_id;
    id.svm_id = mr_info.svm_id;

    svm = find_svm(&id);
    if (!svm)
        goto out;

//     Make sure specific MR not already created.
    mr = search_mr(svm->dsm, mr_info.start_addr);
    if (mr)
        goto out;

    mr = kmalloc(sizeof(*mr), GFP_KERNEL);
    if (!mr)
        goto out;

    mr->addr = mr_info.start_addr;
    mr->sz = mr_info.size;
    mr->svm = svm;

    insert_mr(svm->dsm, mr);
    list_add(&mr->ls, &svm->mr_list);
    r = 0;
    if (!svm->priv || (svm->priv->mm != current->mm)) {
        i = mr->addr;
        end = i + mr->sz - 1;
        while (i < end) {
            r = dsm_flag_page_remote(current->mm, mr->svm->id, i);
            if (r)
                break;
            i += PAGE_SIZE;

        }
    }
    out: return r;
}

static int unmap_range(struct private_data *priv_data, void __user *argp) {

    int r = -EFAULT;

    struct subvirtual_machine *svm = NULL;
    struct unmap_data udata;
    unsigned long i = 0;
    unsigned long end = 0;
    int counter = 0;

    printk("[DSM_UNMAP_RANGE]\n");

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    svm = find_svm(&udata.id);

    if (!svm) {
        printk("[UNMAP_RANGE] could not find the route element \n");
        r = -1;
        printk("[unmap range ] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
                udata.id.svm_id);
        goto out;

    }

    if (priv_data->svm->id.dsm_id != svm->id.dsm_id) {
        printk("[UNMAP_PAGE] DSM id not same, bad id  \n");
        r = -1;
        goto out;
    }

    i = udata.addr;
    end = i + udata.sz;
    counter = 0;
    while (i < end) {
        r = dsm_flag_page_remote(current->mm, udata.id, i);
        if (r)
            break;

        i += PAGE_SIZE;
        counter++;

    }
    printk("[?] unmapped #pages : %d\n", counter);
    r = 0;

    out:

    return r;
}

static int unmap_page(struct private_data *priv_data, void __user *argp) {

    int r = -EFAULT;

    struct subvirtual_machine *svm = NULL;
    struct unmap_data udata;

    printk("[DSM_UNMAP_RANGE]\n");

    r = -EFAULT;

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        goto out;
    }

    svm = find_svm(&udata.id);

    if (!svm) {
        printk("[UNMAP_PAGE] could not find the route element \n");
        r = -1;
        printk("[unmap page 1] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
                udata.id.svm_id);
        goto out;

    }

    printk("[unmap page 2] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
            udata.id.svm_id);

    if (priv_data->svm->id.dsm_id != svm->id.dsm_id) {
        printk("[UNMAP_PAGE] DSM id not same, bad id  \n");
        r = -1;
        goto out;
    }

    r = dsm_flag_page_remote(current->mm, udata.id, udata.addr);

    out:

    return r;
}

static int pushback_page(struct private_data *priv_data, void __user *argp)

{

    int r = -EFAULT;
    unsigned long addr;

    struct subvirtual_machine *svm = NULL;
    struct unmap_data udata;
    printk("[DSM_TRY_PUSH_BACK_PAGE]\n");

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    svm = find_svm(&udata.id);

    if (!svm)
        goto out;
    if (svm == priv_data->svm)
        goto out;
    addr = udata.addr & PAGE_MASK;
    if (!page_is_in_dsm_cache(addr))
        r = dsm_request_page_pull(current->mm, svm, priv_data->svm, udata.addr);
    else
        r = 0;

    out:

    return r;
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
    remove_svm(data->svm);
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

    int r = -1;
    struct conn_element *cele;
    int ip_addr;
    struct dsm_message msg;
    struct page *page;
    struct svm_data svm_info;

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
            //printk("[DSM_CONNECT]\n");
            if (priv_data->dsm)
                r = connect_svm(priv_data, argp);
            break;

        }
        case DSM_UNMAP_RANGE: {
            r = unmap_range(priv_data, argp);
            break;

        }
        case PAGE_SWAP: {
            r = -EFAULT;

            printk("[PAGE_SWAP] swapping of one page \n");
            if (copy_from_user((void *) &msg, argp, sizeof msg))
                goto out;

            page = dsm_extract_page_from_remote(&msg);

            if (page == (void *) -EFAULT
            )
                r = -EFAULT;
            else
                r = !!page;

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

                reset_dsm_connection_stats(&cele->stats);

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

    reg_dsm_functions(&find_svm, &find_local_svm, &request_dsm_page);

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
