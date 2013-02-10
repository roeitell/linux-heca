/*
 * drivers/dsm/dsm.c
 *
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/dsm_hook.h>
#include <dsm/dsm_core.h>

#ifdef CONFIG_DSM_DEBUG
static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug level (0 = disable)");
#endif

#ifdef CONFIG_DSM_VERBOSE_PRINTK
/* strip the leading path if the given path is absolute */
static const char *sanity_file_name(const char *path)
{
    if (*path == '/')
    return strrchr(path, '/') + 1;
    else
    return path;
}
#endif

void __dsm_printk(unsigned int level, const char *path, int line, const char *format,
        ...)
{
#if defined(CONFIG_DSM_DEBUG) || defined(CONFIG_DSM_VERBOSE_PRINTK)
    va_list args;
#ifdef CONFIG_DSM_VERBOSE_PRINTK
    struct va_format vaf;
    char verbose_fmt[] = KERN_DEFAULT "DSM %s:%d %pV";
#endif

#ifdef CONFIG_DSM_DEBUG
    if (debug < level)
        return;
#endif

    va_start(args, format);

#ifdef CONFIG_DSM_VERBOSE_PRINTK
    vaf.fmt = format;
    vaf.va = &args;
    if (format[0] == '<' && format[2] == '>') {
        memcpy(verbose_fmt, format, 3);
        vaf.fmt = format + 3;
    } else if (level)
        memcpy(verbose_fmt, KERN_DEBUG, 3);
    printk(verbose_fmt, sanity_file_name(path), line, &vaf);
#else
    vprintk(format, args);
#endif
    printk("\n");

    va_end(args);
#endif
}
EXPORT_SYMBOL(__dsm_printk);

static int register_dsm(struct private_data *priv_data, void __user *argp)
{
    struct svm_data svm_info;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int rc;

    dsm_printk(KERN_DEBUG "entered function");

    BUG_ON(!dsm_state);

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk(KERN_ERR "copy_from_user failed");
        rc = -EFAULT;
        goto done;
    }

    if ((rc = create_rcm(dsm_state, svm_info.server.sin_addr.s_addr,
            svm_info.server.sin_port))) {
        dsm_printk(KERN_ERR "create_rcm failed");
        goto done;
    }
    rdma_listen(dsm_state->rcm->cm_id, 2);

    if ((rc = create_dsm(priv_data, svm_info.dsm_id))) {
        dsm_printk(KERN_ERR "create_dsm failed");
        goto done;
    }

done:
    dsm_printk(KERN_DEBUG "exit function: %d", rc);
    return rc;
}

static int register_svm(void __user *argp)
{
    struct svm_data svm_info;
    int rc;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    rc = create_svm(svm_info.dsm_id, svm_info.svm_id, svm_info.is_local);
    if (rc) {
        dsm_printk(KERN_ERR "create_svm failed");
        goto done;
    }

    if (!svm_info.is_local) {
        rc = connect_svm(svm_info.dsm_id, svm_info.svm_id, 
            svm_info.server.sin_addr.s_addr, svm_info.server.sin_port);

        if (rc) {
            dsm_printk(KERN_ERR "connect_svm failed");
            goto done;
        }
    }

done:
    return rc;
}

static int register_mr(void __user *argp)
{
    struct unmap_data udata;

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        dsm_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    return create_mr(udata.dsm_id, udata.mr_id, udata.addr, udata.sz,
            udata.svm_ids);
}

static int pushback_page(void __user *argp)
{
    int r = -EFAULT;
    unsigned long addr, start_addr;
    struct dsm *dsm;
    struct unmap_data udata;
    struct memory_region *mr;
    struct page *page;
    struct subvirtual_machine *local_svm = NULL;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    dsm = find_dsm(udata.dsm_id);
    if (!dsm)
        goto out;

    local_svm = find_local_svm_in_dsm(dsm, current->mm);
    if (!local_svm)
        goto out;

    addr = start_addr =((unsigned long) udata.addr) & PAGE_MASK;
    while (addr < start_addr + udata.sz) {

        mr = search_mr(local_svm, addr);
        if (!mr)
            goto out;

        page = dsm_find_normal_page(current->mm, addr);
        if (!page)
            goto out;

        r = dsm_request_page_pull(dsm, local_svm, page, addr, current->mm, mr);
        if (r)
            goto out;

        addr += PAGE_SIZE;
    }
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
    struct subvirtual_machine *svm = NULL;

    if (!dsm)
        return 1;

    while ( !list_empty(&dsm->svm_list) ) {
        svm = list_first_entry(&dsm->svm_list, struct subvirtual_machine,
            svm_ptr);
        dsm_printk(KERN_ERR "removing svm_id: %d from list of svms",
            svm->svm_id);
        remove_svm(dsm->dsm_id, svm->svm_id);
    }

    if (data->dsm->nb_local_svm == 0) {
        remove_dsm(data->dsm);
        dsm_printk(KERN_INFO "[Release ] last local svm , freeing the dsm");
    }
    kfree(data);

    return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
    struct private_data *priv_data = (struct private_data *) f->private_data;
    void __user *argp = (void __user *) arg;
    int r = -EINVAL;

    dsm_printk(KERN_DEBUG "entering with ioctl %d", ioctl);

    /* special case: no need for prior dsm in process */
    if (ioctl == HECAIOC_DSM_INIT) {
        r = register_dsm(priv_data, argp);
        goto out;
    }

    if (!priv_data->dsm) {
        dsm_printk(KERN_ERR "module not initiated - existing");
        goto out;
    }

    switch (ioctl) {
        case HECAIOC_SVM_ADD:
            r = register_svm(argp);
            break;
        case HECAIOC_MR_ADD:
            r = register_mr(argp);
            break;
        case HECAIOC_MR_PUSHBACK: {
            r = pushback_page(argp);
            break;
        }
        default: {
            r = -EFAULT;
            dsm_printk(KERN_ERR "don't support ioctl %d", ioctl);
            break;
        }
    }

out: 
    dsm_printk(KERN_DEBUG "exiting return code of %d", r);
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
    int rc;

    BUG_ON(!dsm_state);
    dsm_zero_pfn_init();
    dsm_sysfs_setup(dsm_state);
    dsm_hook_write(&my_dsm_hook);
    rc = misc_register(&rdma_misc);

    dsm_printk(KERN_DEBUG "existing function: %d", rc);
    return rc;
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
    if (dsm_state->rcm)
        destroy_rcm(dsm_state);

    misc_deregister(&rdma_misc);
    destroy_dsm_module_state();
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("Benoit Hudzia");
MODULE_DESCRIPTION("Distributed Shared memory Module");
MODULE_LICENSE("GPL");


