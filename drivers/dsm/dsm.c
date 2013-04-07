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

static char *ip = 0;
static int port = 0;

module_param(ip, charp, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ip, "The ip of the machine running this module - will be used"
       " as node_id.");
module_param(port, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(port, "The port on the machine running this module - used for"
       " DSM_RDMA communication.");

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
    va_end(args);
#endif
}
EXPORT_SYMBOL(__dsm_printk);

static int register_dsm(struct private_data *priv_data, void __user *argp)
{
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk("copy_from_user failed");
        return -EFAULT;
    }

    return create_dsm(priv_data, svm_info.dsm_id);
}

static int register_svm(void __user *argp)
{
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk("copy_from_user failed");
        return -EFAULT;
    }

    return create_svm(svm_info.dsm_id, svm_info.svm_id, svm_info.local);
}

static int register_svm_connection(void __user *argp)
{
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk("copy_from_user failed");
        return -EFAULT;
    }

    return connect_svm(svm_info.dsm_id, svm_info.svm_id, svm_info.ip,
            svm_info.port);
}

static int register_mr(void __user *argp)
{
    struct unmap_data udata;

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        dsm_printk("copy_from_user failed");
        return -EFAULT;
    }

    return create_mr(udata.dsm_id, udata.id, udata.addr, udata.sz,
            udata.svm_ids, udata.unmap);
}

static int unmap_range(void __user *argp)
{
    int r = -EFAULT;
    struct unmap_data udata;
    struct dsm *dsm;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    dsm = find_dsm(udata.dsm_id);
    if (!dsm)
        goto out;

    r = do_unmap_range(dsm, dsm_get_descriptor(dsm->dsm_id, udata.svm_ids),
            udata.addr, udata.addr + udata.sz - 1);

out:
    return r;
}

/*
 * debug/devel only
 */
static int pushback_page(void __user *argp)
{
    int r = -EFAULT;
    struct unmap_data udata;
    unsigned long addr;
    struct page *page;

    if (copy_from_user((void *) &udata, argp, sizeof udata))
        goto out;

    addr =((unsigned long) udata.addr) & PAGE_MASK;

    page = dsm_find_normal_page(current->mm, addr);
    if (!page || !trylock_page(page))
        goto out;

    r = !push_back_if_remote_dsm_page(page);
    if (r)
        unlock_page(page);

out:
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

    /* special case: no need for prior dsm in process */
    if (ioctl == DSM_DSM) {
        r = register_dsm(priv_data, argp);
        goto out;
    }

    if (!priv_data->dsm)
        goto out;

    switch (ioctl) {
        case DSM_SVM:
            r = register_svm(argp);
            break;
        case DSM_CONNECT:
            r = register_svm_connection(argp);
            break;
        case DSM_MR:
            r = register_mr(argp);
            break;
        case DSM_UNMAP_RANGE:
            r = unmap_range(argp);
            break;

        /*
         * devel/debug
         */
        case DSM_TRY_PUSH_BACK_PAGE: {
            r = pushback_page(argp);
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
    .write_fault = dsm_write_fault,
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

