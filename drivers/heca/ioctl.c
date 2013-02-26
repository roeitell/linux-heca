/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Steve Walsh <steve.walsh@sap.com> 2012 (c)
 */
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/heca_hook.h>
#include "core.h"
#include "sysfs.h"
#include "base.h"
#include "push.h"
#include "pull.h"
#include "ops.h"

#ifdef CONFIG_HECA_DEBUG
static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug level (0 = disable)");
#endif

static pid_t sys_getpid(void)
{
    return task_pid_vnr(current);
}

#ifdef CONFIG_HECA_VERBOSE_PRINTK
/* strip the leading path if the given path is absolute */
static const char *sanity_file_name(const char *path)
{
    if (*path == '/')
    return strrchr(path, '/') + 1;
    else
    return path;
}
#endif

void __dsm_printk(unsigned int level, const char *path, int line,
        const char *func, const char *format, ...)
{
#if defined(CONFIG_HECA_DEBUG) || defined(CONFIG_HECA_VERBOSE_PRINTK)
    va_list args;
#ifdef CONFIG_HECA_VERBOSE_PRINTK
    struct va_format vaf;
    char verbose_fmt[] = KERN_DEFAULT "DSM %s:%d (%s) %pV";
#endif

#ifdef CONFIG_HECA_DEBUG
    if (debug < level)
        return;
#endif

    va_start(args, format);

#ifdef CONFIG_HECA_VERBOSE_PRINTK
    vaf.fmt = format;
    vaf.va = &args;
    if (format[0] == '<' && format[2] == '>') {
        memcpy(verbose_fmt, format, 3);
        vaf.fmt = format + 3;
    } else if (level)
        memcpy(verbose_fmt, KERN_DEBUG, 3);
    printk(verbose_fmt, sanity_file_name(path), line, func, &vaf);
#else
    vprintk(format, args);
#endif
    printk("\n");

    va_end(args);
#endif
}
EXPORT_SYMBOL(__dsm_printk);

static int deregister_dsm(struct private_data *priv_data, pid_t pid_vnr,
        __u32 dsm_id)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int rc = 0;
    struct dsm *dsm = priv_data->dsm;

    dsm_printk(KERN_DEBUG "deregister_dsm [enter] dsm_id=%d", dsm_id);

    BUG_ON(!dsm_state);

    if (!dsm) {
        rc = -EFAULT;
        goto done;
    }

    BUG_ON(dsm->pid_vnr != pid_vnr);
    BUG_ON(dsm->dsm_id != dsm_id);

    if (priv_data->dsm) {
        if (!priv_data->dsm->nb_local_svm) {
            remove_dsm(priv_data->dsm);
            priv_data->dsm = NULL;
        } else
            --priv_data->dsm->nb_local_svm;
    }

    if (dsm_state->rcm) { 
        destroy_rcm_listener(dsm_state);
        dsm_state->rcm = NULL;
    }

done:
    dsm_printk(KERN_DEBUG "deregister_dsm [exit] %d", rc);
    return rc;
}

static int register_dsm(struct private_data *priv_data, 
        struct svm_data *svm_info)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int rc;

    dsm_printk(KERN_DEBUG "[enter]");

    if ((rc = create_rcm_listener(dsm_state, svm_info->server.sin_addr.s_addr,
            svm_info->server.sin_port))) {
        dsm_printk(KERN_ERR "create_rcm %d", rc);
        goto done;
    }

    if ((rc = create_dsm(priv_data, svm_info->pid_vnr, svm_info->dsm_id))) {
        dsm_printk(KERN_ERR "create_dsm %d", rc);
        goto done;
    }

done:
    if (rc)
        deregister_dsm(priv_data, svm_info->pid_vnr, svm_info->dsm_id);
    dsm_printk(KERN_DEBUG "[exit] %d", rc);
    return rc;
}

static int ioctl_svm(int ioctl, void __user *argp)
{
    struct svm_data svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        dsm_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    if (!svm_info.pid_vnr)
        svm_info.pid_vnr = sys_getpid();

    switch (ioctl) {
        case HECAIOC_SVM_ADD:
            return create_svm(&svm_info);
        case HECAIOC_SVM_RM:
            remove_svm(svm_info.dsm_id, svm_info.svm_id);
            return 0;
    }
    return -EINVAL;
}

static int unmap_mr(struct unmap_data *udata)
{
    int r = -EFAULT;
    struct dsm *dsm = NULL;
    struct subvirtual_machine *local_svm = NULL;
    struct memory_region * mr = NULL;

    dsm = find_dsm(udata->dsm_id);
    if (!dsm)
        goto out;

    local_svm = find_local_svm_in_dsm(dsm, current->mm);
    if (!local_svm)
        goto out;
    
    mr = search_mr_by_addr(local_svm, (unsigned long) udata->addr);
    if (!mr)
        goto out;

    r = do_unmap_range(dsm, mr->descriptor, udata->addr, udata->addr+udata->sz - 1);

out:
    if (local_svm)
        release_svm(local_svm);
    return r;
}

static int pushback_mr(struct unmap_data *udata)
{
    int r = -EFAULT;
    unsigned long addr, start_addr;
    struct dsm *dsm;
    struct memory_region *mr;
    struct page *page;
    struct subvirtual_machine *local_svm = NULL;

    dsm = find_dsm(udata->dsm_id);
    if (!dsm)
        goto out;

    local_svm = find_local_svm_in_dsm(dsm, current->mm);
    if (!local_svm)
        goto out;

    addr = start_addr = ((unsigned long) udata->addr) & PAGE_MASK;
    while (addr < start_addr + udata->sz) {

        mr = search_mr_by_addr(local_svm, addr);
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

static int ioctl_mr(int ioctl, void __user *argp)
{
    struct unmap_data udata;

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        dsm_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    if (!udata.pid_vnr)
        udata.pid_vnr = sys_getpid();

    switch (ioctl) {
        case HECAIOC_MR_ADD:
            return create_mr(udata.dsm_id, udata.mr_id, udata.addr, udata.sz,
                udata.svm_ids, udata.flags);
        case HECAIOC_MR_PUSHBACK:
            return pushback_mr(&udata);
        case HECAIOC_MR_UNMAP:
            return unmap_mr(&udata);
    }

    return -EINVAL;
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
    struct private_data *priv_data = (struct private_data *) f->private_data;
    struct subvirtual_machine *svm = NULL;
    struct dsm *dsm;

    dsm_printk(KERN_DEBUG "release [enter]");

    if (!priv_data)
        goto final;
   
    if (!(dsm = priv_data->dsm))
        goto done;

    while (!list_empty(&dsm->svm_list)) {
        svm = list_first_entry(&dsm->svm_list, struct subvirtual_machine,
            svm_ptr);
        dsm_printk(KERN_ERR "removing svm_id: %d from list of svms",
            svm->svm_id);
        remove_svm(dsm->dsm_id, svm->svm_id);
    }

    deregister_dsm(priv_data, dsm->pid_vnr, dsm->dsm_id);

done:
    f->private_data = NULL;
    kfree(priv_data);
final:
    dsm_printk(KERN_DEBUG "release [exit]");
    return 0;
}

static long ioctl_dsm(struct private_data *priv_data, unsigned int ioctl,
    void __user *argp)
{
    struct svm_data svm_info;
    int rc = -EFAULT;

    if ((rc = copy_from_user((void *) &svm_info, argp, sizeof svm_info))) {
        dsm_printk(KERN_ERR "copy_from_user %d", rc);
        goto failed;
    }

    if (!svm_info.pid_vnr)
        svm_info.pid_vnr = sys_getpid();

    switch (ioctl) {
        case HECAIOC_DSM_INIT:
            return register_dsm(priv_data, &svm_info);
        case HECAIOC_DSM_FINI:
            return deregister_dsm(priv_data, svm_info.pid_vnr, svm_info.dsm_id);
        default:
            goto failed;
    }

failed:
    return rc;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
    struct private_data *priv_data = (struct private_data *) f->private_data;
    void __user *argp = (void __user *) arg;
    int r = -EINVAL;

    dsm_printk(KERN_DEBUG "ioctl [enter] ioctl=0x%X", ioctl);

    BUG_ON(!priv_data);

    /* special case: no need for prior dsm in process */
    switch (ioctl) {
        case HECAIOC_DSM_INIT:
        case HECAIOC_DSM_FINI:
            r = ioctl_dsm(priv_data, ioctl, argp);
            goto out;
    }

    if (!priv_data->dsm) {
        dsm_printk(KERN_ERR "module not initiated - existing");
        goto out;
    }

    switch (ioctl) {
        case HECAIOC_SVM_ADD:
        case HECAIOC_SVM_RM:
            r = ioctl_svm(ioctl, argp);
            goto out;
    }

    switch (ioctl) {
        case HECAIOC_MR_ADD:
        case HECAIOC_MR_PUSHBACK:
        case HECAIOC_MR_UNMAP:
            r = ioctl_mr(ioctl, argp);
            goto out;
    }
    r = -EINVAL;
    dsm_printk(KERN_ERR "ioctl 0x%X not supported", ioctl);

out: 
    dsm_printk(KERN_DEBUG "ioctl [exit] ioctl=0x%X: %d", ioctl, r);
    return r;
}

static struct file_operations rdma_fops = { .owner = THIS_MODULE,
    .release = release, .unlocked_ioctl = ioctl, .open = open,
    .llseek = noop_llseek, };
static struct miscdevice rdma_misc = { MISC_DYNAMIC_MINOR, "heca",
    &rdma_fops, };

const struct dsm_hook_struct my_dsm_hook = {
    .name = "HECA",
    .fetch_page = dsm_swap_wrapper,
    .pushback_page = push_back_if_remote_dsm_page,
    .is_congested = dsm_is_congested,
};

static int dsm_init(void)
{
    struct dsm_module_state *dsm_state = create_dsm_module_state();
    int rc;

    dsm_printk(KERN_DEBUG "dsm_init [enter]");

    BUG_ON(!dsm_state);
    dsm_zero_pfn_init();
    heca_sysfs_setup(dsm_state);
    dsm_hook_write(&my_dsm_hook);
    rc = misc_register(&rdma_misc);
    init_rcm();

    dsm_printk(KERN_DEBUG "dsm_init [exit] %d", rc);
    return rc;
}
module_init(dsm_init);

static void dsm_exit(void)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    fini_rcm();
    misc_deregister(&rdma_misc);
    dsm_hook_write(NULL);
    heca_sysfs_cleanup(dsm_state);
    dsm_zero_pfn_exit();
    destroy_dsm_module_state();
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("Benoit Hudzia");
MODULE_DESCRIPTION("Distributed Shared memory Module");
MODULE_LICENSE("GPL");


