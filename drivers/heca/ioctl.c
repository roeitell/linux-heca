/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Steve Walsh <steve.walsh@sap.com> 2012 (c)
 */
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/heca_hook.h>

#include "ioctl.h"
#include "sysfs.h"
#include "base.h"
#include "push.h"
#include "pull.h"
#include "ops.h"
#include "task.h"

/*
 * create the actual trace functions needed for heca.ko
 */
#define CREATE_TRACE_POINTS
#include "trace.h"

#ifdef CONFIG_HECA_DEBUG
static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug level (0 = disable)");
#endif

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

void __heca_printk(unsigned int level, const char *path, int line,
        const char *func, const char *format, ...)
{
#if defined(CONFIG_HECA_DEBUG) || defined(CONFIG_HECA_VERBOSE_PRINTK)
    va_list args;
#ifdef CONFIG_HECA_VERBOSE_PRINTK
    struct va_format vaf;
    char verbose_fmt[] = KERN_DEFAULT "DSM %s:%d [%s] %pV";
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
EXPORT_SYMBOL(__heca_printk);

static int deregister_dsm(__u32 dsm_id);

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
    struct list_head *curr, *next;
    struct dsm *dsm;

    list_for_each_safe (curr, next, &dsm_state->dsm_list) {
        dsm = list_entry(curr, struct dsm, dsm_ptr);
        remove_dsm(dsm);
    }

    destroy_rcm_listener(dsm_state);
    mutex_destroy(&dsm_state->dsm_state_mutex);
    destroy_workqueue(dsm_state->dsm_tx_wq);
    destroy_workqueue(dsm_state->dsm_rx_wq);
    kfree(dsm_state);
    dsm_state = NULL;
}

static int deregister_dsm(__u32 dsm_id)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int ret = 0;
    struct dsm *dsm;
    struct list_head *curr, *next;

    heca_printk(KERN_DEBUG "<enter> dsm_id=%d", dsm_id);
    list_for_each_safe (curr, next, &dsm_state->dsm_list) {
        dsm = list_entry(curr, struct dsm, dsm_ptr);
        if (dsm->dsm_id == dsm_id)
            remove_dsm(dsm);
    }

    destroy_rcm_listener(dsm_state);
    heca_printk(KERN_DEBUG "<exit> %d", ret);
    return ret;
}

static int register_dsm(struct hecaioc_dsm *dsm_info)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int rc;

    heca_printk(KERN_DEBUG "<enter>");

    if ((rc = create_rcm_listener(dsm_state, dsm_info->local.sin_addr.s_addr,
            dsm_info->local.sin_port))) {
        heca_printk(KERN_ERR "create_rcm %d", rc);
        goto done;
    }

    if ((rc = create_dsm(dsm_info->dsm_id))) {
        heca_printk(KERN_ERR "create_dsm %d", rc);
        goto done;
    }

done:
    if (rc)
        deregister_dsm(dsm_info->dsm_id);
    heca_printk(KERN_DEBUG "<exit> %d", rc);
    return rc;
}

static int ioctl_svm(int ioctl, void __user *argp)
{
    struct hecaioc_svm svm_info;

    if (copy_from_user((void *) &svm_info, argp, sizeof svm_info)) {
        heca_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    if (!svm_info.pid) {
        svm_info.pid = task_pid_vnr(current);
        heca_printk(KERN_INFO "no pid defined assuming %d", svm_info.pid);
    }

    switch (ioctl) {
        case HECAIOC_SVM_ADD:
            return create_svm(&svm_info);
        case HECAIOC_SVM_RM:
            remove_svm(svm_info.dsm_id, svm_info.svm_id);
            return 0;
    }
    return -EINVAL;
}

static int ioctl_mr(int ioctl, void __user *argp)
{
    struct hecaioc_mr udata;

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        heca_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    switch (ioctl) {
        case HECAIOC_MR_ADD:
            return create_mr(&udata);
    }

    return -EINVAL;
}

static int ioctl_ps(int ioctl, void __user *argp)
{
    struct hecaioc_ps udata;

    if (copy_from_user((void *) &udata, argp, sizeof udata)) {
        heca_printk(KERN_ERR "copy_from_user failed");
        return -EFAULT;
    }

    if (!udata.pid) {
        udata.pid = task_pid_vnr(current);
        heca_printk(KERN_INFO "no pid defined assuming %d", udata.pid);
    }

    switch (ioctl) {
        case HECAIOC_PS_PUSHBACK:
            return pushback_ps(&udata);
        case HECAIOC_PS_UNMAP:
            return unmap_ps(&udata);
    }

    return -EINVAL;
}

static long ioctl_dsm(unsigned int ioctl, void __user *argp)
{
    struct hecaioc_dsm dsm_info;
    int rc = -EFAULT;

    if ((rc = copy_from_user((void *) &dsm_info, argp, sizeof dsm_info))) {
        heca_printk(KERN_ERR "copy_from_user %d", rc);
        goto failed;
    }

    switch (ioctl) {
        case HECAIOC_DSM_ADD:
            return register_dsm(&dsm_info);
        case HECAIOC_DSM_RM:
            return deregister_dsm(dsm_info.dsm_id);
        default:
            goto failed;
    }

failed:
    return rc;
}

static long heca_ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
    void __user *argp = (void __user *) arg;
    int r = -EINVAL;

    heca_printk(KERN_DEBUG "<enter> ioctl=0x%X", ioctl);

    /* special case: no need for prior dsm in process */
    switch (ioctl) {
        case HECAIOC_DSM_ADD:
        case HECAIOC_DSM_RM:
            r = ioctl_dsm(ioctl, argp);
            goto out;
        case HECAIOC_SVM_ADD:
        case HECAIOC_SVM_RM:
            r = ioctl_svm(ioctl, argp);
            goto out;
        case HECAIOC_MR_ADD:
            r = ioctl_mr(ioctl, argp);
            goto out;
        case HECAIOC_PS_PUSHBACK:
        case HECAIOC_PS_UNMAP:
            r = ioctl_ps(ioctl, argp);
            goto out;
        default:
            heca_printk(KERN_ERR "ioctl 0x%X not supported", ioctl);
    }

out: 
    heca_printk(KERN_DEBUG "<exit> ioctl=0x%X: %d", ioctl, r);
    return r;
}

static struct file_operations heca_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = heca_ioctl,
    .llseek = noop_llseek,
};

static struct miscdevice heca_misc = {
    MISC_DYNAMIC_MINOR,
    "heca",
    &heca_fops,
};

const struct heca_hook_struct my_heca_hook = {
    .name = "HECA",
    .fetch_page = dsm_swap_wrapper,
    .pushback_page = push_back_if_remote_dsm_page,
    .is_congested = dsm_is_congested,
    .attach_task = heca_attach_task,
    .detach_task = heca_detach_task,
};

static int dsm_init(void)
{
    struct dsm_module_state *dsm_state = create_dsm_module_state();
    int rc;

    heca_printk(KERN_DEBUG "<enter>");

    BUG_ON(!dsm_state);
    dsm_zero_pfn_init();
    heca_sysfs_setup(dsm_state);
    rc = misc_register(&heca_misc);
    init_rcm();
    BUG_ON(heca_hook_register(&my_heca_hook));

    heca_printk(KERN_DEBUG "<exit> %d", rc);
    return rc;
}
module_init(dsm_init);

static void dsm_exit(void)
{
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    heca_printk(KERN_DEBUG "<enter>");
    BUG_ON(heca_hook_unregister());
    fini_rcm();
    misc_deregister(&heca_misc);
    heca_sysfs_cleanup(dsm_state);
    dsm_zero_pfn_exit();
    destroy_dsm_module_state();
    heca_printk(KERN_DEBUG "<exit>");
}
module_exit(dsm_exit);

MODULE_VERSION("0.2.0");
MODULE_AUTHOR("Benoit Hudzia");
MODULE_DESCRIPTION("Hecatonchire Module");
MODULE_LICENSE("GPL");

