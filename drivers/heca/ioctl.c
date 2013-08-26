/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Steve Walsh <steve.walsh@sap.com> 2012 (c)
 */
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/heca_hook.h>
#include <linux/kern_levels.h>

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

void __heca_printk(const char *file, int line,
                const char *func, const char *format, ...)
{
#if defined(CONFIG_HECA_DEBUG) || defined(CONFIG_HECA_VERBOSE_PRINTK)
        int kern_level;
        va_list args;
        struct va_format vaf;
        char verbose_fmt[] = KERN_DEFAULT "heca:"
#ifdef CONFIG_HECA_VERBOSE_PRINTK
                " %s:%d [%s]"
#endif
                " %pV\n";

        va_start(args, format);
        vaf.fmt = format;
        vaf.va = &args;

        kern_level = printk_get_level(format);
        if (kern_level) {
                const char *end_of_header = printk_skip_level(format);
                memcpy(verbose_fmt, format, end_of_header - format);
                vaf.fmt = end_of_header;
        }

        printk(verbose_fmt,
#ifdef CONFIG_HECA_VERBOSE_PRINTK
                        sanity_file_name(file), line, func,
#endif
                        &vaf);

        va_end(args);
#endif
}
EXPORT_SYMBOL(__heca_printk);

static int deregister_hspace(__u32 hspace_id);

static struct heca_module_state *heca_state;

inline struct heca_module_state *get_heca_module_state(void)
{
        return heca_state;
}

struct heca_module_state *create_heca_module_state(void)
{
        heca_state = kzalloc(sizeof(struct heca_module_state), GFP_KERNEL);
        BUG_ON(!(heca_state));
        INIT_RADIX_TREE(&heca_state->hspaces_tree_root,
                        GFP_KERNEL & ~__GFP_WAIT);
        INIT_RADIX_TREE(&heca_state->mm_tree_root, GFP_KERNEL & ~__GFP_WAIT);
        INIT_LIST_HEAD(&heca_state->hspaces_list);
        mutex_init(&heca_state->heca_state_mutex);
        spin_lock_init(&heca_state->radix_lock);
        heca_state->heca_tx_wq = alloc_workqueue("heca_rx_wq",
                        WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM , 0);
        heca_state->heca_rx_wq = alloc_workqueue("heca_tx_wq",
                        WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM , 0);
        return heca_state;
}

void destroy_heca_module_state(void)
{
        struct list_head *curr, *next;
        struct heca_space *hspace;

        list_for_each_safe (curr, next, &heca_state->hspaces_list) {
                hspace = list_entry(curr, struct heca_space, hspace_ptr);
                remove_hspace(hspace);
        }

        destroy_hcm_listener(heca_state);
        mutex_destroy(&heca_state->heca_state_mutex);
        destroy_workqueue(heca_state->heca_tx_wq);
        destroy_workqueue(heca_state->heca_rx_wq);
        kfree(heca_state);
        heca_state = NULL;
}

static int deregister_hspace(__u32 hspace_id)
{
        struct heca_module_state *heca_state = get_heca_module_state();
        int ret = 0;
        struct heca_space *hspace;
        struct list_head *curr, *next;

        heca_printk(KERN_DEBUG "<enter> hspace_id=%d", hspace_id);
        list_for_each_safe (curr, next, &heca_state->hspaces_list) {
                hspace = list_entry(curr, struct heca_space, hspace_ptr);
                if (hspace->hspace_id == hspace_id)
                        remove_hspace(hspace);
        }

        destroy_hcm_listener(heca_state);
        heca_printk(KERN_DEBUG "<exit> %d", ret);
        return ret;
}

static int register_hspace(struct hecaioc_hspace *hspace_info)
{
        struct heca_module_state *heca_state = get_heca_module_state();
        int rc;

        heca_printk(KERN_DEBUG "<enter>");

        if ((rc = create_hcm_listener(heca_state,
                                        hspace_info->local.sin_addr.s_addr,
                                        hspace_info->local.sin_port))) {
                heca_printk(KERN_ERR "create_hcm %d", rc);
                goto done;
        }

        if ((rc = create_hspace(hspace_info->hspace_id))) {
                heca_printk(KERN_ERR "create_hspace %d", rc);
                goto done;
        }

done:
        if (rc)
                deregister_hspace(hspace_info->hspace_id);
        heca_printk(KERN_DEBUG "<exit> %d", rc);
        return rc;
}

static int ioctl_hproc(int ioctl, void __user *argp)
{
        struct hecaioc_hproc hproc_info;

        if (copy_from_user((void *) &hproc_info, argp, sizeof hproc_info)) {
                heca_printk(KERN_ERR "copy_from_user failed");
                return -EFAULT;
        }

        if (!hproc_info.pid) {
                hproc_info.pid = get_current_pid();
                heca_printk(KERN_INFO "no pid defined assuming %d",
                                hproc_info.pid);
        }

        switch (ioctl) {
        case HECAIOC_HPROC_ADD:
                return create_hproc(&hproc_info);
        case HECAIOC_HPROC_RM:
                remove_hproc(hproc_info.hspace_id, hproc_info.hproc_id);
                return 0;
        }
        return -EINVAL;
}

static int ioctl_mr(int ioctl, void __user *argp)
{
        struct hecaioc_hmr udata;

        if (copy_from_user((void *) &udata, argp, sizeof udata)) {
                heca_printk(KERN_ERR "copy_from_user failed");
                return -EFAULT;
        }

        switch (ioctl) {
        case HECAIOC_HMR_ADD:
                return create_heca_mr(&udata);
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
                udata.pid = get_current_pid();
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

static long ioctl_hspace(unsigned int ioctl, void __user *argp)
{
        struct hecaioc_hspace hspace_info;
        int rc = -EFAULT;

        if ((rc = copy_from_user((void *) &hspace_info, argp,
                                        sizeof hspace_info))) {
                heca_printk(KERN_ERR "copy_from_user %d", rc);
                goto failed;
        }

        switch (ioctl) {
        case HECAIOC_HSPACE_ADD:
                return register_hspace(&hspace_info);
        case HECAIOC_HSPACE_RM:
                return deregister_hspace(hspace_info.hspace_id);
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

        /* special case: no need for prior hspace in process */
        switch (ioctl) {
        case HECAIOC_HSPACE_ADD:
        case HECAIOC_HSPACE_RM:
                r = ioctl_hspace(ioctl, argp);
                goto out;
        case HECAIOC_HPROC_ADD:
        case HECAIOC_HPROC_RM:
                r = ioctl_hproc(ioctl, argp);
                goto out;
        case HECAIOC_HMR_ADD:
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
        .fetch_page = heca_do_page_fault,
        .pushback_page = push_back_if_remote_heca_page,
        .is_congested = heca_is_congested,
        .write_fault = heca_write_fault,
        .attach_task = heca_attach_task,
        .detach_task = heca_detach_task,
};

static int heca_init(void)
{
        struct heca_module_state *heca_state = create_heca_module_state();
        int rc;

        heca_printk(KERN_DEBUG "<enter>");

        BUG_ON(!heca_state);
        heca_zero_pfn_init();
        heca_sysfs_setup(heca_state);
        rc = misc_register(&heca_misc);
        init_hcm();
        BUG_ON(heca_hook_register(&my_heca_hook));

        heca_printk(KERN_DEBUG "<exit> %d", rc);
        return rc;
}
module_init(heca_init);

static void heca_exit(void)
{
        struct heca_module_state *heca_state = get_heca_module_state();

        heca_printk(KERN_DEBUG "<enter>");
        BUG_ON(heca_hook_unregister());
        fini_hcm();
        misc_deregister(&heca_misc);
        heca_sysfs_cleanup(heca_state);
        heca_zero_pfn_exit();
        destroy_heca_module_state();
        heca_printk(KERN_DEBUG "<exit>");
}
module_exit(heca_exit);

MODULE_VERSION("0.2.0");
MODULE_AUTHOR("Benoit Hudzia");
MODULE_DESCRIPTION("Hecatonchire Module");
MODULE_LICENSE("GPL");

