/*
 * proc_dsm.c
 *
 *  Created on: 3 Nov 2011
 *      Author: john
 */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <dsm/dsm_core.h>

static int dsminfo_proc_show(struct seq_file *m, void *v)
{
    struct prefetch_stat *pf_stat = get_rcm()->pf_stat;

    seq_printf(m, "#faults %lu\n", pf_stat->num_faults);

    return 0;
}

static int dsminfo_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, dsminfo_proc_show, NULL);
}

static const struct file_operations dsminfo_proc_fops = {
    .open       = dsminfo_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static int __init proc_dsminfo_init(void)
{
    proc_create("dsminfo", 0, NULL, &dsminfo_proc_fops);
    return 0;
}
module_init(proc_dsminfo_init);

