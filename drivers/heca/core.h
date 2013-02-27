/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 * Steve Walsh <steve.walsh@sap.com> 2012 (c)
 */

#ifndef HECA_CORE_H_
#define HECA_CORE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/byteorder/generic.h>
#include <linux/miscdevice.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/rculist.h>
#include <linux/socket.h>
#include <linux/stat.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/page-flags.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/mmu_notifier.h>
#include <linux/mmu_context.h>
#include <linux/init.h>
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/writeback.h>
#include <linux/swap.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <asm-generic/memory_model.h>
#include <asm-generic/mman-common.h>

#include "../../../mm/internal.h"
#include "struct.h"

#define PULL_TAG        (1 << 0)  /* pulling the page */
#define PREFETCH_TAG    (1 << 1)  /* pulling the page for prefetch */
#define PUSH_TAG        (1 << 2)  /* pushing the page */
#define PULL_TRY_TAG    (1 << 3)  /* pulling the page by request (pushing to us) */
#define CLAIM_TAG       (1 << 4)  /* reclaiming a page */

/* dsm.c */
#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)
void __heca_printk(unsigned int level, const char *path, int line,
        const char *func, const char *format, ...);
#define heca_printk(fmt, args...) \
    __heca_printk(0, __FILE__, __LINE__, __func__, fmt, ##args);

#endif /* HECA_CORE_H_ */

