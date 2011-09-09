/*
 1 * rdma.c
 *
 *  Created on: 22 Jun 2011
 *      Author: john
 */
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/rculist.h>
#include <asm/uaccess.h>
#include <asm-generic/memory_model.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <rdma/rdma_cm_ib.h>
#include <asm/byteorder.h>

#include <dsm/dsm_ctl.h>
#include <dsm/dsm_op.h>
#include <dsm/dsm_rb.h>
#include <dsm/dsm_core.h>

#include <linux/stat.h>

static struct rcm *_rcm;
static char *ip = 0;
static int port = 0;

struct route_element *find_routing_element(struct dsm_vm_id *id) {
    return search_rb_route(_rcm, id);

}

/*
 *  Blue pages are local to this machine.
 */
int page_blue(unsigned long addr, struct dsm_vm_id *id) {
    struct route_element *rele = search_rb_route(_rcm, id);
    struct dsm_data *data = rele->data;
    int r = 0;

    if (data->remote_addr != addr)
        r = 1;

    return r;

}

static int open(struct inode *inode, struct file *f) {
    dsm_data *data;

    data = kmalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -EFAULT;

    data->root_swap = RB_ROOT;
    rwlock_init(&data->dsm_data_lock);
    data->mm = current->mm;
    data->remote_addr = 0;
    INIT_LIST_HEAD(&data->vm_route_element_list);

    printk("[open]\n");

    f->private_data = (void *) data;

    return 0;

}

static int release(struct inode *inode, struct file *f) {
    dsm_data *data = (dsm_data *) f->private_data;
    struct route_element *rele = NULL;
    struct dsm_memory_region *mr = NULL;
    write_lock(&data->dsm_data_lock);
    list_for_each_entry_rcu(rele, &data->vm_route_element_list, vm_route_element_list)
    {
        printk("\n[release] removing dsm_id : %d - vm_id : %d\n", rele->id.dsm_id, rele->id.vm_id);
        list_for_each_entry_rcu(mr, &rele->local_memory_regions, dsm_memory_region)
        {
            printk("\n[release] removing mr : %p size %ul\n", (void *) mr->start_addr, mr->size);
            list_del_rcu(&mr->dsm_memory_region);
            kfree(mr);
        }
        list_del_rcu(&rele->vm_route_element_list);
        erase_rb_route(&_rcm->root_route, rele);

    }
    mr = NULL;
    list_for_each_entry_rcu(mr, &data->self_route_e->local_memory_regions, dsm_memory_region)
    {
        list_del_rcu(&mr->dsm_memory_region);
        kfree(mr);
    }
    erase_rb_route(&_rcm->root_route, data->self_route_e);
    write_unlock(&data->dsm_data_lock);
    kfree(data);

    printk("\n[release]\n");

    return 0;

}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg) {
    int r = -1;
    dsm_data *data = (dsm_data *) f->private_data;
    void __user *argp = (void __user *) arg;
    struct connect_data c_data;
    struct r_data r_data;

    struct route_element *rele;
    struct dsm_vm_id id;
    struct conn_element *cele;
    int ip_addr;

    printk("[IOCTL]\n");

    switch (ioctl) {
    case RDMA_REG_VM: {
        r = -EFAULT;
        printk("[*] version 1 \n");
        if (copy_from_user((void *) &r_data, argp, sizeof r_data))
            goto out;

        id.dsm_id = r_data.dsm_id;
        id.vm_id = r_data.vm_id;

        printk("[RDMA_REG_VM] dsm_id : %d - vm_id : %d\n", r_data.dsm_id, r_data.vm_id);

        rele = search_rb_route(_rcm, &id);

        printk("[RDMA_REG_VM] Searched rb_route - found = %d\n", !!rele);

        if (!rele) {
            printk("[RDMA_REG_VM] About to create route_element\n");

            rele = kmalloc(sizeof(*rele), GFP_KERNEL);
            if (!rele) {
                r = -EFAULT;
                goto out;

            }

            // DSM1 - loopback connection will cause issues.
            //rele->ele = search_rb_conn(_rcm, inet_addr("127.0.0.1"));

            rele->id.dsm_id = id.dsm_id;
            rele->id.vm_id = id.vm_id;
            rele->data = data;
            INIT_LIST_HEAD(&rele->local_memory_regions);
            INIT_LIST_HEAD(&rele->vm_route_element_list);

            insert_rb_route(_rcm, rele);

            data->self_route_e = rele;
            data->offset = r_data.offset;

            r = 0;

        } else
            r = -1;

        rele = search_rb_route(_rcm, &id);

        printk("[RDMA_REG_VM] Searched rb_route - found = %d\n", !!rele);
        break;

    }
    case RDMA_CONNECT: {
        r = -EFAULT;

        if (copy_from_user((void *) &c_data, argp, sizeof c_data))
            goto out;

        printk("[RDMA_CONNECT]\n");

        if (_rcm) {
            id.dsm_id = c_data.dsm_id;
            id.vm_id = c_data.vm_id;

            ip_addr = inet_addr(c_data.ip);

            // Check for connection
            cele = search_rb_conn(_rcm, ip_addr);

            if (!cele) {
                printk("[RDMA_CONNECT] creating connection\n");

                r = create_connection(_rcm, &c_data);
                printk("[RDMA_CONNECT] create_connection - %d\n", r);

                if (r)
                    goto out;

                printk("[RDMA_CONNECT] connection created \n");

            }

            rele = search_rb_route(_rcm, &id);

            printk("[RDMA_CONNECT] searching_rb_route : %d\n", !!rele);

            if (!rele) {
                printk("[RDMA_CONNECT] no route\n");

                rele = kmalloc(sizeof(*rele), GFP_KERNEL);
                if (!rele) {
                    r = -EFAULT;
                    goto out;

                }

                rele->ele = search_rb_conn(_rcm, ip_addr);
                rele->id.dsm_id = id.dsm_id;
                rele->id.vm_id = id.vm_id;
                rele->data = 0;

                insert_rb_route(_rcm, rele);

                printk("[RDMA_CONNECT] inserted routing element to rb_tree\n");

            } else
                r = -EEXIST;

        } else
            r = -1;

        break;

    }
    case PAGE_SWAP: {
        r = -EFAULT;

        struct dsm_message msg;
        printk("[PAGE_SWAP] swapping of one page \n");
        if (copy_from_user((void *) &msg, argp, sizeof msg))
            goto out;

        r = dsm_extract_page(&msg);

        break;

    }
    case UNMAP_PAGE: {

        r = -EFAULT;

        struct unmap_data udata;

        if (copy_from_user((void *) &udata, argp, sizeof udata))
            goto out;

        struct route_element *rele = search_rb_route(_rcm, &udata.id);

        if (!rele) {
            rele = kmalloc(sizeof(*rele), GFP_KERNEL);

            rele->data = data;
            rele->ele = 0;

            rele->id.dsm_id = udata.id.dsm_id;
            rele->id.vm_id = udata.id.vm_id;

            insert_rb_route(_rcm, rele);

        }

        if (((int) data->self_route_e->id.dsm_id) == 0)
            data->self_route_e->id.dsm_id = rele->id.dsm_id;

        data->remote_addr = udata.addr;

        r = dsm_flag_page_remote(current->mm, udata.id, udata.addr);

        break;

    }
    case REGISTER_MR: {
        struct dsm_memory_region *dsm_memory_region;
        struct dsm_mr dsm_mr;
        r = -EFAULT;

        if (copy_from_user((void *) &dsm_mr, argp, sizeof dsm_mr))
            goto out;

        dsm_memory_region = kmalloc(sizeof(*dsm_memory_region), GFP_KERNEL);
        printk("[REGISTER_MR] registering a memory region dsm_id : %d - vm_id : %d, local dsm_id : %d - vm_id : %d\n", dsm_mr.id.dsm_id, dsm_mr.id.vm_id, data->self_route_e->id.dsm_id, data->self_route_e->id.vm_id);
        dsm_memory_region->start_addr = dsm_mr.start_addr;
        dsm_memory_region->size = dsm_mr.size;
        printk("\n[release] removing mr : %p size %ul\n", (void *) dsm_memory_region->start_addr, dsm_memory_region->size);
        INIT_LIST_HEAD(&dsm_memory_region->dsm_memory_region);
        if (unlikely(dsm_mr.id.dsm_id != data->self_route_e->id.dsm_id)) {
            printk("[REGISTER_MR] bad mr registration ... \n");

        } else if (dsm_mr.id.vm_id == data->self_route_e->id.vm_id) {
            printk("[REGISTER_MR] we add to local list\n");
            write_lock(&data->dsm_data_lock);
            list_add_rcu(&dsm_memory_region->dsm_memory_region, &data->self_route_e->local_memory_regions);
            write_unlock(&data->dsm_data_lock);

            r = 0;
        } else {
            printk("[REGISTER_MR] we add to remote list\n");
            struct route_element *rele = search_rb_route(_rcm, &dsm_mr.id);

            if (!rele) {
                printk("[REG DSM MR] failed couldn't find the dsm id \n");

            } else {
                printk("[REGISTER_MR] adding region to remote vm \n");
                write_lock(&data->dsm_data_lock);
                list_add_rcu(&dsm_memory_region->dsm_memory_region, &rele->local_memory_regions);
                write_unlock(&data->dsm_data_lock);
                r = 0;

            }
        }

        break;

    }
    case FAKE_RDMA_CONNECT: {
        r = -EFAULT;
        printk("[FAKE_RDMA_CONNECT] registering a remote VM \n");
        if (copy_from_user((void *) &r_data, argp, sizeof r_data))
            goto out;

        id.dsm_id = r_data.dsm_id;
        id.vm_id = r_data.vm_id;

        printk("[FAKE_RDMA_CONNECT] dsm_id : %d - vm_id : %d\n", r_data.dsm_id, r_data.vm_id);

        rele = search_rb_route(_rcm, &id);

        printk("[FAKE_RDMA_CONNECT] Searched rb_route - found = %d\n", !!rele);

        if (!rele) {
            printk("[FAKE_RDMA_CONNECT] About to create route_element\n");

            rele = kmalloc(sizeof(*rele), GFP_KERNEL);
            if (!rele) {
                r = -EFAULT;
                goto out;

            }
            rele->id.dsm_id = id.dsm_id;
            rele->id.vm_id = id.vm_id;
            rele->data = data;
            INIT_LIST_HEAD(&rele->local_memory_regions);
            INIT_LIST_HEAD(&rele->vm_route_element_list);
            //we add the route to the remote note list of the dsm_data
            write_lock(&data->dsm_data_lock);
            list_add_rcu(&rele->vm_route_element_list, &data->vm_route_element_list);
            insert_rb_route(_rcm, rele);
            write_unlock(&data->dsm_data_lock);

            r = 0;

        } else
            r = -1;

        break;

    }

    default: {
        r = -EFAULT;

        break;

    }

    }

    out: return r;

}

static struct file_operations rdma_fops = { .owner = THIS_MODULE, .release = release, .unlocked_ioctl = ioctl, .open = open, .llseek = noop_llseek,

};

static struct miscdevice rdma_misc = { MISC_DYNAMIC_MINOR, "rdma", &rdma_fops,

};

module_param(ip, charp, S_IRUGO|S_IWUSR);
module_param(port, int, S_IRUGO|S_IWUSR);

MODULE_PARM_DESC(ip, "The ip of the machine running this module - will be used as node_id.");
MODULE_PARM_DESC(port, "The port on the machine running this module - used for DSM_RDMA communication.");

static int dsm_init(void) {
    reg_dsm_functions(&find_routing_element, &erase_rb_swap, &insert_rb_swap, &page_blue, &search_rb_swap);

    printk("[dsm_init] ip : %s\n", ip);
    printk("[dsm_init] port : %d\n", port);

    if (create_rcm(&_rcm, ip, port))
        goto err;

    rdma_listen(_rcm->cm_id, 2);
//DSM2: really need better cleanup here - incase of failure
    err: return misc_register(&rdma_misc);

}
module_init(dsm_init);

static void dsm_exit(void) {
    dereg_dsm_functions();

    destroy_rcm(&_rcm);

    misc_deregister(&rdma_misc);

}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
MODULE_LICENSE("GPL");
