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
    spin_lock_init(&data->root_swap_lock);
    data->mm = current->mm;
    data->id.dsm_id = 0;
    data->remote_addr = 0;

    printk("[open]\n");

    f->private_data = (void *) data;

    return 0;

}

static int release(struct inode *inode, struct file *f) {
    dsm_data *data = (dsm_data *) f->private_data;
    int i;
    struct route_element *rele;
    struct dsm_vm_id id;

    id.dsm_id = 1; //data->id.dsm_id;

    for (i = 0; i < 5; ++i) {
        id.vm_id = i;

        // DSM1: FIND AND DESTROY conn_ele?
        // DSM1: think of some way to search and destroy all routes with same dsm_id.
        rele = search_rb_route(_rcm, &id);

        if (rele) {
            erase_rb_route(&_rcm->root_route, rele);

            // DSM1: TEMPORARY
            break;

        }

    }

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

            insert_rb_route(_rcm, rele);

            data->id = id;

            r = 0;

        } else
            r = -1;

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

        if (copy_from_user((void *) &msg, argp, sizeof msg))
            goto out;

        struct dsm_vm_id id;
        id.dsm_id = u32_to_dsm_id(msg.dest);
        id.vm_id = u32_to_vm_id(msg.dest);

        struct route_element *rele = search_rb_route(_rcm, &id);

        if (!rele) {
            rele = kmalloc(sizeof(*rele), GFP_KERNEL);

            rele->data = data;
            rele->ele = 0;

            rele->id.dsm_id = id.dsm_id;
            rele->id.vm_id = id.vm_id;

            insert_rb_route(_rcm, rele);

        }

        if (data->id.dsm_id == 0)
            data->id.dsm_id = rele->id.dsm_id;

        r = dsm_extract_page( &msg);

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

        if (((int) data->id.dsm_id) == 0)
            data->id.dsm_id = rele->id.dsm_id;

        data->remote_addr = udata.addr;

        r = dsm_flag_page_remote(current->mm, udata.id, udata.addr);

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
