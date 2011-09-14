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

struct route_element *find_routing_element(struct dsm_vm_id *id)
{
    return search_rb_route(_rcm, id);

}

struct route_element *find_local_routing_element(struct route_element * route_e, struct mm_struct * mm)
{
    struct route_element * re;
    list_for_each_entry_rcu(re, route_e->head, ls)
    {
        printk("[find_local_routing_element]  dsm_id : %d - vm_id : %d\n", re->id.dsm_id, re->id.vm_id);

        if (re->data)
            if (re->data->mm == mm)
            {
                printk("[find_local_routing_element] RETURNING - \n");
                return re;
            }
    }

    return NULL;
}

/*
 *  Blue pages are local to this machine.
 */
int page_blue(unsigned long addr, struct dsm_vm_id *id)
{
    struct route_element *rele = search_rb_route(_rcm, id);
    struct private_data *data = rele->data;
    int r = 0;

    if (data->remote_addr != addr)
        r = 1;

    return r;

}

static int open(struct inode *inode, struct file *f)
{
    private_data *data;

    write_lock(&_rcm->conn_lock);
    data = kmalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -EFAULT;

    data->root_swap = RB_ROOT;
    rwlock_init(&data->dsm_data_lock);
    data->mm = current->mm;
    data->remote_addr = 0;
    INIT_LIST_HEAD(&data->head);

    printk("[open]\n");

    printk("[open] 1: %p\n", (void*) f->private_data);

    f->private_data = (void *) data;

    printk("[open] 2: %p\n", (void*) f->private_data);
    write_unlock(&_rcm->conn_lock);
    return 0;

}

static void free_dsm_mr(struct rcu_head *head)
{
    kfree(container_of(head, struct mem_region, rcu));
}

static void free_route_element(struct rcu_head *head)
{
    struct route_element *route_e;
    route_e = (struct route_element *) container_of(head, struct route_element, rcu_head);
    erase_rb_route(&_rcm->root_route, route_e);
}

static int release(struct inode *inode, struct file *f)
{
    private_data *data = (private_data *) f->private_data;
    struct route_element *rele = NULL;
    struct mem_region *mr = NULL;
    struct list_head * head;
    write_lock(&_rcm->conn_lock);
    printk("[release] %p\n", (void*) data);
    if (!data->self_route_e)
        goto out;
    printk("[*] a\n");

    list_for_each_entry_rcu(rele, data->self_route_e->head, ls)
    {
        printk("[release] scanning dsm_id : %d - vm_id : %d\n", rele->id.dsm_id, rele->id.vm_id);
        if (rele != data->self_route_e)
            if (rele->data)
            {
                printk("[*] q\n");
                goto fake_remove;
            }
    }

    printk("[*] b\n");
    head = data->self_route_e->head;
    list_for_each_entry_rcu(rele, data->self_route_e->head, ls)
    {
        printk("\n[release] removing dsm_id : %d - vm_id : %d\n", rele->id.dsm_id, rele->id.vm_id);
        list_for_each_entry_rcu(mr, &rele->mr_head, ls)
        {
            printk("\n[release] removing mr : %p size %ull\n", (void *) mr->addr, mr->sz);
            list_del_rcu(&mr->ls);
            call_rcu(&mr->rcu, free_dsm_mr);
        }
        list_del_rcu(&rele->ls);
        call_rcu(&rele->rcu_head, free_route_element);

    }
    synchronize_rcu();
    kfree(head);
    printk("[*] c\n");
    fake_remove:

    printk("[*] e\n");
    data->self_route_e->data = NULL;

    kfree(data);
    printk("[*] f\n");
    out: printk("\n[release]\n");

    write_unlock(&_rcm->conn_lock);

    return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
    int r = -1;
    private_data *data = (private_data *) f->private_data;
    void __user *argp = (void __user *) arg;
    struct connect_data c_data;
    struct r_data r_data;

    struct route_element *rele;
    struct dsm_vm_id id;
    struct conn_element *cele;
    int ip_addr;
    struct dsm_message msg;
    struct page *page;


    struct unmap_data udata;

    printk("[IOCTL]\n");

    switch (ioctl)
    {
    case RDMA_REG_VM:
    {
        write_lock(&_rcm->conn_lock);
        r = -EFAULT;
        printk("[*] version 17 remote \n");
        if (copy_from_user((void *) &r_data, argp, sizeof r_data))
            goto out;

        id.dsm_id = r_data.dsm_id;
        id.vm_id = r_data.vm_id;
        printk("[RDMA_REG_VM] %p\n", (void*) data);
        printk("[RDMA_REG_VM] dsm_id : %d - vm_id : %d\n", r_data.dsm_id, r_data.vm_id);

        rele = search_rb_route(_rcm, &id);

        printk("[RDMA_REG_VM] Searched rb_route - found = %d\n", !!rele);

        if (!rele)
        {
            printk("[RDMA_REG_VM] About to create route_element\n");

            rele = kmalloc(sizeof(*rele), GFP_KERNEL);
            if (!rele)
            {
                r = -EFAULT;
                goto out_reg_vm;

            }

            // DSM1 - loopback connection will cause issues.
            //rele->ele = search_rb_conn(_rcm, inet_addr("127.0.0.1"));

            rele->id.dsm_id = id.dsm_id;
            rele->id.vm_id = id.vm_id;
            rele->data = data;
            INIT_LIST_HEAD(&rele->mr_head);
            rele->head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
            INIT_LIST_HEAD(rele->head);
            list_add_rcu(&rele->ls, rele->head);
            insert_rb_route(_rcm, rele);

            data->self_route_e = rele;
            data->offset = r_data.offset;

            r = 0;

        }
        else
        {
            printk("[RDMA_REG_VM] we updated the vm  entry\n");
            rele->data = data;
            data->self_route_e = rele;
            data->offset = r_data.offset;
            r = 0;
        }
        out_reg_vm: write_unlock(&_rcm->conn_lock);
        break;

    }
    case RDMA_CONNECT:
    {
        r = -EFAULT;

        if (copy_from_user((void *) &c_data, argp, sizeof c_data))
            goto out;

        printk("[RDMA_CONNECT]\n");

        if (_rcm)
        {
            id.dsm_id = c_data.dsm_id;
            id.vm_id = c_data.vm_id;

            ip_addr = inet_addr(c_data.ip);

            // Check for connection
            cele = search_rb_conn(_rcm, ip_addr);

            if (!cele)
            {
                printk("[RDMA_CONNECT] creating connection\n");

                r = create_connection(_rcm, &c_data);
                printk("[RDMA_CONNECT] create_connection - %d\n", r);

                if (r)
                    goto out;

                printk("[RDMA_CONNECT] connection created \n");

            }

            rele = search_rb_route(_rcm, &id);

            printk("[RDMA_CONNECT] searching_rb_route : %d\n", !!rele);

            if (!rele)
            {
                printk("[RDMA_CONNECT] no route\n");

                rele = kmalloc(sizeof(*rele), GFP_KERNEL);
                if (!rele)
                {
                    r = -EFAULT;
                    goto out;

                }

                rele->ele = search_rb_conn(_rcm, ip_addr);
                rele->id.dsm_id = id.dsm_id;
                rele->id.vm_id = id.vm_id;
                rele->data = 0;

                insert_rb_route(_rcm, rele);

                printk("[RDMA_CONNECT] inserted routing element to rb_tree\n");

            }
            else
                r = -EEXIST;

        }
        else
            r = -1;

        break;

    }
    case PAGE_SWAP:
    {
        r = -EFAULT;


        printk("[PAGE_SWAP] swapping of one page \n");
        if (copy_from_user((void *) &msg, argp, sizeof msg))
            goto out;

        page = dsm_extract_page_from_remote(&msg);

        r = !!page;

        break;

    }
    case UNMAP_PAGE:
    {

        r = -EFAULT;


        if (copy_from_user((void *) &udata, argp, sizeof udata))
        {
            goto out;
        }

        read_lock(&_rcm->conn_lock);
        rele = search_rb_route(_rcm, &udata.id);
        read_unlock(&_rcm->conn_lock);
        if (!rele)
        {
            printk("[UNMAP_PAGE] could not find the route element \n");
            r = -1;
            printk("[unmap page 1] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id, udata.id.vm_id);
            goto out;

        }

        printk("[unmap page 2] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id, udata.id.vm_id);

        if (data->self_route_e->id.dsm_id != rele->id.dsm_id)
        {
            printk("[UNMAP_PAGE] DSM id not same, bad id  \n");
            r = -1;
        }

        data->remote_addr = udata.addr;

        r = dsm_flag_page_remote(current->mm, udata.id, udata.addr);

        break;

    }
    case REGISTER_MR:
    {
        //DSM1 we need to do a global lock and verify if the MR already exist
        struct mem_region *mr;
        struct dsm_mr dsm_mr;
        r = -EFAULT;
        write_lock(&_rcm->conn_lock);
        if (copy_from_user((void *) &dsm_mr, argp, sizeof dsm_mr))
            goto out;

        if (unlikely(dsm_mr.id.dsm_id != data->self_route_e->id.dsm_id))
        {
            printk("[REGISTER_MR] bad mr registration ... \n");

        }
        else
            if (dsm_mr.id.vm_id == data->self_route_e->id.vm_id)
            {
                printk("[REGISTER_MR] we add to local list\n");
                list_for_each_entry_rcu(mr, &data->self_route_e->mr_head, ls)
                {
                    if (mr->addr == dsm_mr.start_addr)
                    {
                        goto register_mr_out;
                    }
                }

                mr = kmalloc(sizeof(*mr), GFP_KERNEL);
                printk("[REGISTER_MR] registering a memory region dsm_id : %d - vm_id : %d, local dsm_id : %d - vm_id : %d\n", dsm_mr.id.dsm_id, dsm_mr.id.vm_id, data->self_route_e->id.dsm_id, data->self_route_e->id.vm_id);
                mr->addr = dsm_mr.start_addr;
                mr->sz = dsm_mr.size;
                printk("\n[REGISTER_MR] adding mr : %p size %ull\n", (void *) mr->addr, mr->sz);
                list_add_rcu(&mr->ls, &data->self_route_e->mr_head);

                r = 0;
            }
            else
            {
                printk("[REGISTER_MR] we add to remote list\n");
                read_lock(&_rcm->conn_lock);
                rele = search_rb_route(_rcm, &dsm_mr.id);
                read_unlock(&_rcm->conn_lock);

                if (!rele)
                {
                    printk("[REG DSM MR] failed couldn't find the dsm id \n");

                }
                else
                {

                    list_for_each_entry_rcu(mr, &rele->mr_head, ls)
                    {
                        if (mr->addr == dsm_mr.start_addr)
                        {
                            goto register_mr_out;
                        }
                    }
                    printk("[REGISTER_MR] adding region to remote vm \n");
                    mr = kmalloc(sizeof(*mr), GFP_KERNEL);
                    printk("[REGISTER_MR] registering a memory region dsm_id : %d - vm_id : %d, local dsm_id : %d - vm_id : %d\n", dsm_mr.id.dsm_id, dsm_mr.id.vm_id, data->self_route_e->id.dsm_id, data->self_route_e->id.vm_id);
                    mr->addr = dsm_mr.start_addr;
                    mr->sz = dsm_mr.size;
                    printk("\n[REGISTER_MR] adding mr : %p size %ul\n", (void *) mr->addr, (unsigned long) mr->sz);
                    list_add_rcu(&mr->ls, &rele->mr_head);

                    r = 0;

                }
            }
        register_mr_out: write_unlock(&_rcm->conn_lock);
        break;

    }
    case FAKE_RDMA_CONNECT:
    {
        r = -EFAULT;
        printk("[FAKE_RDMA_CONNECT] registering a remote VM \n");
        if (copy_from_user((void *) &r_data, argp, sizeof r_data))
            goto out;

        id.dsm_id = r_data.dsm_id;
        id.vm_id = r_data.vm_id;

        printk("[FAKE_RDMA_CONNECT] dsm_id : %d - vm_id : %d\n", r_data.dsm_id, r_data.vm_id);
        write_lock(&_rcm->conn_lock);
        rele = search_rb_route(_rcm, &id);

        printk("[FAKE_RDMA_CONNECT] Searched rb_route - found = %d\n", !!rele);

        if (!rele)
        {
            printk("[FAKE_RDMA_CONNECT] About to create route_element\n");

            rele = kmalloc(sizeof(*rele), GFP_KERNEL);
            if (!rele)
            {
                r = -EFAULT;
                goto out_fake_rdma_connect;

            }
            rele->id.dsm_id = id.dsm_id;
            rele->id.vm_id = id.vm_id;
            rele->data = NULL;
            INIT_LIST_HEAD(&rele->mr_head);
            rele->head = data->self_route_e->head;
            //we add the route to the remote note list of the dsm_data
            list_add_rcu(&rele->ls, data->self_route_e->head);
            insert_rb_route(_rcm, rele);

            r = 0;

        }
        else
            if (rele->head != data->self_route_e->head)
            {
                struct route_element *re, *re_2, *re_3;
                r = 0;
                printk("[FAKE_RDMA_CONNECT] element already existing updating \n");
                list_for_each_entry_rcu(re, rele->head, ls)
                {
                    printk("[FAKE_RDMA_CONNECT] dsm_id : %d - vm_id : %d\n", re->id.dsm_id, re->id.vm_id);
                    re_3 = re;
                    list_for_each_entry_rcu(re_2, data->self_route_e->head, ls)
                    {
                        if (re_2 == re)
                            re_3 = NULL;

                    }
                    if (re_3)
                    {
                        list_del_rcu(&re_3);
                        list_add_rcu(&re_3->ls, data->self_route_e->head);
                    }

                }
                synchronize_rcu();
                kfree(rele->head);
                rele->head = data->self_route_e->head;
            }
            else
            {
                r = 0;
            }

out_fake_rdma_connect:
        write_unlock(&_rcm->conn_lock);
        break;

    }

    default:
    {
        r = -EFAULT;

        break;

    }

    }

    out: return r;

}

static struct file_operations rdma_fops =
{ .owner = THIS_MODULE, .release = release, .unlocked_ioctl = ioctl, .open = open, .llseek = noop_llseek,

};

static struct miscdevice rdma_misc =
{ MISC_DYNAMIC_MINOR, "rdma", &rdma_fops,

};

module_param(ip, charp, S_IRUGO|S_IWUSR);
module_param(port, int, S_IRUGO|S_IWUSR);

MODULE_PARM_DESC(ip, "The ip of the machine running this module - will be used as node_id.");
MODULE_PARM_DESC( port, "The port on the machine running this module - used for DSM_RDMA communication.");

static int dsm_init(void)
{
    reg_dsm_functions(&find_routing_element, &find_local_routing_element, &erase_rb_swap, &insert_rb_swap, &page_blue, &search_rb_swap);

    printk("[dsm_init] ip : %s\n", ip);
    printk("[dsm_init] port : %d\n", port);

    if (create_rcm(&_rcm, ip, port))
        goto err;

    rdma_listen(_rcm->cm_id, 2);
//DSM2: really need better cleanup here - incase of failure
    err: return misc_register(&rdma_misc);

}
module_init(dsm_init);

static void dsm_exit(void)
{
    dereg_dsm_functions();

    destroy_rcm(&_rcm);

    misc_deregister(&rdma_misc);

}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
MODULE_LICENSE("GPL");
