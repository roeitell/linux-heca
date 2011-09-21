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

/*
 * Find and return SVM with pointer to process file desc private_data. *
 */
struct route_element *find_local_routing_element(struct route_element * route_e,
		struct mm_struct * mm)
{
	struct route_element *svm;
	struct dsm *_dsm;
	u16 dsm_id = route_e->id.dsm_id;

	list_for_each_entry_rcu(_dsm, &_rcm->dsm_ls, ls)
	{
		printk("[?] _dsm->dsm_id %u\n[?] dsm_id %u\n", (unsigned int) _dsm->dsm_id, (unsigned int) dsm_id);

		if (_dsm->dsm_id == dsm_id)
		{
			list_for_each_entry_rcu(svm, &_dsm->svm_ls, ls)
			{
				if (svm->priv)
					if (svm->priv->mm == mm)
						return svm;

			}

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
	struct private_data *data = rele->priv;
	int r = 0;

	if (data->remote_addr != addr)
		r = 1;

	return r;

}

static int open(struct inode *inode, struct file *f)
{
	private_data *data;

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -EFAULT;

	write_lock(&_rcm->conn_lock);

	data->root_swap = RB_ROOT;
	rwlock_init(&data->dsm_data_lock);
	data->mm = current->mm;
	data->remote_addr = 0;
	INIT_LIST_HEAD(&data->head);

	f->private_data = (void *) data;

	write_unlock(&_rcm->conn_lock);

	return 0;

}

static void free_route_element(struct rcu_head *head)
{
	struct route_element *route_e;

	route_e = (struct route_element *) container_of(head, struct route_element, rcu_head);

	erase_rb_route(&_rcm->root_route, route_e);

}

static void free_mem_region(struct rcu_head *head)
{
	kfree(container_of(head, struct mem_region, rcu));

}

/*
 * 		for DSM in RCM.dsm_ls:
 * 			for SVM in DSM.svm_ls:
 * 				if SVM is local:
 * 					for MR in SVM.mr_ls:
 * 				 		free(MR)
 * 					free(SVM)
 *
 */
static int release(struct inode *inode, struct file *f)
{
	private_data *data = (private_data *) f->private_data;
	struct route_element *svm = NULL;
	struct mem_region *mr = NULL;
	struct dsm *_dsm = NULL;
	u16 dsm_id;

	if (!data->self_route_e)
		return 1;

	write_lock(&_rcm->conn_lock);

	dsm_id = data->self_route_e->id.dsm_id;

	list_for_each_entry_rcu(_dsm, &_rcm->dsm_ls, ls)
	{
		if (_dsm->dsm_id == dsm_id)
		{
			list_for_each_entry_rcu(svm, &_dsm->svm_ls, ls)
			{
				if (svm == data->self_route_e)
				{
					printk("[release] RELE: dsm_id=%u ... vm_id=%u\n", svm->id.dsm_id, svm->id.vm_id);

					list_for_each_entry_rcu(mr, &svm->mr_ls, ls)
					{
						list_del_rcu(&mr->ls);
						call_rcu(&mr->rcu, free_mem_region);

					}

					data->self_route_e->priv = NULL;
					list_del_rcu(&svm->ls);
					call_rcu(&svm->rcu_head, free_route_element);

				}

			}

		}

	}

	synchronize_rcu();

	kfree(data);

	write_unlock(&_rcm->conn_lock);

	return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
	int r = -1;

	struct connect_data c_data;
	struct r_data r_data;

	struct route_element *rele;

	struct conn_element *cele;
	int ip_addr;
	struct dsm_message msg;
	struct page *page;

	struct unmap_data udata;

	printk("[IOCTL]\n");

	private_data *priv_data = (private_data *) f->private_data;
	void __user *argp = (void __user *) arg;
	struct svm_data svm_info;
	struct route_element *svm = NULL;
	struct mem_region *mr = NULL;
	struct dsm *_dsm = NULL;
	struct dsm_vm_id id;


	switch (ioctl)
	{
		case DSM_SVM:
		{
			r = -EFAULT;

			if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
				goto out;

			write_lock(&_rcm->route_lock);

			id.dsm_id = svm_info.dsm_id;
			id.vm_id = svm_info.vm_id;

			// DSM1: To be changed to search_rcu.
			svm = search_rb_route(_rcm, &id);

			if (!svm)
			{
				svm = kmalloc(sizeof(*svm), GFP_KERNEL);
				if (!svm)
					goto fail1;

				priv_data->self_route_e = svm;
				priv_data->offset = svm_info.offset;

				svm->id.dsm_id = svm_info.dsm_id;
				svm->id.vm_id = svm_info.vm_id;
				svm->priv = priv_data;

				_dsm = list_first_entry(&_rcm->dsm_ls, struct dsm, ls);

				list_add_rcu(&svm->ls, &_dsm->svm_ls);

				// DSM1: to be removed
				insert_rb_route(_rcm, svm);

				INIT_LIST_HEAD(&svm->mr_ls);

				mr = kmalloc(sizeof(*mr), GFP_KERNEL);
				if (!mr)
					goto fail1;

				mr->addr = svm_info.start_addr;
				mr->sz = svm_info.size;
				mr->tint = blue;
				mr->svm = svm;

				list_add_rcu(&mr->ls, &svm->mr_ls);

			}
			else
			{
				priv_data->self_route_e = svm;
				priv_data->offset = svm_info.offset;

				svm->priv = priv_data;

				// Free all MR and add new one
				list_for_each_entry_rcu(mr, &svm->mr_ls, ls)
				{
					list_del_rcu(&mr->ls);
					call_rcu(&mr->rcu, free_mem_region);

				}

				synchronize_rcu();

				mr = kmalloc(sizeof(*mr), GFP_KERNEL);
				if (!mr)
					goto fail1;

				mr->addr = svm_info.start_addr;
				mr->sz = svm_info.size;
				mr->tint = blue;
				mr->svm = svm;

				list_add_rcu(&mr->ls, &svm->mr_ls);

			}

			r = 0;
fail1:
			write_unlock(&_rcm->route_lock);

			break;

		}
		case DSM_CONNECT:
		{
			r = -EFAULT;

			if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
				goto out;

			write_lock(&_rcm->route_lock);

			id.dsm_id = svm_info.dsm_id;
			id.vm_id = svm_info.vm_id;

			svm = search_rb_route(_rcm, &id);

			if (!svm)
			{
				svm = kmalloc(sizeof(*svm), GFP_KERNEL);
				if (!svm)
					goto fail2;

				svm->id.dsm_id = svm_info.dsm_id;
				svm->id.vm_id = svm_info.vm_id;
				svm->priv = NULL;

				_dsm = list_first_entry(&_rcm->dsm_ls, struct dsm, ls);

				list_add_rcu(&svm->ls, &_dsm->svm_ls);

				// DSM1: to be removed
				insert_rb_route(_rcm, svm);

				INIT_LIST_HEAD(&svm->mr_ls);

				mr = kmalloc(sizeof(*mr), GFP_KERNEL);
				if (!mr)
					goto fail2;

				mr->addr = svm_info.start_addr;
				mr->sz = svm_info.size;
				mr->tint = red;
				mr->svm = svm;

				list_add_rcu(&mr->ls, &svm->mr_ls);

			}

			r = 0;

fail2:
			write_unlock(&_rcm->route_lock);

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
					rele->priv = 0;

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
				printk("[unmap page 1] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
						udata.id.vm_id);
				goto out;

			}

			printk("[unmap page 2] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
					udata.id.vm_id);

			if (priv_data->self_route_e->id.dsm_id != rele->id.dsm_id)
			{
				printk("[UNMAP_PAGE] DSM id not same, bad id  \n");
				r = -1;
			}

			priv_data->remote_addr = udata.addr;

			r = dsm_flag_page_remote(current->mm, udata.id, udata.addr);

			break;

		}
		default:
		{
			r = -EFAULT;

			break;

		}

	}

out:

	return r;

}

static struct file_operations rdma_fops =
{ .owner = THIS_MODULE, .release = release, .unlocked_ioctl = ioctl, .open =
		open, .llseek = noop_llseek,

};

static struct miscdevice rdma_misc =
{ MISC_DYNAMIC_MINOR, "rdma", &rdma_fops,

};

module_param(ip, charp, S_IRUGO|S_IWUSR);
module_param(port, int, S_IRUGO|S_IWUSR);

MODULE_PARM_DESC(ip,
		"The ip of the machine running this module - will be used as node_id.");
MODULE_PARM_DESC(
		port,
		"The port on the machine running this module - used for DSM_RDMA communication.");

static int dsm_init(void)
{
	reg_dsm_functions(&find_routing_element, &find_local_routing_element,
			&erase_rb_swap, &insert_rb_swap, &page_blue, &search_rb_swap);

	printk("[dsm_init] ip : %s\n", ip);
	printk("[dsm_init] port : %d\n", port);

	if (create_rcm(&_rcm, ip, port))
		goto err;

	INIT_LIST_HEAD(&_rcm->dsm_ls);

	struct dsm *_dsm = kmalloc(sizeof(*_dsm), GFP_KERNEL);

	_dsm->dsm_id = 1;

	INIT_LIST_HEAD(&_dsm->svm_ls);

	list_add_rcu(&_dsm->ls, &_rcm->dsm_ls);

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
