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

struct subvirtual_machine *find_svm(struct dsm_vm_id *id)
{
	//return search_rb_route(_rcm, id);
	struct dsm *_dsm;
	struct subvirtual_machine *svm;

	list_for_each_entry_rcu(_dsm, &_rcm->dsm_ls, ls)
	{
		if (_dsm->dsm_id == id->dsm_id)
			list_for_each_entry_rcu(svm, &_dsm->svm_ls, ls)
			{
				if (svm->id.svm_id == id->svm_id)
					return svm;

			}
	}

	return NULL;

}

/*
 * Find and return SVM with pointer to process file desc private_data. *
 */
struct subvirtual_machine *find_local_svm(u16 dsm_id,
		struct mm_struct * mm)
{
	struct subvirtual_machine *local_svm;
	struct dsm *_dsm;

	list_for_each_entry_rcu(_dsm, &_rcm->dsm_ls, ls)
	{
		if (_dsm->dsm_id == dsm_id)
		{
			list_for_each_entry_rcu(local_svm, &_dsm->svm_ls, ls)
			{
				if (local_svm->priv)
					if (local_svm->priv->mm == mm)
						return local_svm;

			}

		}

	}

	return NULL;
}

// DSM2 - when is find_mr likely to be used?
struct mem_region *find_mr(unsigned long addr, struct dsm_vm_id *id)
{
	struct dsm *_dsm;
	struct subvirtual_machine *svm;
	struct mem_region *mr;

	list_for_each_entry_rcu(_dsm, &_rcm->dsm_ls, ls)
	{
		if (_dsm->dsm_id == id->dsm_id)
			list_for_each_entry_rcu(svm, &_dsm->svm_ls, ls)
			{
				if (svm->id.svm_id == id->svm_id)
					list_for_each_entry_rcu(mr, &svm->mr_ls, ls)
					{
						if (addr >= mr->addr && addr <= (mr->addr + mr->sz))
							return mr;

					}

			}

	}

	return NULL;

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
	INIT_LIST_HEAD(&data->head);

	f->private_data = (void *) data;

	write_unlock(&_rcm->conn_lock);

	return 0;

}

static void free_svm(struct rcu_head *head)
{
	kfree(container_of(head, struct subvirtual_machine, rcu_head));

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
	struct subvirtual_machine *svm = NULL;
	struct mem_region *mr = NULL;
	struct dsm *_dsm = NULL;
	u16 dsm_id;

	if (!data->svm)
		return 1;

	write_lock(&_rcm->conn_lock);

	dsm_id = data->svm->id.dsm_id;

	list_for_each_entry_rcu(_dsm, &_rcm->dsm_ls, ls)
	{
		if (_dsm->dsm_id == dsm_id)
		{
			list_for_each_entry_rcu(svm, &_dsm->svm_ls, ls)
			{
				if (svm == data->svm)
				{
					printk("[release] SVM: dsm_id=%u ... vm_id=%u\n", svm->id.dsm_id, svm->id.svm_id);

					list_for_each_entry_rcu(mr, &svm->mr_ls, ls)
					{
						list_del_rcu(&mr->ls);
						call_rcu(&mr->rcu, free_mem_region);

					}

					data->svm->priv = NULL;
					list_del_rcu(&svm->ls);
					call_rcu(&svm->rcu_head, free_svm);

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
	struct subvirtual_machine *rele;
	struct conn_element *cele;
	int ip_addr;
	struct dsm_message msg;
	struct page *page;

	struct unmap_data udata;



	private_data *priv_data = (private_data *) f->private_data;
	void __user *argp = (void __user *) arg;
	struct svm_data svm_info;
	struct subvirtual_machine *svm = NULL;
	struct mem_region *mr = NULL;
	struct dsm *_dsm = NULL;
	struct dsm_vm_id id;


	switch (ioctl)
	{
		case DSM_SVM:
		{
			//printk("[DSM_SVM]\n");

			r = -EFAULT;

			if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
				goto out;

			write_lock(&_rcm->route_lock);

			id.dsm_id = svm_info.dsm_id;
			id.svm_id = svm_info.vm_id;

			svm = find_svm(&id);

			printk("[DSM_SVM]\n\tfound svm : %d\n\tdsm_id : %u\n\tsvm_id : %u\n", !!svm, svm_info.dsm_id, svm_info.vm_id);

			if (!svm)
			{
				svm = kmalloc(sizeof(*svm), GFP_KERNEL);
				if (!svm)
					goto fail1;

				priv_data->svm = svm;
				priv_data->offset = svm_info.offset;

				svm->id.dsm_id = svm_info.dsm_id;
				svm->id.svm_id = svm_info.vm_id;
				svm->priv = priv_data;

				_dsm = list_first_entry(&_rcm->dsm_ls, struct dsm, ls);

				list_add_rcu(&svm->ls, &_dsm->svm_ls);

				INIT_LIST_HEAD(&svm->mr_ls);

				mr = kmalloc(sizeof(*mr), GFP_KERNEL);
				if (!mr)
					goto fail1;

				mr->addr = svm_info.start_addr;
				mr->sz = svm_info.size;
				mr->svm = svm;

				list_add_rcu(&mr->ls, &svm->mr_ls);

			}
			else
			{
				priv_data->svm = svm;
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
			//printk("[DSM_CONNECT]\n");

			r = -EFAULT;

			if (copy_from_user((void *) &svm_info, argp, sizeof svm_info))
				goto out;

			write_lock(&_rcm->route_lock);

			id.dsm_id = svm_info.dsm_id;
			id.svm_id = svm_info.vm_id;

			svm = find_svm(&id);

			printk("[DSM_CONNECT]\n\tfound svm : %d\n\tdsm_id : %u\n\tsvm_id : %u\n", !!svm, svm_info.dsm_id, svm_info.vm_id);

			if (!svm)
			{
				svm = kmalloc(sizeof(*svm), GFP_KERNEL);
				if (!svm)
					goto fail2;

				svm->id.dsm_id = svm_info.dsm_id;
				svm->id.svm_id = svm_info.vm_id;
				svm->priv = NULL;

				_dsm = list_first_entry(&_rcm->dsm_ls, struct dsm, ls);

				list_add_rcu(&svm->ls, &_dsm->svm_ls);

				INIT_LIST_HEAD(&svm->mr_ls);

				mr = kmalloc(sizeof(*mr), GFP_KERNEL);
				if (!mr)
					goto fail2;

				mr->addr = svm_info.start_addr;
				mr->sz = svm_info.size;
				mr->svm = svm;

				list_add_rcu(&mr->ls, &svm->mr_ls);

			}

			r = 0;

fail2:
			write_unlock(&_rcm->route_lock);

			break;

		}
		case DSM_UNMAP_RANGE:
		{
			//printk("[DSM_UNMAP_RANGE]\n");

			r = -EFAULT;

			if (copy_from_user((void *) &udata, argp, sizeof udata))
				goto out;

			// DSM2: why are locks outside of function?
			read_lock(&_rcm->conn_lock);
			svm = find_svm(&udata.id);
			read_unlock(&_rcm->conn_lock);

			r = -1;

			printk("[DSM_UNMAP_RANGE]\n\tsvm : %d\n\tdsm_id : %d\n\tsvm_id : %d\n", !!svm, svm->id.dsm_id, svm->id.svm_id);

			if (!svm)
				goto out;

			if (priv_data->svm->id.dsm_id != svm->id.dsm_id)
				goto out;

			unsigned long i = udata.addr;
			unsigned long end = i + udata.sz;

			while (i < end)
			{
				r = dsm_flag_page_remote(current->mm, udata.id, i);

				if (r)
					break;

				i += PAGE_SIZE;

			}

			r = 0;

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
				id.svm_id = c_data.vm_id;

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
					rele->id.svm_id = id.svm_id;
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
			svm = find_svm(&udata.id);
			read_unlock(&_rcm->conn_lock);
			if (!svm)
			{
				printk("[UNMAP_PAGE] could not find the route element \n");
				r = -1;
				printk("[unmap page 1] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
						udata.id.svm_id);
				goto out;

			}

			printk("[unmap page 2] dsm_id : %d - vm_id : %d\n", udata.id.dsm_id,
					udata.id.svm_id);

			if (priv_data->svm->id.dsm_id != svm->id.dsm_id)
			{
				printk("[UNMAP_PAGE] DSM id not same, bad id  \n");
				r = -1;
			}

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
	reg_dsm_functions(&find_svm, &find_local_svm,
			&erase_rb_swap, &insert_rb_swap, &search_rb_swap);

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
