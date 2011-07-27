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

#include <linux/stat.h>

static rcm *_rcm;
static char *ip = 0;
static int port =0;

static int open(struct inode *inode, struct file *f)
{
	vm_data *data = kmalloc(sizeof(vm_data), GFP_KERNEL);

	printk("\n[open]");

	f->private_data = (void *) data;

	return 0;

}

static int release(struct inode *inode, struct file *f)
{
	vm_data *data = (vm_data *) f->private_data;

	printk("\n[release]\n");

	// DSM1: FIND AND DESTROY conn_ele?

	kfree(data);

	return 0;

}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
	int r = 0;
	vm_data *data = (vm_data *) f->private_data;
	void __user *argp = (void __user *)arg;
	connect_data c_data;
	r_data r_data;

	route_element *rele;
	dsm_vm_id id;
	conn_element *cele;
	int ip_addr;

	switch (ioctl)
	{
		case RDMA_REG_VM:
		{
			r = -EFAULT;

			if (copy_from_user( (void *) &r_data, argp, sizeof r_data))
				goto out;

			id.dsm_id = r_data.dsm_id;
			id.vm_id = r_data.vm_id;

			rele = search_rb_route(_rcm, &id);

			ip_addr = inet_addr("127.0.0.1");

			if (!rele)
			{
				rele = kmalloc(sizeof(route_element), GFP_KERNEL);

				rele->ele = search_rb_conn(_rcm, ip_addr);
				rele->id.dsm_id = id.dsm_id;
				rele->id.vm_id = id.vm_id;
				rele->mm = current->mm;
				rele->type = local;

				insert_rb_route(_rcm, rele);

				r = 0;

			}
			else
				r = -1;

			break;

		}
		case RDMA_CONNECT:
		{
			r = -EFAULT;

			if (copy_from_user( (void *) &c_data, argp, sizeof c_data))
				goto out;

			if (_rcm)
			{
				id.dsm_id = c_data.dsm_id;
				id.vm_id = c_data.vm_id;

				ip_addr = inet_addr(c_data.ip);

				// Check for connection
				cele = search_rb_conn(_rcm, ip_addr);

				if (!cele)
				{
					r = create_connection(_rcm, &c_data);
					if (r)
						goto out;

				}

				rele = search_rb_route(_rcm, &id);

				if (!rele)
				{
					rele = kmalloc(sizeof(route_element), GFP_KERNEL);

					rele->ele = search_rb_conn(_rcm, ip_addr);
					rele->id.dsm_id = id.dsm_id;
					rele->id.vm_id = id.vm_id;
					rele->mm = current->mm;
					rele->type = remote;

					insert_rb_route(_rcm, rele);

				}
				else
					r = -EEXIST;

			}
			else
				r = -1;

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
{
	.owner          = THIS_MODULE,
	.release        = release,
	.unlocked_ioctl = ioctl,
	.open           = open,
	.llseek			= noop_llseek,

};

static struct miscdevice rdma_misc =
{
	MISC_DYNAMIC_MINOR,
	"rdma",
	&rdma_fops,

};

module_param(ip, charp, S_IRUGO|S_IWUSR);
module_param(port, int, S_IRUGO|S_IWUSR);

MODULE_PARM_DESC(ip, "[ip] of the machine - will be used at node_id");
MODULE_PARM_DESC(port, "[port] of DSM_RDMA");

static int dsm_init(void)
{
	printk("\n>ip : %s", ip);
	printk("\n>port : %d", port);

	if (create_rcm(&_rcm, ip, port))
		goto err;

	rdma_listen(_rcm->cm_id, 2);
//DSM2: really need better cleanup here - incase of failure
err:
	return misc_register(&rdma_misc);

}
module_init(dsm_init);

static void dsm_exit(void)
{
	destroy_rcm(&_rcm);

	misc_deregister(&rdma_misc);
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
