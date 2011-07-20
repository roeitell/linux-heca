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


static rcm *rdma_cm = NULL;

static void BIG_CLEANUP(fd_data *data)
{
	if(rdma_cm)
		destroy_rcm(rdma_cm);

	kfree(data);
}


static int open(struct inode *inode, struct file *f)
{
	//fd_data *fd_data = kmalloc(sizeof *fd_data, GFP_KERNEL);

	//f->private_data = fd_data;

	return 0;
}

static int release(struct inode *inode, struct file *f)
{
	//fd_data *fd_data = f->private_data;

	// Get the rdma_cm_id from the RB_TREE and pass it to function close_connection().
	//conn_element *ele = search_rb_conn(rcm->root_conn, fd_data->vm_id);

//	conn_element *ele = rb_entry(rdma_cm->root_conn.rb_node, conn_element, rb_node);
//	if(ele){
//		if (destroy_connection(ele))
//			printk("\n[close_connection] FAILED");
//	}
//	kfree(fd_data);

	// DSM1 - dont fuking leave this here!!
	//destroy_rcm(_rcm);

	return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
	int r;
	//fd_data *fd_data = f->private_data;
	void __user *argp;
	connect_data d;

	argp = (void __user *)arg;

	switch (ioctl)
	{
		case RDMA_INIT:
		{
//			r = -EFAULT;
//
//			if (copy_from_user( (void *) &d, argp, sizeof d))
//				goto out;
//
//			//create_rcm(&_rcm);
//			rdma_cm = kmalloc(sizeof(rcm), GFP_KERNEL);
//			if(!rdma_cm)
//			{
//				printk("\n> [ioctl] - failed allocating rdma_cm");
//				goto out;
//			}
//			memset(rdma_cm, 0, sizeof(rcm));
//
//			rdma_cm->root_conn = RB_ROOT;
//			rdma_cm->root_route = RB_ROOT;
//
//			//sema_init(&rdma_cm->sem, 0);
//
//			rdma_cm->cm_id = rdma_create_id(rcm_event_handler, rdma_cm, RDMA_PS_TCP, IB_QPT_RC);
//			if (IS_ERR(rdma_cm->cm_id))
//				goto out;
//
//			printk("\n> [ioctl] - starting the listener");
//			printk("\n> [ioctl] - &rcm : %p", rdma_cm);
//			printk("\n> [ioctl] - &d : %p", &d);
//			printk("\n> [ioctl] - starting the listener2");
//			r = start_listener(rdma_cm, &d);
//			printk("\n> [ioctl] - listener returns %d", r);
//
//
//			//BIG_CLEANUP(fd_data);

			break;
		}
		case RDMA_CONNECT:
		{
			r = -EFAULT;

			if (copy_from_user( (void *) &d, argp, sizeof d))
				goto out;

			//fd_data->vm_id = d.vm_id;

			printk("\n>[RDMA_CONNECT] start");

			r = create_connection(rdma_cm, &d);

			printk("\n>[RDMA_CONNECT] finish");

			break;
		}
		default:
		{
			r = -EFAULT;

			break;
		}
	}

out:
	kfree(rdma_cm);
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
//
static void dsm_iw_add_one(struct ib_device *device)
{
//	struct ib_device_attr *dev_attr;
//	rcm *rcm;
//
//	rcm = kmalloc(sizeof *rcm, GFP_KERNEL);
//	dev_attr = kmalloc(sizeof *dev_attr, GFP_KERNEL);
//
//	if (ib_query_device(device, dev_attr))
//	{
//		printk("\n[dsm_iw_add_one] - query_device failed");
//		goto free_attr;
//	}
//
//	rcm->dev = device;
//
//	rcm->pd = ib_alloc_pd(device);
//	if (IS_ERR(rcm->pd))
//		goto pd_err;
//
//	rcm->mr = ib_get_dma_mr(rcm->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
//	if (IS_ERR(rcm->mr))
//		goto mr_err;
//
//	ib_set_client_data(device, &dsm_iw_client, (void *) rcm);
//
//	goto free_attr;
//
//mr_err:
//	ib_dealloc_pd(rcm->pd);
//pd_err:
//	printk("\n>[dsm_iw_add_one] Failed.");
//free_attr:
//	kfree(dev_attr);

}

static void dsm_iw_remove_one(struct ib_device *device)
{
//	rcm *rcm;
//
//	rcm = (rcm *) ib_get_client_data(device, &dsm_iw_client);
//	if (!rcm)
//		return;
//
//	rds_iw_destroy_conns(rds_iwdev);
//
//	if (rds_iwdev->mr_pool)
//		rds_iw_destroy_mr_pool(rds_iwdev->mr_pool);
//
//	if (rds_iwdev->mr)
//		ib_dereg_mr(rds_iwdev->mr);
//
//	while (ib_dealloc_pd(rds_iwdev->pd)) {
//		rdsdebug("Failed to dealloc pd %p\n", rds_iwdev->pd);
//		msleep(1);
//	}
//
//	list_del(&rds_iwdev->list);
//	kfree(rds_iwdev);
}

struct ib_client dsm_iw_client = {
	.name   = "dsm_iw", // DSM1 -- SIW device name?
	.add    = dsm_iw_add_one,
	.remove = dsm_iw_remove_one
};

static int dsm_init(void)
{
	//create_rcm(_rcm);

	//ib_register_client(&dsm_iw_client);

	return misc_register(&rdma_misc);

}
module_init(dsm_init);

static void dsm_exit(void)
{
	//destroy_rcm(_rcm);

	misc_deregister(&rdma_misc);
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
