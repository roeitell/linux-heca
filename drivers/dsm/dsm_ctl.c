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


static rcm *_rcm;

static int open(struct inode *inode, struct file *f)
{

	return 0;
}

static int release(struct inode *inode, struct file *f)
{
	destroy_rcm(&_rcm);

	return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
	int r = 0;
	void __user *argp;
	connect_data conn_data;
	init_data i_data;

	argp = (void __user *)arg;

	switch (ioctl)
	{
		case RDMA_INIT:
		{
			r = -EFAULT;

			if (copy_from_user( (void *) &i_data, argp, sizeof i_data))
				goto out;

			r = create_rcm(&_rcm, &i_data);

			break;
		}
		case RDMA_LISTEN:
		{

			if (_rcm)
			{
				r = rdma_listen(_rcm->cm_id, 2);
			}
			else
			{
				r = -1;
			}

			break;
		}
		case RDMA_CONNECT:
		{

			r = -EFAULT;

			if (copy_from_user( (void *) &conn_data, argp, sizeof conn_data))
				goto out;


			if (_rcm)
			{
				r = create_connection(_rcm, &conn_data);
			}
			else
			{
				r = -1;
			}

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
	.name   = "dsm_rdma",
	.add    = dsm_iw_add_one,
	.remove = dsm_iw_remove_one
};

static int dsm_init(void)
{

	return misc_register(&rdma_misc);

}
module_init(dsm_init);

static void dsm_exit(void)
{

	misc_deregister(&rdma_misc);
}
module_exit(dsm_exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
