/*
 * rdma.c
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
#include <dsm/dsm_rdma.h>
#include <linux/socket.h>

#include <rdma/rdma_cm.h>
#include <linux/kernel.h>

int dummy(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	return 0;
}

static int run_rdma(__u32 addr)
{
	int r = 0;
	//rdma_cm_event_handler event_hnd = dummy;
	void* param = NULL;
	struct sockaddr_in sock;
	struct rdma_cm_id *cm;
	struct rdma_conn_param conn_param = {
			0,
			0,
			1,
			1,
			0,
			10,
			0,
			0,
			0,
	};
	//P)!ecom
	//conn_param.responder_resources = 1;
	//conn_param.initiator_depth = 1;
	//conn_param.retry_count = 10;

//	sock.sa_family = AF_INET;
//	sock.sa_data = "10.55.168.54";
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = addr;
	//sock.sin_port = htons(1026);

	cm = rdma_create_id(dummy, param, RDMA_PS_TCP);

	r = rdma_resolve_addr(cm, NULL, (struct sockaddr*) &sock, 2000);

	printk("\n>[rdma_resolve_addr] returns : %d", r);

	r = rdma_connect(cm, &conn_param);

	printk("\n>[rdma_connect] returns : %d", r);

	return 0;
}

static int open(struct inode *inode, struct file *f)
{

	return 0;
}

static int release(struct inode *inode, struct file *f)
{
	return 0;
}

static long ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
	int r;
	//dsm_data *data = f->private_data;
	void __user *argp;

	argp = (void __user *)arg;

	switch (ioctl)
	{
		case RDMA_CONNECT:
		{
			unsigned long addr;

			r = -EFAULT;

			if (copy_from_user(&addr, argp, sizeof addr))
				goto out;

			r = run_rdma((__u32) addr);

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

static int init(void)
{
	return misc_register(&rdma_misc);
}
module_init(init);

static void exit(void)
{
	misc_deregister(&rdma_misc);
}
module_exit(exit);

MODULE_VERSION("0.0.1");
MODULE_AUTHOR("virtex");
MODULE_DESCRIPTION("");
