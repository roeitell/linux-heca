/*
 * dsm_op.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_op.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>

//working dsm1
int start_listener(rcm *rcm, connect_data *d)
{
	int r;

	rcm->sin.sin_family = AF_INET;
//	rcm->sin.sin_addr.s_addr = (__u32) inet_addr(d->src_ip);
//	rcm->sin.sin_port = (__u16) htons(d->src_port);
	rcm->sin.sin_addr.s_addr = (__u32) inet_addr("10.55.168.66");
	rcm->sin.sin_port = (__u16) htons(1025);

	if ( (r = rdma_bind_addr(rcm->cm_id, (struct sockaddr *) &rcm->sin)) )
		goto bind_err;

	if (!!rcm->cm_id->device)
	{
		printk("We has device");
	}
		printk("we has no device");

	rcm->pd = ib_alloc_pd(rcm->cm_id->device);
	if (IS_ERR(rcm->pd))
		goto pd_err;

	printk("\n>[start_listener] - Alloc pd successful");

	rcm->listen_cq = ib_create_cq(rcm->cm_id->device, listener_cq_handle, NULL, rcm, 2, 0);
	if (IS_ERR(rcm->listen_cq))
		goto cq_err;

	if (ib_req_notify_cq(rcm->listen_cq, IB_CQ_NEXT_COMP))
		goto notif_err;

	rcm->mr = ib_get_dma_mr(rcm->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(rcm->mr))
		goto map_err;

// DSM3 - BACKLOG! - do we need to set higher?
	if ( (r = rdma_listen(rcm->cm_id, 2)) )
		goto list_err;

	printk("\n---flush---");

	return r;

list_err:
	printk("\n>[start_listener] - rdma_listen returns %d", r);
map_err:
	printk("\n>[start_listener] - mapping failed");
notif_err:
	printk("\n>[start_listener] - cq notification failed");
cq_err:
	printk("\n>[start_listener] - cq creation failed");
	ib_dealloc_pd(rcm->pd);
pd_err:
	printk("\n>[start_listener] - ib_alloc_pd err");
bind_err:
	printk("\n>[start_listener] - rdma_bind_addr returns %d", r);

	return r;
}

void exchange_info_clientside(conn_element *ele)
{
	int i;
	int r;
	// DSM1 : lol come back and sort this
	r = dsm_recv_info(ele);

	r = dsm_send_info(ele);
	//wait
//	for(i = 0; i < RX_BUF_ELEMENTS_NUM; ++i)
//	{
//		dsm_recv_msg(ele, i);
//	}
//	r = dsm_send_info(ele);
	//wait

}

void exchange_info_serverside(conn_element *ele)
{
	int i;
	int r = 0;
	//wait
	r = dsm_send_info(ele);
	//wait

	for(i = 0; i < RX_BUF_ELEMENTS_NUM; ++i)
	{
		dsm_recv_msg(ele, i);
	}
	r = dsm_send_info(ele);
}

int dsm_send_msg(conn_element *ele, int i)
{
	struct ib_send_wr wr = ele->rcm->tx_buf->wrk_req->wr_ele->wr;
	struct ib_sge *sge = &ele->rcm->tx_buf->wrk_req->wr_ele->sg;

	sge->addr = (u64) ele->rcm->tx_buf[i].dsm_msg;
	sge->length = sizeof(dsm_message);
	sge->lkey = ele->rcm->mr->lkey;

	wr.next = NULL;
	wr.wr_id = (u64) &ele->rcm->tx_buf[i];
	wr.sg_list = sge;
	wr.num_sge = 1;
	wr.opcode	   = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(ele->cm_id->qp, &wr,  &ele->rcm->tx_buf->wrk_req->wr_ele->bad_wr);
}

int dsm_recv_msg(conn_element *ele, int i)
{
	struct ib_recv_wr wr = ele->rx_buf[i].reply_work_req->recv_wrk_rq_ele->sq_wr;
	struct ib_sge sge;

	sge.addr = (u64) ele->rx_buf[i].dsm_msg;
	sge.length = sizeof(dsm_message);
	sge.lkey = ele->rcm->mr->lkey;

	wr.next = NULL;
	wr.wr_id = (u64) &ele->rx_buf[i];
	wr.sg_list = &sge;
	wr.num_sge = 1;

	return ib_post_recv(ele->cm_id->qp, &wr,  &ele->rx_buf[i].reply_work_req->recv_wrk_rq_ele->bad_wr);
}

int init_dsm_info(conn_element *ele)
{
	ele->send_info->buf_msg_addr = (u64) ele->rcm->tx_buf;
	ele->send_info->buf_rx_addr = (u64) ele->rx_buf;

	ele->send_info->rkey_msg = ele->rcm->mr->rkey;
	ele->send_info->rkey_rx = ele->rcm->mr->rkey;

	ele->send_info->node_id = ele->rcm->node_id;
	ele->send_info->rx_buf_size = TX_BUF_ELEMENTS_NUM;

	return 0;
}

// DSM1 - store this in workrequest - pre fill idea.
int dsm_send_info(conn_element *ele)
{
	// DSM1 : msg_buf - msg_rx_buf request etc!
	static struct ib_sge sge;
	static struct ib_send_wr wr;
	static struct ib_send_wr *bad_wr;

	sge.addr = (u64) ele->send_info;
	sge.length = sizeof(rdma_info);
	sge.lkey = ele->mr->lkey;

	wr.next	   = NULL;
	wr.wr_id	   = 1;
	wr.sg_list	   = &sge; // From tx_desc??
	wr.num_sge	   = 1;
	wr.opcode	   = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(ele->cm_id->qp, &wr, &bad_wr);
}

// DSM1: dsm_post_recv - what do we recieve?
int dsm_recv_info(conn_element *ele)
{
	// DSM1 : msg_buf - msg_rx_buf request etc!
	static struct ib_sge sge;
	static struct ib_recv_wr wr;
	static struct ib_recv_wr *bad_wr;

	sge.addr = (u64) ele->recv_info; //DSM1 - sge addr = dma mapped addr
	sge.length = sizeof(rdma_info); // What should this be - dsm_message or rdma_info?
	sge.lkey = ele->mr->lkey;

	wr.next = NULL;
	wr.wr_id = 2;	// DSM2: Some sort of unique id required for post_recv
	wr.sg_list = &sge;
	wr.num_sge = 1;

	// DSM3 : post_recv ref count?

	return ib_post_recv(ele->cm_id->qp, &wr, &bad_wr);

}

int create_rcm(rcm **rcm)
{
//	*rcm = kmalloc(sizeof(rcm), GFP_KERNEL);
//
//	rcm->root_conn = RB_ROOT;
//	rcm->root_route = RB_ROOT;
//
//	rcm->cm_id = rdma_create_id(rcm_event_handler, rcm, RDMA_PS_TCP, IB_QPT_RC);
//	if (IS_ERR(*rcm->cm_id))
//		goto cm_id_err;


//	rcm->pd = ib_alloc_pd(rcm->cm_id->device);
//	if (IS_ERR(rcm->pd))
//		goto pd_err;
//
//	rcm->listen_cq = ib_create_cq(rcm->cm_id->device, listener_cq_handle, NULL, rcm, 2, 0);
//	if (IS_ERR(rcm->listen_cq))
//		goto cq_err;
//
//	if (ib_req_notify_cq(rcm->listen_cq, IB_CQ_NEXT_COMP))
//		goto cq_arm_err;
//
//	rcm->mr = ib_get_dma_mr(rcm->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
//	if (IS_ERR(rcm->mr))
//		goto mr_err;
//
//	// dev handler
//
//	create_tx_buffer(rcm);

	return 0;

//handler_err: DSM1 - device handler?
//	ib_dereg_mr(rcm->mr);
//mr_err:
//cq_arm_err:
//	ib_destroy_cq(rcm->listen_cq);
//cq_err:
//	ib_dealloc_pd(rcm->pd);
//pd_err:
//	rdma_destroy_id(rcm->cm_id);
//cm_id_err:
//	printk("\n>[create_rcm] Failed.");

	return -1;
}

void destroy_rcm(rcm *rcm)
{

	destroy_connection( search_rb_conn(&rcm->root_conn, 7) );

	if(rcm->cm_id->qp)
		ib_destroy_qp(rcm->cm_id->qp);

	if(rcm->listen_cq)
		ib_destroy_cq(rcm->listen_cq);

	destroy_tx_buffer(rcm);

	if(rcm->mr)
		rcm->cm_id->device->dereg_mr(rcm->mr);

	if(rcm->pd)
		ib_dealloc_pd(rcm->pd);

	if(rcm->cm_id)
	rdma_destroy_id(rcm->cm_id);

	kfree(rcm);
}

int create_tx_buffer(rcm *rcm)
{
	//DSM2 - sort this *
	rcm->tx_buf = kmalloc(sizeof(tx_buf_ele), GFP_KERNEL);
	rcm->tx_buf->mem = vmalloc(sizeof(dsm_message));

	rcm->tx_buf->dsm_msg = (dsm_message *) ib_dma_map_single(rcm->cm_id->device, rcm->tx_buf->mem, sizeof(dsm_message), DMA_TO_DEVICE);

	rcm->tx_buf->wrk_req = kmalloc(sizeof(msg_work_request), GFP_KERNEL);
	rcm->tx_buf->wrk_req->wr_ele = kmalloc(sizeof(work_request_ele), GFP_KERNEL);
	rcm->tx_buf->wrk_req->wr_ele->dsm_msg = rcm->tx_buf->dsm_msg;

	return 0;
}

void destroy_tx_buffer(rcm *rcm)
{
	if(rcm->tx_buf)
	{
		ib_dma_unmap_single(rcm->cm_id->device, (u64) rcm->tx_buf->dsm_msg, sizeof(dsm_message), DMA_TO_DEVICE);

		vfree(rcm->tx_buf->mem);

		kfree(rcm->tx_buf->wrk_req->wr_ele);
		kfree(rcm->tx_buf->wrk_req);

		kfree(rcm->tx_buf);
	}
}

int create_rx_buffer(conn_element *ele)
{
	ele->rx_buf = kmalloc(sizeof(rx_buf_ele), GFP_KERNEL);
	ele->rx_buf->mem = vmalloc(sizeof(dsm_message));
	ele->rx_buf->dsm_msg = (dsm_message *) ib_dma_map_single(ele->cm_id->device, ele->rx_buf->mem, sizeof(dsm_message),DMA_FROM_DEVICE);

	ele->rx_buf->reply_work_req = kmalloc(sizeof(reply_work_request), GFP_KERNEL);
	ele->rx_buf->reply_work_req->wr_ele = kmalloc(sizeof(work_request_ele), GFP_KERNEL);
	ele->rx_buf->reply_work_req->recv_wrk_rq_ele = kmalloc(sizeof(recv_work_req_ele), GFP_KERNEL);

	return 0;
}

void destroy_rx_buffer(conn_element *ele)
{

	if(ele->rx_buf)
	{
		ib_dma_unmap_single(ele->cm_id->device, (u64) ele->rx_buf->dsm_msg, sizeof(dsm_message), DMA_FROM_DEVICE);

		vfree(ele->rx_buf->mem);

		kfree(ele->rx_buf->reply_work_req->recv_wrk_rq_ele);
		kfree(ele->rx_buf->reply_work_req->wr_ele);
		kfree(ele->rx_buf->reply_work_req);

		kfree(ele->rx_buf);
	}
}

int create_connection(rcm *rcm, connect_data *d)
{
	int r;
	struct sockaddr_in dst, src;
	struct ib_device_attr dev_attr;
	struct rdma_conn_param param;
	conn_element *ele = NULL;

	memset(&param, 0, sizeof(struct rdma_conn_param));

	param.responder_resources = 1;
	param.initiator_depth = 1;
	param.retry_count = 10;

	// DSM1 : TEST STUFF - remove cause wil be set in listener!!!
	src.sin_family = AF_INET;
	src.sin_addr.s_addr = (__u32) inet_addr(d->src_ip);
	src.sin_port = (__u16) htons(d->src_port);
	// - Test STUFF -

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = (__u32) inet_addr(d->dst_ip);
	dst.sin_port = (__u16) htons(d->dst_port);

	ele = vmalloc(sizeof(conn_element));

	//insert_rb_conn(&rcm->root_conn, ele);

	//ele->rcm = rcm;
	ele->cm_id = rdma_create_id(connection_event_handler, ele, RDMA_PS_TCP, IB_QPT_RC);

	r = rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &src, (struct sockaddr*) &dst, 2000);

	return r;
}

conn_element *accept_connection(rcm* rcm, struct rdma_cm_id *id)
{
	int r;
	struct rdma_conn_param conn_param;
//	struct ib_device_attr dev_attr;
	conn_element *ele = kmalloc(sizeof(conn_element), GFP_KERNEL);
	if(!ele)
		goto err1;

	//ele->send_info = kmalloc(sizeof(rdma_info), GFP_KERNEL);

	//ele->send_info->node_id = 7;

	//insert_rb_conn(&rcm->root_conn, ele);

	printk("\n* a *");

	memset(ele, 0, sizeof(conn_element));
	memset(&conn_param, 0, sizeof(struct rdma_conn_param));

	ele->rcm = rcm;
	ele->cm_id = id;
	id->context = (void *) ele;

	printk("\n* b *");

	// DSM3: - do we need a new port??! -- is this done in rdma_accept?!
//	r = rdma_bind_addr(ele->cm_id, (struct sockaddr *) &rcm->sin);

	printk("\n* c *");

	//r = ib_query_device(ele->cm_id->device, &dev_attr);

	if ( (r = create_qp(ele)) )
	{
		printk("\n>[accept_connection] create_qp returns: %d", r);
		goto err1;
	}


	printk("\n* d *");

	//create_tx_buffer(rcm);

	printk("\n* e *");

	//create_rx_buffer(ele);

	printk("\n* f *");

	//init_dsm_info(ele);

	printk("\n* g *");

	//dsm_recv_info(ele);

	printk("\n* h *");

	//conn_param.responder_resources = 1;
	//conn_param.initiator_depth = 1;

	//rdma_accept(ele->cm_id, &conn_param);

	printk("\n* i *");

	//insert_rb_conn(&rcm->root_conn, ele);

	printk("\n* j *");

	return ele;

err1:

	printk("\n>[accept_connection] - failed creating connection element");
	printk("\n---flush---\n");

	return NULL;

}

int destroy_connection(conn_element *ele)
{
	if(ele)
	{
		if(ele->cm_id)
		{
			rdma_disconnect(ele->cm_id);

			if(ele->cm_id->qp)
				ib_destroy_qp(ele->cm_id->qp);

			rdma_destroy_id(ele->cm_id);
		}

		if(ele->send_cq)
			ib_destroy_cq(ele->send_cq);
		if(ele->recv_cq)
			ib_destroy_cq(ele->recv_cq);

		destroy_rx_buffer(ele);

		kfree(ele->send_info);
		kfree(ele);
	}
	return 0;
}

struct rdma_id_private {
	struct rdma_cm_id	id;

	struct rdma_bind_list	*bind_list;
	struct hlist_node	node;
	struct list_head	list; /* listen_any_list or cma_device.list */
	struct list_head	listen_list; /* per device listens */
	struct cma_device	*cma_dev;
	struct list_head	mc_list;

	int			internal_id;
	enum rdma_cm_state	state;
	spinlock_t		lock;
	struct mutex		qp_mutex;

	struct completion	comp;
	atomic_t		refcount;
	struct mutex		handler_mutex;

	int			backlog;
	int			timeout_ms;
	struct ib_sa_query	*query;
	int			query_id;
	union {
		struct ib_cm_id	*ib;
		struct iw_cm_id	*iw;
	} cm_id;

	u32			seq_num;
	u32			qkey;
	u32			qp_num;
	pid_t			owner;
	u8			srq;
	u8			tos;
	u8			reuseaddr;
};

int create_qp(conn_element *ele)
{
	struct ib_qp_init_attr attr;
	struct rdma_cm_id *id = ele->cm_id;
	int r = 0;
	struct rdma_id_private *id_priv;
	struct ib_qp *qp;
	int ret;

	printk("\n * z * ");

	ele->send_cq = ib_create_cq(ele->cm_id->device, send_cq_handle, NULL, (void *) ele->rcm, 2, 0);
	if (IS_ERR(ele->send_cq))
	{
		printk("\n>[] - send_cq creation failed");
		r = -1;
		goto err;
	}

	// DSM2 - notify_cq(send_cq)

	ele->recv_cq = ib_create_cq(ele->cm_id->device, recv_cq_handle, NULL, (void *) ele->rcm, 2, 0);
	if (IS_ERR(ele->recv_cq))
	{
		printk("\n>[] - recv_cq creation failed");
		r = -1;
		goto err;
	}
	if(ib_req_notify_cq(ele->recv_cq, IB_CQ_SOLICITED))
	{
		r = -1;
		printk("notify failed");
		goto err;
	}

	memset(&attr, 0, sizeof attr);

	attr.send_cq = ele->send_cq;
	attr.recv_cq = ele->recv_cq;
	attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	attr.cap.max_send_wr = 2;
	attr.cap.max_recv_wr = 2;
	attr.cap.max_send_sge = 1;
	attr.cap.max_recv_sge = 1;
	attr.qp_type = IB_QPT_RC;
	attr.port_num = ele->cm_id->port_num;
	attr.qp_context = (void *) ele->rcm;// DSM1 : return to orig.

	printk("\n *  y * ");

	r = rdma_create_qp(id, ele->rcm->pd, &attr);
//
//	id_priv = container_of(id, struct rdma_id_private, id);
//	if (id->device != ele->rcm->pd->device)
//		return -EINVAL;
//
//	qp = ib_create_qp(ele->rcm->pd, &attr);
//	if (IS_ERR(qp))
//		return PTR_ERR(qp);

//	if (id->qp_type == IB_QPT_UD)
//		ret = cma_init_ud_qp(id_priv, qp);
//	else
//		ret = cma_init_conn_qp(id_priv, qp);
//	if (ret)
//		goto err;

//	id->qp = qp;
//	id_priv->qp_num = qp->qp_num;
//	id_priv->srq = (qp->srq != NULL);

	printk("\n * x*\n\n");

	//return 0;
//err:

	//return ret;

	printk("\n Rdma create qp returns : %d ", r);
	return r;

err:
printk("\n ERROR SHIT\n\n");
ib_destroy_qp(qp);
	return r;

}

unsigned int inet_addr(char *addr)
{
	int a,b,c,d;
	char arr[4];

	sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d);

	arr[0] = a;
	arr[1] = b;
	arr[2] = c;
	arr[3] = d;

	return *(unsigned int*)arr;
}
