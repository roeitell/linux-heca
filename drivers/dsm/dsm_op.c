/*
 * dsm_op.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_op.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>

static struct ib_sge recv_sge;
static struct ib_recv_wr recv_wr;
static struct ib_recv_wr *recv_bad_wr;

static struct ib_sge send_sge;
static struct ib_send_wr send_wr;
static struct ib_send_wr *send_bad_wr;

void destroy_connections(rcm *rcm)
{
	conn_element *ele;
	int i = 0;

	// DSM3: Temporarily using i
	while ( (ele = search_rb_conn(&rcm->root_conn, i)) )
	{
		destroy_connection(&ele);

		++i;
	}

}

void exchange_info_clientside(conn_element *ele)
{
	// DSM1 : lol come back and sort this
	dsm_recv_info(ele);

	dsm_send_info(ele);
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
//	int i;
	int r = 0;
	//wait

	printk("\n [1]\n");

	r = dsm_recv_info(ele);

	printk("[2] \n");

	r = dsm_send_info(ele);
	//wait

//	for(i = 0; i < RX_BUF_ELEMENTS_NUM; ++i)
//	{
//		dsm_recv_msg(ele, i);
//	}
	printk("[3] \n");

	r = dsm_send_info(ele);

	printk("[4] \n");
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

int dsm_send_info(conn_element *ele)
{
	// DSM1 : msg_buf - msg_rx_buf request etc!

	send_sge.addr = (u64) ele->send_info;
	send_sge.length = sizeof(rdma_info);
	send_sge.lkey = ele->mr->lkey;

	send_wr.next	   = NULL;
	send_wr.wr_id	   = 1;
	send_wr.sg_list	   = &send_sge; // From tx_desc??
	send_wr.num_sge	   = 1;
	send_wr.opcode	   = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(ele->cm_id->qp, &send_wr, &send_bad_wr);
}

int dsm_recv_info(conn_element *ele)
{

	recv_sge.addr = (u64) ele->recv_info; //DSM1 - sge addr = dma mapped addr
	recv_sge.length = sizeof(rdma_info); // What should this be - dsm_message or rdma_info?
	recv_sge.lkey = ele->mr->lkey;

	recv_wr.next = NULL;
	recv_wr.wr_id = 2;	// DSM2: Some sort of unique id required for post_recv
	recv_wr.sg_list = &recv_sge;
	recv_wr.num_sge = 1;

	return ib_post_recv(ele->cm_id->qp, &recv_wr, &recv_bad_wr);

}

int create_rcm(rcm **rcm, init_data *i_data)
{
	int r;

	printk("\n{a}");

	*rcm = kmalloc(sizeof(struct rcm), GFP_KERNEL);

	(*rcm)->root_conn = RB_ROOT;
	(*rcm)->root_route = RB_ROOT;

	(*rcm)->sin.sin_family = AF_INET;
	(*rcm)->sin.sin_addr.s_addr = (__u32) inet_addr(i_data->ip);
	(*rcm)->sin.sin_port = (__u16) htons(i_data->port);

	printk("\n{b}");

	(*rcm)->cm_id = rdma_create_id(server_event_handler, *rcm, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR((*rcm)->cm_id))
		goto err_cm_id;

	printk("\n{c}");

	if ( (r = rdma_bind_addr((*rcm)->cm_id, (struct sockaddr *) &((*rcm)->sin) )) )
	{
		printk("\n{r = %d}", r);
		goto err_bind;
	}

	printk("\n R : %d\n", r);

	printk("\n{d}");

	(*rcm)->pd = ib_alloc_pd((*rcm)->cm_id->device);
	if (IS_ERR((*rcm)->pd))
		goto err_pd;

	printk("\n{e}");

	(*rcm)->listen_cq = ib_create_cq((*rcm)->cm_id->device, listener_cq_handle, NULL, (*rcm), 2, 0);
	if (IS_ERR((*rcm)->listen_cq))
		goto err_cq;

	printk("\n{f}");

	if (ib_req_notify_cq((*rcm)->listen_cq, IB_CQ_NEXT_COMP))
		goto err_notify;

	printk("\n{g}");

	(*rcm)->mr = ib_get_dma_mr((*rcm)->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR((*rcm)->mr))
		goto err_mr;

	printk("\n{h}");

	create_tx_buffer((*rcm));

	printk("\n{i}");

	printk("\n R : %d\n", r);

	return r;

err_mr:
err_notify:
	ib_destroy_cq((*rcm)->listen_cq);
err_cq:
	ib_dealloc_pd((*rcm)->pd);
err_pd:
err_bind:
	rdma_destroy_id((*rcm)->cm_id);
err_cm_id:
	printk("\n>[create_rcm] Failed.");

	return r;

}

void destroy_rcm(rcm **rcm)
{
	printk("\n(1)");

	if (*rcm)
	{
		printk("\n(2)");
		destroy_connections(*rcm);

		printk("\n(3)");

		destroy_tx_buffer((*rcm));


		if ((*rcm)->cm_id)
		{
			printk("\n(4)");

			if((*rcm)->cm_id->qp)
				ib_destroy_qp((*rcm)->cm_id->qp);

			printk("\n(5)");

			if((*rcm)->mr)
				(*rcm)->cm_id->device->dereg_mr((*rcm)->mr);

			printk("\n(6)");

			if((*rcm)->pd)
				ib_dealloc_pd((*rcm)->pd);

			printk("\n(7)");

			if((*rcm)->cm_id)
				rdma_destroy_id((*rcm)->cm_id);

		}

		printk("\n(8)");

		kfree(*rcm);
		*rcm = 0;

		printk("\n(9)\n\n");
	}

}

void create_tx_buffer(rcm *rcm)
{
	//DSM2 - sort this *
	rcm->tx_buf = kmalloc(sizeof(tx_buf_ele), GFP_KERNEL);
	rcm->tx_buf->mem = vmalloc(sizeof(dsm_message));

	rcm->tx_buf->dsm_msg = (dsm_message *) ib_dma_map_single(rcm->cm_id->device, rcm->tx_buf->mem, sizeof(dsm_message), DMA_TO_DEVICE);

	rcm->tx_buf->wrk_req = kmalloc(sizeof(msg_work_request), GFP_KERNEL);
	rcm->tx_buf->wrk_req->wr_ele = kmalloc(sizeof(work_request_ele), GFP_KERNEL);
	rcm->tx_buf->wrk_req->wr_ele->dsm_msg = rcm->tx_buf->dsm_msg;

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

int create_connection(rcm *rcm, connect_data *conn_data)
{
	int r;
	struct sockaddr_in dst;
	struct rdma_conn_param param;
	conn_element *ele;

	memset(&param, 0, sizeof(struct rdma_conn_param));
	param.responder_resources = 1;
	param.initiator_depth = 1;
	param.retry_count = 10;

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = (__u32) inet_addr(conn_data->ip);
	dst.sin_port = (__u16) htons(conn_data->port);

	ele = vmalloc(sizeof(conn_element));

	insert_rb_conn(&rcm->root_conn, ele);

	ele->cm_id = rdma_create_id(connection_event_handler, ele, RDMA_PS_TCP, IB_QPT_RC);

	r = rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &rcm->sin, (struct sockaddr*) &dst, 2000);

	return r;
}

void accept_connection(conn_element *ele)
{
	int r;
	struct rdma_conn_param conn_param;

	printk("\n* a *");

	sema_init(&
	ele->sem, 1);

	ele->send_mem = vmalloc(sizeof(rdma_info));

	ele->send_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device, ele->send_mem, sizeof(rdma_info), DMA_TO_DEVICE);
	memset(ele->send_info, 0, sizeof(rdma_info));

	printk("\n* b *");




	ele->recv_mem = vmalloc(sizeof(rdma_info));

	ele->recv_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device, ele->recv_mem, sizeof(rdma_info), DMA_FROM_DEVICE);

	memset(ele->recv_info, 0, sizeof(rdma_info));


	ele->pd = ib_alloc_pd(ele->cm_id->device);

	ele->mr = ib_get_dma_mr(ele->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);


	ele->send_info->node_id = htons(1);
	ele->send_info->buf_rx_addr = 0;
	ele->send_info->buf_msg_addr = htonll((u64) ele->recv_info);
	ele->send_info->rkey_msg = htonl(ele->mr->rkey);
	ele->send_info->rkey_rx = 0;


	printk("\n* c *");

	if ( (r = create_qp(ele)) )
		goto err1;



	printk("\n* d *");

	create_tx_buffer(ele->rcm);

	printk("\n* e *");

	create_rx_buffer(ele);

	printk("\n* f *");

	init_dsm_info(ele);

	printk("\n* g *");


	dsm_recv_info(ele);

	down_interruptible(&ele->sem);



	printk("\n* h *");

	memset(&conn_param, 0, sizeof(struct rdma_conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;

	printk("\n* i *");

	rdma_accept(ele->cm_id, &conn_param);

	printk("\n* j *");

	return;

err1:

	printk("\n>[accept_connection] - failed creating connection element");
	printk("\n---flush---\n");

	return;

}

void destroy_connection(conn_element **ele)
{
	if(*ele)
	{
		if((*ele)->cm_id)
		{
			rdma_disconnect((*ele)->cm_id);

			if((*ele)->cm_id->qp)
				ib_destroy_qp((*ele)->cm_id->qp);

			if((*ele)->mr)
				(*ele)->cm_id->device->dereg_mr((*ele)->mr);

			if((*ele)->pd)
				ib_dealloc_pd((*ele)->pd);

			rdma_destroy_id((*ele)->cm_id);
		}

		if((*ele)->send_cq)
			ib_destroy_cq((*ele)->send_cq);
		if((*ele)->recv_cq)
			ib_destroy_cq((*ele)->recv_cq);

		destroy_rx_buffer((*ele));

		if ((*ele)->send_info)
			kfree((*ele)->send_info);

		if ((*ele)->recv_info)
			kfree((*ele)->recv_info);

		kfree(*ele);
		*ele = 0;
	}

}

int create_qp(conn_element *ele)
{
	struct ib_qp_init_attr attr;
	struct rdma_cm_id *id = ele->cm_id;
	int r = 0;



	ele->send_cq = ib_create_cq(ele->cm_id->device, send_cq_handle, NULL, (void *) ele, 2, 0);
	if (IS_ERR(ele->send_cq))
	{
		r = -1;
		goto err;
	}

	ele->recv_cq = ib_create_cq(ele->cm_id->device, recv_cq_handle, NULL, (void *) ele, 2, 0);
	if (IS_ERR(ele->recv_cq))
	{
		r = -1;
		goto err;
	}

	if(ib_req_notify_cq(ele->recv_cq, IB_CQ_SOLICITED))
	{
		r = -1;
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
	attr.qp_context = (void *) ele;// DSM1 : return to orig.

	r = rdma_create_qp(id, ele->pd, &attr);

	return r;

err:
	printk("\n ERROR SHIT\n\n");

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
