/*
 * dsm_op.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_op.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>
#include <dsm/dsm_sr.h>


int create_rcm(rcm **rcm, char *ip, int port)
{
	int r = 0;

	*rcm = kmalloc(sizeof(struct rcm), GFP_KERNEL);

	(*rcm)->node_ip = inet_addr(ip);

	(*rcm)->root_conn = RB_ROOT;
	(*rcm)->root_route = RB_ROOT;

	rwlock_init(&(*rcm)->conn_lock);
	rwlock_init(&(*rcm)->route_lock);

	(*rcm)->sin.sin_family = AF_INET;
	(*rcm)->sin.sin_addr.s_addr = (__u32) (*rcm)->node_ip;
	(*rcm)->sin.sin_port = (__u16) htons(port);

	(*rcm)->cm_id = rdma_create_id(server_event_handler, *rcm, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR((*rcm)->cm_id))
		goto err_cm_id;

	if ( (r = rdma_bind_addr((*rcm)->cm_id, (struct sockaddr *) &((*rcm)->sin) )) )
	{
		printk("\n{r = %d}", r);
		goto err_bind;
	}

	(*rcm)->pd = ib_alloc_pd((*rcm)->cm_id->device);
	if (IS_ERR((*rcm)->pd))
		goto err_pd;

	(*rcm)->listen_cq = ib_create_cq((*rcm)->cm_id->device, listener_cq_handle, NULL, (*rcm), 2, 0);
	if (IS_ERR((*rcm)->listen_cq))
		goto err_cq;

	if (ib_req_notify_cq((*rcm)->listen_cq, IB_CQ_NEXT_COMP))
		goto err_notify;

	(*rcm)->mr = ib_get_dma_mr((*rcm)->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR((*rcm)->mr))
		goto err_mr;

	create_tx_buffer((*rcm));

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
	if (*rcm)
	{
		destroy_connections(*rcm);

		destroy_tx_buffer((*rcm));

		if ((*rcm)->cm_id)
		{
			if((*rcm)->cm_id->qp)
				ib_destroy_qp((*rcm)->cm_id->qp);

			if((*rcm)->mr)
				(*rcm)->cm_id->device->dereg_mr((*rcm)->mr);

			if((*rcm)->pd)
				ib_dealloc_pd((*rcm)->pd);

			if((*rcm)->cm_id)
				rdma_destroy_id((*rcm)->cm_id);

		}

		kfree(*rcm);
		*rcm = 0;

	}

}

int create_connection(rcm *rcm, connect_data *conn_data)
{
	struct sockaddr_in dst, src;
	struct rdma_conn_param param;
	conn_element *ele;

	memset(&param, 0, sizeof(struct rdma_conn_param));
	param.responder_resources = 1;
	param.initiator_depth = 1;
	param.retry_count = 10;

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = (__u32) inet_addr(conn_data->ip);
	dst.sin_port = (__u16) htons(conn_data->port);

	src.sin_family = AF_INET;
	src.sin_addr.s_addr = rcm->sin.sin_addr.s_addr;
	src.sin_port = htons(5001);

	ele = vmalloc(sizeof(conn_element));

	ele->remote_node_ip = inet_addr(conn_data->ip);

	insert_rb_conn(rcm, ele);

	ele->cm_id = rdma_create_id(connection_event_handler, ele, RDMA_PS_TCP, IB_QPT_RC);

	return rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &src, (struct sockaddr*) &dst, 2000);

}

void accept_connection(conn_element *ele)
{
	int r;
	struct rdma_conn_param conn_param;

	ele->send_mem = vmalloc(sizeof(rdma_info));

	ele->send_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device, ele->send_mem, sizeof(rdma_info), DMA_TO_DEVICE);
	memset(ele->send_info, 0, sizeof(rdma_info));

	ele->recv_mem = vmalloc(sizeof(rdma_info));

	ele->recv_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device, ele->recv_mem, sizeof(rdma_info), DMA_FROM_DEVICE);

	memset(ele->recv_info, 0, sizeof(rdma_info));

	ele->pd = ib_alloc_pd(ele->cm_id->device);

	ele->mr = ib_get_dma_mr(ele->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);

	ele->send_info->node_ip = htons(ele->rcm->node_ip);
	ele->send_info->buf_rx_addr = 0;
	ele->send_info->buf_msg_addr = htonll((u64) ele->recv_info);
	ele->send_info->rkey_msg = htonl(ele->mr->rkey);
	ele->send_info->rkey_rx = 0;

	if ( (r = create_qp(ele)) )
		goto err1;

	create_tx_buffer(ele->rcm);

	create_rx_buffer(ele);

	init_dsm_info(ele);

	dsm_recv_info(ele);

	memset(&conn_param, 0, sizeof(struct rdma_conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;

	rdma_accept(ele->cm_id, &conn_param);

	return;

err1:

	printk("\n>[accept_connection] - failed creating connection element\n");

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

void destroy_connections(rcm *rcm)
{
	conn_element *ele;
	int i = 0;

	// DSM3: Temporarily using i - this doesn't make sense - what if nodes = 1, 3, 4?  We only free first!
	while ( (ele = search_rb_conn(rcm, i)) )
	{
		printk("\n[destroy_connections] ele->remote_node_id : %d", ele->remote_node_ip);

		destroy_connection(&ele);

		++i;

	}

}

void create_tx_buffer(rcm *rcm)
{
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

int create_qp(conn_element *ele)
{
	struct ib_qp_init_attr attr;
	struct rdma_cm_id *id = ele->cm_id;
	int r = 0;

	ele->send_cq = ib_create_cq(ele->cm_id->device, send_cq_handle, dsm_cq_event_handler, (void *) ele, 2, 0);
	if (IS_ERR(ele->send_cq))
	{
		r = -1;
		goto err;

	}

	if(ib_req_notify_cq(ele->send_cq, IB_CQ_NEXT_COMP))
	{
		r = -1;
		goto err;

	}

	ele->recv_cq = ib_create_cq(ele->cm_id->device, recv_cq_handle, dsm_cq_event_handler, (void *) ele, 2, 0);
	if (IS_ERR(ele->recv_cq))
	{
		r = -1;
		goto err;

	}
//IB_CQ_SOLICITED
	if(ib_req_notify_cq(ele->recv_cq, IB_CQ_NEXT_COMP))
	{
		r = -1;
		goto err;

	}

	memset(&attr, 0, sizeof attr);

	attr.send_cq = ele->send_cq;
	attr.recv_cq = ele->recv_cq;
	attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	attr.cap.max_send_wr = 2;
	attr.cap.max_recv_wr = 2;
	attr.cap.max_send_sge = 1;
	attr.cap.max_recv_sge = 1;
	attr.qp_type = IB_QPT_RC;
	attr.port_num = ele->cm_id->port_num;
	attr.qp_context = (void *) ele;

	r = rdma_create_qp(id, ele->pd, &attr);

	return r;

err:
	printk("\n ERROR\n\n");

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
