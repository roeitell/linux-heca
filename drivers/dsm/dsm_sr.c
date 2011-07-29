/*
 * dsm_sr.c
 *
 *  Created on: 26 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_sr.h>

static struct ib_sge recv_sge;
static struct ib_recv_wr recv_wr;
static struct ib_recv_wr *recv_bad_wr;

static struct ib_sge send_sge;
static struct ib_send_wr send_wr;
static struct ib_send_wr *send_bad_wr;

void exchange_info_clientside(conn_element *ele)
{
	int r = 0;
	printk("[exchange_info_clientside] start\n");

	r = dsm_recv_info(ele);

	printk("[exchange_info_clientside] dsm_recv_info : %d\n", r);

	dsm_send_info(ele);

	r = printk("[exchange_info_clientside] dsm_send_info : %d\n", r);

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

	printk("[exchange_info_serverside] start\n");

	r = dsm_recv_info(ele);

	printk("[exchange_info_serverside] dsm_recv_info : %d\n", r);

	r = dsm_send_info(ele);

	printk("[exchange_info_serverside] dsm_send_info : %d\n", r);

//	for(i = 0; i < RX_BUF_ELEMENTS_NUM; ++i)
//	{
//		dsm_recv_msg(ele, i);
//	}


	//r = dsm_send_info(ele);
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

	ele->send_info->node_ip = ele->rcm->node_ip;
	ele->send_info->rx_buf_size = TX_BUF_ELEMENTS_NUM;

	return 0;

}

int dsm_send_info(conn_element *ele)
{
	send_sge.addr = (u64) ele->send_info;
	send_sge.length = sizeof(rdma_info);
	send_sge.lkey = ele->mr->lkey;

	send_wr.next	   = NULL;
	send_wr.wr_id	   = 1;
	send_wr.sg_list	   = &send_sge;
	send_wr.num_sge	   = 1;
	send_wr.opcode	   = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	return ib_post_send(ele->cm_id->qp, &send_wr, &send_bad_wr);

}

int dsm_recv_info(conn_element *ele)
{
	recv_sge.addr = (u64) ele->recv_info;
	recv_sge.length = sizeof(rdma_info);
	recv_sge.lkey = ele->mr->lkey;

	recv_wr.next = NULL;
	recv_wr.wr_id = 2;	// DSM2: unique id - address of data_struct
	recv_wr.sg_list = &recv_sge;
	recv_wr.num_sge = 1;

	return ib_post_recv(ele->cm_id->qp, &recv_wr, &recv_bad_wr);

}
