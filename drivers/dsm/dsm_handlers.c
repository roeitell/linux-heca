/*
 * dsm_handlers.c
 *
 *  Created on: 11 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_def.h>
#include <dsm/dsm_op.h>
#include <dsm/dsm_handlers.h>

void dsm_cq_event_handler(struct ib_event *event, void *data)
{
	printk("\n>[dsm_cq_event_handler] event %u data %p\n", event->event, data);
}

void listener_cq_handle(struct ib_cq *cq, void *cq_context)
{
	struct ib_wc wc;

	if (ib_req_notify_cq(cq, IB_CQ_SOLICITED))
		printk("\n>[listener_cq_handle] - ib_req_notify_cq: Failed to get cq event");

	if (ib_poll_cq(cq, 1, &wc))
	{
		if (wc.status == IB_WC_SUCCESS)
		{
			switch(wc.opcode)
			{
				case IB_WC_RECV:
				{

					printk("\n>[listener_cq_handle]");

					break;
				}
				default:
				{
					break;
				}

			}
		}
	}
	else
	{
		printk("\n>[ib_poll_cq] - recv FAILURE ");
	}
}

void send_cq_handle(struct ib_cq *cq, void *cq_context)
{
	struct ib_wc wc;

	if (ib_req_notify_cq(cq, IB_CQ_NEXT_COMP))
		printk("\n>[ib_req_notify_cq] - Failed to get cq event");


	if (ib_poll_cq(cq, 1, &wc))
	{
		if (wc.status == IB_WC_SUCCESS)
		{
			switch(wc.opcode)
			{
				case IB_WC_SEND:
				{
					printk("\n>[send_cq_handle] [IB_WC_SEND] - send completion.");

					printk("\n>---flush---\n");
					break;
				}
				default:
				{
					printk("\n>[DEFAULT] - wtf");
					printk("expected opcode %d got %d\n", IB_WC_RECV, wc.opcode);
					printk("\n>---flush---\n");

					break;
				}
			}

		}
	}
	else
		printk("\n>[ib_poll_cq] - send FAILURE ");

}

void recv_cq_handle(struct ib_cq *cq, void *cq_context)
{
	struct ib_wc wc;
	conn_element *ele = (conn_element *) cq_context;
	conn_element *ele_found;
	rdma_info *info = ele->recv_info;

	if (ib_req_notify_cq(cq, IB_CQ_NEXT_COMP))
		printk("\n>[ib_req_notify_cq] - Failed to get cq event");

	if (ib_poll_cq(cq, 1, &wc))
	{
		if (wc.status == IB_WC_SUCCESS)
		{
			switch(wc.opcode)
			{
				case IB_WC_RECV:
				{
					printk("\n[recv_cq_handle] - received.\n");

					printk("\n[rdma_info] \n>node-id: %u\n>buf_rx_addr: %llu\n>rkey_rx: %lu\n>buf_msg_addr: %llu\n>rkey_msg: %lu",
							(unsigned int) ntohs(info->node_ip),
							(unsigned long long int) ntohll(info->buf_rx_addr),
							(unsigned long int) ntohl(info->rkey_rx),
							(unsigned long long int) ntohll(info->buf_msg_addr),
							(unsigned long int) ntohl(info->rkey_msg)

					);
					printk("\n[rdma_info] \n>rx_buf_size: %u", (unsigned int) info->rx_buf_size);
					printk("\n>---flush---\n");


					if (ele && (ele->phase == 2) )
					{
						printk("\n[server_event_handler -- recv_cq_handle] - exchange_info_serverside");

						--ele->phase;

						exchange_info_serverside(ele);

					}
					else
						if (ele && (ele->phase == 1))
						{
							// DSM1: do we need ntohs to convert remote_node_ip?
							ele->remote_node_ip = (int) info->node_ip;

							ele_found = search_rb_conn(ele->rcm, ele->remote_node_ip);

							// We find that a connection is already open with that node - delete this connection request.
							if (ele_found)
							{
								printk("[recv_cq_handle] - destroy_connection duplicate : %d", ele->remote_node_ip);

								destroy_connection(&ele);

							}
							else
							{
								insert_rb_conn(ele->rcm, ele);

							}

							// DSM2: I am assuming that we don't need to worry about routing here.

						}

					break;

				}
				default:
				{
					break;

				}

			}

		}

	}
	else
	{
		printk("\n>[ib_poll_cq] - recv FAILURE ");

	}

}//

int connection_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	int r = 0;
    struct rdma_conn_param param;
    conn_element *ele;
	struct ib_qp_init_attr attr;

	switch (event->event)
	{
		case RDMA_CM_EVENT_ADDR_RESOLVED:

			r = rdma_resolve_route(id, 2000);

			printk("\n>[connection_event_handler] - rdma_resolve_route r: %d", r);

			break;

		case RDMA_CM_EVENT_ROUTE_RESOLVED:

			ele = id->context;

			ele->pd = ib_alloc_pd(ele->cm_id->device);

			ele->mr = ib_get_dma_mr(ele->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);

			ele->send_mem = vmalloc(sizeof(rdma_info));

			ele->send_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device, ele->send_mem, sizeof(rdma_info), DMA_TO_DEVICE);
			memset(ele->send_info, 0, sizeof(rdma_info));

			ele->recv_mem = vmalloc(sizeof(rdma_info));
			ele->recv_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device, ele->recv_mem, sizeof(rdma_info), DMA_FROM_DEVICE);
			memset(ele->recv_info, 0, sizeof(rdma_info));

	        ele->send_info->node_ip = htons(1);
	        ele->send_info->buf_rx_addr = 0;
	        ele->send_info->buf_msg_addr = htonll((u64) ele->recv_info);
	        ele->send_info->rkey_msg = htonl(ele->mr->rkey);
	        ele->send_info->rkey_rx = 0;

			ele->send_cq = ib_create_cq(ele->cm_id->device, send_cq_handle, dsm_cq_event_handler, (void *) ele, 2, 0);
			if (IS_ERR(ele->send_cq))
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

			memset(&param, 0, sizeof(struct rdma_conn_param));
			param.responder_resources = 1;
			param.initiator_depth = 1;
			param.retry_count = 10;

			r = rdma_connect(id, &param);

			printk("\n> [rdma_connect] %d", r);

err:
			break;

		case RDMA_CM_EVENT_ESTABLISHED:

			printk("\n>[connection_event_handler] - rdma_cm_event_established");

			exchange_info_clientside(id->context);

			break;

		case RDMA_CM_EVENT_DISCONNECTED:
		case RDMA_CM_EVENT_ADDR_ERROR:
		case RDMA_CM_EVENT_ROUTE_ERROR:
		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
		case RDMA_CM_EVENT_ADDR_CHANGE:

			r = rdma_disconnect(id);

			break;

		default:
			break;
	}

	return r;
}

int server_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	int r = -1;
	conn_element *ele;
	rcm *rcm;

	switch (event->event)
	{
		case RDMA_CM_EVENT_ADDR_RESOLVED:

			printk("\n[server_event_handler] RDMA_CM_EVENT_ADDR_RESOLVED");
			break;

		case RDMA_CM_EVENT_CONNECT_REQUEST:

			printk("\n[server_event_handler] RDMA_CM_EVENT_CONNECT_REQUEST");

			ele = vmalloc(sizeof(conn_element));
			if (!ele)
				goto out;

			rcm = id->context;

			ele->rcm = rcm;
			ele->cm_id = id;
			ele->phase = 2;

			accept_connection(ele);

			break;

		case RDMA_CM_EVENT_ESTABLISHED:

			printk("\n>[server_event_handler] - RDMA_CM_EVENT_ESTABLISHED");

			break;

		case RDMA_CM_EVENT_DISCONNECTED:

			printk("\n[server_event_handler] - RDMA_CM_EVENT_DISCONNECTED");

			r = rdma_disconnect(id);

			break;

		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
		case RDMA_CM_EVENT_ADDR_ERROR:
		case RDMA_CM_EVENT_ROUTE_ERROR:
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
		case RDMA_CM_EVENT_ADDR_CHANGE:

			printk("\n[server_event_handler] - RDMA_CM_EVENT_RANDOM");

			r = rdma_disconnect(id);

			break;

		default:
			break;
	}

	r = 0;

out:
	return r;
}
