/*
 * dsm_handlers.c
 *
 *  Created on: 11 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_def.h>
#include <dsm/dsm_op.h>
#include <dsm/dsm_handlers.h>
#include <dsm/dsm_sr.h>

void print_work_completion(struct ib_wc *wc, char * error_context) {
        printk(
                        "%s status = %d , wrid= %llu vend_err %x , opcode=%d  msg lenght %d\n",
                        error_context, wc->status, wc->wr_id, wc->vendor_err,
                        wc->opcode, wc->byte_len);
}

void dsm_cq_event_handler(struct ib_event *event, void *data) {
        printk("event %u  data %p\n", event->event, data);
        return;
}

/*
 *  We seems to never make use of this one
 */
void listener_cq_handle(struct ib_cq *cq, void *cq_context) {
        struct ib_wc wc;
        int ret = 0;

        if (ib_req_notify_cq(cq, IB_CQ_SOLICITED))
                printk(
                                ">[listener_cq_handle] - ib_req_notify_cq: Failed to get cq event\n");

        if ((ret = ib_poll_cq(cq, 1, &wc)) > 0) {
                if (likely(wc.status == IB_WC_SUCCESS)) {
                        switch (wc.opcode) {
                                case IB_WC_RECV: {

                                        break;
                                }
                                default: {
                                        printk(
                                                        ">[listener_cq_handle] - expected opcode %d got %d\n",
                                                        IB_WC_SEND, wc.opcode);
                                        break;
                                }
                        }
                } else
                        printk(
                                        ">[listener_cq_handle] - Unexpected type of wc\n");
        } else if (unlikely(ret < 0)) {
                printk(">[listener_cq_handle] - recv FAILURE \n");
        }
}

void dsm_send_poll(struct ib_cq *cq) {
        struct ib_wc wc;
        conn_element *ele = (conn_element *) cq->cq_context;
        struct tx_buf_ele * tx_buf_e = NULL;
        while (ib_poll_cq(cq, 1, &wc) > 0) {
                if (likely(wc.status == IB_WC_SUCCESS)) {
                        switch (wc.opcode) {
                                case IB_WC_SEND: {
                                        if (unlikely(ele->rid.exchanged)) {
                                                ele->rid.exchanged--;
                                                printk(
                                                                ">[dsm_send_poll] - ack rdma info exchange wr_id %llu \n",
                                                                wc.wr_id);
                                        } else {

                                                tx_buf_e =
                                                                &ele->tx_buffer.tx_buf[wc.wr_id];
                                                stats_message_send_completion(
                                                                &ele->stats);
                                                stats_update_time_send_completion(
                                                                &tx_buf_e->stats);
                                                switch (tx_buf_e->dsm_msg->status) {
                                                        case REQ_RCV_PROC: {
                                                                calc_stat_reply(
                                                                                &ele->stats,
                                                                                &tx_buf_e->stats);
                                                                release_replace_page(
                                                                                ele,
                                                                                tx_buf_e);
                                                                release_tx_element_reply(
                                                                                ele,
                                                                                tx_buf_e);

                                                                break;
                                                        }
                                                        case REQ_PROC: {

                                                                break;
                                                        }
                                                        default: {
                                                                printk(
                                                                                "[dsm_send_poll] unhandled message stats  addr: %p ,status %d , id %d , msg_nb %d\n",
                                                                                tx_buf_e,
                                                                                tx_buf_e->dsm_msg->status,
                                                                                tx_buf_e->id,
                                                                                tx_buf_e->dsm_msg->msg_num);
                                                                print_work_completion(
                                                                                &wc,
                                                                                "[dsm_send_poll] unhandled message stats , wc info - ");
                                                        }
                                                }

                                        }
                                        break;
                                }
                                case IB_WC_RDMA_WRITE: {
                                        stats_message_send_rdma_completion(
                                                        &ele->stats);
                                        break;
                                }
                                default: {
                                        print_work_completion(
                                                        &wc,
                                                        "[dsm_send_poll] - wrong  opcode ");
                                        break;
                                }
                        }
                } else {
                        print_work_completion(
                                        &wc,
                                        "[dsm_send_poll] WC status not success ");
                }

        }
}

void dsm_recv_poll(struct ib_cq *cq) {
        struct ib_wc wc;
        conn_element *ele = (conn_element *) cq->cq_context;
        struct rx_buf_ele * rx_e = NULL;
        struct tx_buf_ele * tx_e = NULL;

        while (ib_poll_cq(cq, 1, &wc) > 0) {
                switch (wc.status) {
                        case IB_WC_WR_FLUSH_ERR: {
                                print_work_completion(
                                                &wc,
                                                "[dsm_recv_poll] B_WC_WR_FLUSH_ERR ");
                                goto err;
                        }
                        case IB_WC_SUCCESS:
                                break;

                        default: {
                                print_work_completion(
                                                &wc,
                                                "[dsm_recv_poll] unkown completion status ");
                                goto err;
                        }
                }

                switch (wc.opcode) {
                        case IB_WC_RECV: {
                                if (ele) {
                                        if (unlikely(
                                                        ele->rid.remote_info->flag)) {
                                                if (wc.byte_len
                                                                != sizeof(rdma_info)) {
                                                        print_work_completion(
                                                                        &wc,
                                                                        "[dsm_recv_poll] -Received bogus data, size -");
                                                        goto err;
                                                }

                                                reg_rem_info(ele);

                                                exchange_info(ele, wc.wr_id);
                                        } else {
                                                if (wc.byte_len
                                                                != sizeof(dsm_message)) {
                                                        print_work_completion(
                                                                        &wc,
                                                                        "[dsm_recv_poll] -Received bogus data, size -");
                                                        goto err;
                                                }
                                                rx_e =
                                                                &ele->rx_buffer.rx_buf[wc.wr_id];
                                                stats_message_recv_completion(
                                                                &ele->stats);
                                                switch (rx_e->dsm_msg->status) {
                                                        case REQ_REPLY: {
                                                                tx_e =
                                                                                &ele->tx_buffer.tx_buf[rx_e->dsm_msg->offset];
                                                                stats_message_recv_rdma_completion(
                                                                                &ele->stats);
                                                                stats_update_time_recv_completion(
                                                                                &tx_e->stats);
                                                                calc_stat_request_reply(
                                                                                &ele->stats,
                                                                                &tx_e->stats);
                                                                process_response(
                                                                                ele,
                                                                                tx_e); // client got its response

                                                                break;
                                                        }

                                                        case REQ_RCV: {

                                                                rx_tx_message_transfer(
                                                                                ele,
                                                                                rx_e); // server got a request
                                                                break;
                                                        }
                                                        default: {
                                                                printk(
                                                                                "[dsm_recv_poll] unhandled message stats  addr: %p ,status %d , id %d , msg_nb %d\n",
                                                                                rx_e,
                                                                                rx_e->dsm_msg->status,
                                                                                rx_e->id,
                                                                                rx_e->dsm_msg->msg_num);
                                                                print_work_completion(
                                                                                &wc,
                                                                                "[dsm_recv_poll] - unknown message status ");
                                                                break;
                                                        }
                                                }

                                                refill_recv_wr(ele, rx_e);
                                        }
                                } else
                                        printk(
                                                        ">[recv_cq_handle] - reference to a non existent connection\n");

                                break;

                        }
                        default: {
                                printk(
                                                ">[recv_cq_handle] - expected opcode %d got %d\n",
                                                IB_WC_RECV, wc.opcode);
                                break;
                        }
                }

        }

        err: return;

}

/*
 * This one notifies that the sending as been correctly done
 */
void _send_cq_handle(struct ib_cq *cq, void *cq_context) {
        int ret = 0;
        conn_element *ele = (conn_element *) cq->cq_context;
        dsm_send_poll(cq);
        ret = ib_req_notify_cq(cq,
                        IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
        if (ret > 0)
                tasklet_schedule(&ele->send_work);
        else if (ret < 0)
                printk("[_send_cq_handle]ib_req_notify_cq fault  %d\n ", ret);

}

/*
 * This one handles the reception of messages for both client or server purposes
 */
void _recv_cq_handle(struct ib_cq *cq, void *cq_context) {
        int ret = 0;
        conn_element *ele = (conn_element *) cq->cq_context;
        dsm_recv_poll(cq);
        ret = ib_req_notify_cq(cq,
                        IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
        if (ret > 0)
                tasklet_schedule(&ele->recv_work);
        else if (ret < 0)
                printk("[_send_cq_handle]ib_req_notify_cq fault  %d\n ", ret);

}

void send_cq_handle_work(struct tasklet_struct *work) {

        conn_element *ele;
        ele= container_of(work, struct conn_element ,send_work );
        _send_cq_handle(ele->send_cq, NULL);
}
void recv_cq_handle_work(struct work_struct *work) {
        conn_element *ele;
        ele= container_of(work, struct conn_element ,recv_work );
        _recv_cq_handle(ele->recv_cq, NULL);
}

void send_cq_handle(struct ib_cq *cq, void *cq_context) {
        conn_element *ele = (conn_element *) cq->cq_context;
        tasklet_schedule(&ele->send_work);
}
void recv_cq_handle(struct ib_cq *cq, void *cq_context) {
        conn_element *ele = (conn_element *) cq->cq_context;
        queue_work(ele->rcm->dsm_wq, &ele->recv_work);
}
/*
 * This one is specific to the client part
 * It triggers the connection in the first place and handles the reaction of the remote node.
 */
int connection_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event) {
        int ret = 0;
        int err = 0;
        conn_element *ele;

        switch (event->event) {
                case RDMA_CM_EVENT_ADDR_RESOLVED:

                        ret = rdma_resolve_route(id, 2000);
                        if (ret)
                                goto err1;
                        break;

                case RDMA_CM_EVENT_ROUTE_RESOLVED:

                        ele = id->context;

                        ret = setup_connection(ele, 0);
                        if (ret)
                                goto err2;

                        ret = connect_client(id);
                        if (ret)
                                goto err3;

                        break;

                case RDMA_CM_EVENT_ESTABLISHED:

                        ele = id->context;

                        ret = dsm_recv_info(ele);
                        if (ret)
                                goto err4;

                        ret = dsm_send_info(ele);
                        if (ret < 0)
                                goto err5;

                        break;

                case RDMA_CM_EVENT_DISCONNECTED:

                        printk(
                                        ">>>>[connection_event_handler] - disconnection from remote node\n");
                        ele = id->context;
                        ret = destroy_connection(&ele, ele->rcm);

                        break;

                case RDMA_CM_EVENT_DEVICE_REMOVAL:
                case RDMA_CM_EVENT_ADDR_ERROR:
                case RDMA_CM_EVENT_ROUTE_ERROR:
                case RDMA_CM_EVENT_CONNECT_ERROR:
                case RDMA_CM_EVENT_UNREACHABLE:
                case RDMA_CM_EVENT_REJECTED:
                case RDMA_CM_EVENT_ADDR_CHANGE:

                        printk(
                                        ">>>>[connection_event_handler] - Unexpected event: %d\n",
                                        event->event);
                        ret = rdma_disconnect(id);
                        if (unlikely(ret))
                                goto disconnect_err;

                        break;

                default:
                        printk(
                                        ">>>>[connection_event_handler] - Unhandled event: %d\n",
                                        event->event);
                        break;
        }

        return ret;

        err5: err++;
        err4: err++;
        err3: err++;
        err2: err++;
        err1: err++;
        ret = rdma_disconnect(id);
        printk(">[connection_event_handler] - ERROR %d\n", err);
        if (unlikely(ret))
                goto disconnect_err;

        return ret;

        disconnect_err: printk("*** DISCONNECTION FAILED *** \n");
        return ret;
}

/*
 * this one is for the server part
 * It waits for a connection request as soon as the rcm has been created
 * Then it creates it's own connection element and accept the request to complete the connection
 */
int server_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event) {
        int ret = 0;
        conn_element *ele = 0;
        rcm *rcm;

        switch (event->event) {
                case RDMA_CM_EVENT_ADDR_RESOLVED:

                        break;

                case RDMA_CM_EVENT_CONNECT_REQUEST:

                        ele = vmalloc(sizeof(conn_element));
                        if (!ele)
                                goto out;

                        rcm = id->context;

                        ele->rcm = rcm;
                        ele->cm_id = id;
                        id->context = ele;

                        ret = setup_connection(ele, 1);
                        if (ret) {
                                printk("Connection could not be accepted\n");
                                goto err;
                        }

                        break;

                case RDMA_CM_EVENT_ESTABLISHED:

                        break;

                case RDMA_CM_EVENT_DISCONNECTED:

                        ele = id->context;

                        destroy_connection(&ele, ele->rcm);

                        break;

                case RDMA_CM_EVENT_CONNECT_ERROR:
                case RDMA_CM_EVENT_DEVICE_REMOVAL:
                case RDMA_CM_EVENT_ROUTE_RESOLVED:
                case RDMA_CM_EVENT_ADDR_ERROR:
                case RDMA_CM_EVENT_ROUTE_ERROR:
                case RDMA_CM_EVENT_UNREACHABLE:
                case RDMA_CM_EVENT_REJECTED:
                case RDMA_CM_EVENT_ADDR_CHANGE:

                        printk(
                                        "[server_event_handler] - Unexpected event: %d\n",
                                        event->event);

                        ret = rdma_disconnect(id);
                        if (unlikely(ret))
                                goto disconnect_err;

                        break;

                default:
                        break;
        }

        out: return ret;

        disconnect_err: printk("*** DISCONNECTION FAILED *** \n");

        err: vfree(ele);
        ele = 0;

        return ret;
}
