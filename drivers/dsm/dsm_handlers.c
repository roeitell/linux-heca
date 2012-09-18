/*
 * dsm_handlers.c
 *
 *  Created on: 11 Jul 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>
#include <dsm/dsm_trace.h>

static void destroy_connection_work(struct work_struct *work)
{
    struct rcm *rcm = get_dsm_module_state()->rcm;
    struct rb_root *root;
    struct rb_node *node, *next;
    struct conn_element *ele;
    unsigned long seq;

    do {
        seq = read_seqbegin(&rcm->conn_lock);
        root = &rcm->root_conn;
        for (node = rb_first(root); node; node = next) {
            ele = rb_entry(node, struct conn_element, rb_node);
            next = rb_next(node);
            if (atomic_cmpxchg(&ele->alive, -1, 0) == -1)
                destroy_connection(ele);
        }
    } while (read_seqretry(&rcm->conn_lock, seq));

    kfree(work);
}

static inline void schedule_destroy_conns(void)
{
    struct work_struct *work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
    INIT_WORK(work, destroy_connection_work);
    schedule_work(work);
}

static inline void queue_recv_work(struct conn_element *ele)
{
    rcu_read_lock();
    if (atomic_read(&ele->alive))
        queue_work(get_dsm_module_state()->dsm_rx_wq, &ele->recv_work);
    rcu_read_unlock();
}

static inline void queue_send_work(struct conn_element *ele)
{
    rcu_read_lock();
    if (atomic_read(&ele->alive))
        queue_work(get_dsm_module_state()->dsm_tx_wq, &ele->send_work);
    rcu_read_unlock();
}

static int process_dsm_request(struct conn_element *ele,
        struct dsm_request *req,  struct tx_buf_ele *tx_e)
{
    switch (req->type) {
        case REQUEST_PAGE:
        case TRY_REQUEST_PAGE:
            create_page_request(ele, tx_e, req->dsm_id, req->mr_id,
                    req->local_svm_id, req->remote_svm_id, req->addr, req->page,
                    req->type, req->dpc, req->ppe);
            break;
        case REQUEST_PAGE_PULL:
            create_page_pull_request(ele, tx_e, req->dsm_id, req->mr_id,
                    req->local_svm_id, req->remote_svm_id, req->addr);
            break;
        case PAGE_REQUEST_FAIL:
            dsm_msg_cpy(tx_e->dsm_buf, &req->dsm_buf);
            tx_e->dsm_buf->type = PAGE_REQUEST_FAIL;
            break;
        case PAGE_REQUEST_REDIRECT:
            dsm_msg_cpy(tx_e->dsm_buf, &req->dsm_buf);
            tx_e->dsm_buf->type = PAGE_REQUEST_REDIRECT;
            break;
        case SVM_STATUS_UPDATE:
            dsm_msg_cpy(tx_e->dsm_buf, &req->dsm_buf);
            tx_e->dsm_buf->type = SVM_STATUS_UPDATE;
            break;
        case ACK:
            dsm_msg_cpy(tx_e->dsm_buf, &req->dsm_buf);
            tx_e->dsm_buf->type = ACK;
            break;
        default:
            BUG();
    }
    tx_e->callback.func = req->func;
    tx_dsm_send(ele, tx_e);
    return 0;
}

void dsm_request_queue_merge(struct tx_buffer *tx)
{
    struct list_head *head = &tx->ordered_request_queue;
    struct llist_node *llnode = llist_del_all(&tx->request_queue);

    while (llnode) {
        struct dsm_request *req;

        req = container_of(llnode, struct dsm_request, lnode);
        list_add_tail(&req->ordered_list, head);
        head = &req->ordered_list;
        llnode = llnode->next;
        tx->request_queue_sz++;
    }
}

static inline int flush_dsm_request_queue(struct conn_element *ele) {
    struct tx_buffer *tx = &ele->tx_buffer;
    struct dsm_request *req;
    struct tx_buf_ele *tx_e = NULL;
    int ret = 0;

    mutex_lock(&tx->flush_mutex);
    dsm_request_queue_merge(tx);
    while (!list_empty(&tx->ordered_request_queue)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (!tx_e) {
            ret = 1;
            break;
        }
        tx->request_queue_sz--;
        req = list_first_entry(&tx->ordered_request_queue, struct dsm_request,
                ordered_list);
        trace_flushing_requests(tx->request_queue_sz);
        process_dsm_request(ele, req, tx_e);
        list_del(&req->ordered_list);
        release_dsm_request(req);
    }
    mutex_unlock(&tx->flush_mutex);
    return ret;

}

void schedule_delayed_request_flush(struct conn_element *ele)
{
    schedule_work(&ele->delayed_request_flush_work);
}

void delayed_request_flush_work_fn(struct work_struct *w)
{
    struct conn_element *ele;
    udelay(REQUEST_FLUSH_DELAY);
    ele = container_of(w, struct conn_element , delayed_request_flush_work);
    if (flush_dsm_request_queue(ele))
        schedule_delayed_request_flush(ele);
}

static inline void handle_tx_element(struct conn_element *ele,
        struct tx_buf_ele *tx_e, int (*callback)(struct conn_element *,
        struct tx_buf_ele *))
{
    /* if tx_e->used > 2, we're racing with release_svm_tx_elements */
    if (atomic_add_return(1, &tx_e->used) == 2) {
        if (callback)
            callback(ele, tx_e);
		try_release_tx_element(ele, tx_e);
	}
}

static int dsm_recv_message_handler(struct conn_element *ele,
        struct rx_buf_ele *rx_e)
{
    struct tx_buf_ele *tx_e = NULL;

    trace_dsm_rx_msg(rx_e->dsm_buf->dsm_id, rx_e->dsm_buf->src_id,
                    rx_e->dsm_buf->dest_id, -1, 0, 
                    rx_e->dsm_buf->req_addr, rx_e->dsm_buf->type,
                    rx_e->dsm_buf->offset);

    switch (rx_e->dsm_buf->type) {
        case PAGE_REQUEST_REPLY: {
            BUG_ON(rx_e->dsm_buf->offset < 0 ||
                    rx_e->dsm_buf->offset >= ele->tx_buffer.len);
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            handle_tx_element(ele, tx_e, process_page_response);
            break;
        }
        case PAGE_REQUEST_REDIRECT:{
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            process_page_redirect(ele, tx_e, rx_e->dsm_buf->dest_id);
            break;
        }
        case PAGE_REQUEST_FAIL: {
            BUG_ON(rx_e->dsm_buf->offset < 0 ||
                    rx_e->dsm_buf->offset >= ele->tx_buffer.len);
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            tx_e->dsm_buf->type = PAGE_REQUEST_FAIL;
            handle_tx_element(ele, tx_e, process_page_response);
            break;
        }
        case TRY_REQUEST_PAGE:
        case REQUEST_PAGE: {
            process_page_request_msg(ele, rx_e->dsm_buf);
            break;
        }
        case REQUEST_PAGE_PULL: {
            process_pull_request(ele, rx_e); // server is requested to pull
            ack_msg(ele, rx_e);
            break;
        }
        case SVM_STATUS_UPDATE: {
            process_svm_status(ele, rx_e);
            break;
        }
        case ACK: {
            BUG_ON(rx_e->dsm_buf->offset < 0 ||
                    rx_e->dsm_buf->offset >= ele->tx_buffer.len);
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            handle_tx_element(ele, tx_e, NULL);
            break;
        }

        default: {
            printk("[dsm_recv_poll] unhandled message stats addr: %p, status %d"
                    " id %d\n", rx_e, rx_e->dsm_buf->type, rx_e->id);
            goto err;
        }
    }

    refill_recv_wr(ele, rx_e);
    return 0;
err: 
    return 1;
}
EXPORT_SYMBOL(dsm_recv_message_handler);

static int dsm_send_message_handler(struct conn_element *ele,
        struct tx_buf_ele *tx_buf_e)
{
    trace_dsm_tx_msg(tx_buf_e->dsm_buf->dsm_id, tx_buf_e->dsm_buf->src_id,
            tx_buf_e->dsm_buf->dest_id, -1, 0, tx_buf_e->dsm_buf->req_addr,
            tx_buf_e->dsm_buf->type, tx_buf_e->dsm_buf->offset);

    switch (tx_buf_e->dsm_buf->type) {
        case PAGE_REQUEST_REPLY:
            dsm_clear_swp_entry_flag(tx_buf_e->reply_work_req->mm,
                    tx_buf_e->reply_work_req->addr,
                    tx_buf_e->reply_work_req->pte, DSM_INFLIGHT_BITPOS);
            dsm_ppe_clear_release(ele, &tx_buf_e->wrk_req->dst_addr);
            release_tx_element_reply(ele, tx_buf_e);
            break;
        case ACK:
        case PAGE_REQUEST_FAIL:
        case SVM_STATUS_UPDATE:
            release_tx_element(ele, tx_buf_e);
            break;
        case REQUEST_PAGE:
        case TRY_REQUEST_PAGE:
        case REQUEST_PAGE_PULL:
            try_release_tx_element(ele, tx_buf_e);
            break;
        default:
            printk("[dsm_send_poll] unhandled message stats  addr: %p, "
                    "status %d , id %d \n", tx_buf_e, tx_buf_e->dsm_buf->type,
                    tx_buf_e->id);
            return 1;
    }
    return 0;
}
EXPORT_SYMBOL(dsm_send_message_handler);

void dsm_cq_event_handler(struct ib_event *event, void *data)
{
    printk("event %u  data %p\n", event->event, data);
}

/*
 *  We seems to never make use of this one
 */
void listener_cq_handle(struct ib_cq *cq, void *cq_context)
{
    struct ib_wc wc;
    int ret = 0;

    if (ib_req_notify_cq(cq, IB_CQ_SOLICITED))
        printk(
                ">[listener_cq_handle] - ib_req_notify_cq: Failed to get cq event\n");

    if ((ret = ib_poll_cq(cq, 1, &wc)) > 0) {
        if (likely(wc.status == IB_WC_SUCCESS)) {
            switch (wc.opcode) {
                case IB_WC_RECV:
                    break;
                default: {
                    printk(
                            ">[listener_cq_handle] - expected opcode %d got %d\n",
                            IB_WC_SEND, wc.opcode);
                    break;
                }
            }
        } else
            printk(">[listener_cq_handle] - Unexpected type of wc\n");
    } else if (unlikely(ret < 0)) {
        printk(">[listener_cq_handle] - recv FAILURE \n");
    }
}

static void dsm_send_poll(struct ib_cq *cq)
{
    struct ib_wc wc;
    struct conn_element *ele = (struct conn_element *) cq->cq_context;

    while (ib_poll_cq(cq, 1, &wc) > 0) {
        if (unlikely(wc.status != IB_WC_SUCCESS || wc.opcode != IB_WC_SEND))
            continue;

        if (unlikely(ele->rid.exchanged))
            ele->rid.exchanged--;
        else
            dsm_send_message_handler(ele, &ele->tx_buffer.tx_buf[wc.wr_id]);
    }
}

static void dsm_recv_poll(struct ib_cq *cq)
{
    struct ib_wc wc;
    struct conn_element *ele = (struct conn_element *) cq->cq_context;

    while (ib_poll_cq(cq, 1, &wc) == 1) {
        if (likely(wc.status == IB_WC_SUCCESS)) {
            if (unlikely(wc.opcode != IB_WC_RECV)) {
                dsm_printk(KERN_INFO "expected opcode %d got %d",
                        IB_WC_RECV, wc.opcode);
                continue;
            }
        } else {
            if (wc.status == IB_WC_WR_FLUSH_ERR) {
                dsm_printk(KERN_INFO "rx id %llx status %d vendor_err %x",
                    wc.wr_id, wc.status, wc.vendor_err);
            } else {
                dsm_printk(KERN_ERR "rx id %llx status %d vendor_err %x",
                    wc.wr_id, wc.status, wc.vendor_err);
            }
            continue;
        }
            
        if (ele->rid.remote_info->flag) {
            BUG_ON(wc.byte_len != sizeof(struct rdma_info));
            reg_rem_info(ele);
            exchange_info(ele, wc.wr_id);
        } else {
            BUG_ON(wc.byte_len != sizeof(struct dsm_message));
            BUG_ON(wc.wr_id < 0 || wc.wr_id >= ele->rx_buffer.len);
            dsm_recv_message_handler(ele, &ele->rx_buffer.rx_buf[wc.wr_id]);
        }
    }
}

void send_cq_handle_work(struct work_struct *work)
{
    struct conn_element *ele = container_of(work, struct conn_element,
            send_work);
    int ret = 0;

    dsm_send_poll(ele->qp_attr.send_cq);
    ret = ib_req_notify_cq(ele->qp_attr.send_cq,
            IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
    dsm_send_poll(ele->qp_attr.send_cq);
    if (ret > 0)
        queue_send_work(ele);
}

void recv_cq_handle_work(struct work_struct *work)
{
    struct conn_element *ele = container_of(work, struct conn_element,
            recv_work);
    int ret = 0;

    dsm_recv_poll(ele->qp_attr.recv_cq);
    ret = ib_req_notify_cq(ele->qp_attr.recv_cq,
            IB_CQ_NEXT_COMP | IB_CQ_REPORT_MISSED_EVENTS);
    dsm_recv_poll(ele->qp_attr.recv_cq);
    if (ret > 0)
        queue_recv_work(ele);
}

void send_cq_handle(struct ib_cq *cq, void *cq_context)
{
    queue_send_work((struct conn_element *) cq->cq_context);
}

void recv_cq_handle(struct ib_cq *cq, void *cq_context)
{
    queue_recv_work((struct conn_element *) cq->cq_context);
}

/*
 * This one is specific to the client part
 * It triggers the connection in the first place and handles the reaction of the remote node.
 */
int client_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
    int ret = 0, err = 0;
    struct conn_element *ele = id->context;

    switch (event->event) {
        case RDMA_CM_EVENT_ADDR_RESOLVED:
            ret = rdma_resolve_route(id, 2000);
            if (ret)
                goto err1;
            break;

        case RDMA_CM_EVENT_ROUTE_RESOLVED:
            ret = setup_connection(ele, 0);
            if (ret)
                goto err2;

            ret = connect_client(id);
            if (ret) {
                complete(&ele->completion);
                goto err3;
            }

            atomic_set(&ele->alive, 1);
            break;

        case RDMA_CM_EVENT_ESTABLISHED:
            ret = dsm_recv_info(ele);
            if (ret)
                goto err4;

            ret = dsm_send_info(ele);
            if (ret < 0)
                goto err5;

            break;

        case RDMA_CM_EVENT_DISCONNECTED:
            if (likely(atomic_cmpxchg(&ele->alive, 1, -1) == 1))
                schedule_destroy_conns();
            break;

        case RDMA_CM_EVENT_ADDR_ERROR:
        case RDMA_CM_EVENT_ROUTE_ERROR:
        case RDMA_CM_EVENT_CONNECT_ERROR:
        case RDMA_CM_EVENT_UNREACHABLE:
        case RDMA_CM_EVENT_REJECTED:
            dsm_printk(KERN_ERR, "could not connect, %d\n", event->event);
            complete(&ele->completion);
            break;

        case RDMA_CM_EVENT_DEVICE_REMOVAL:
        case RDMA_CM_EVENT_ADDR_CHANGE:
            dsm_printk(KERN_ERR "unexpected event: %d", event->event);
            ret = rdma_disconnect(id);
            if (unlikely(ret))
                goto disconnect_err;
            break;

        default:
            dsm_printk(KERN_ERR "no special handling: %d", event->event);
            break;
    }

    return ret;

err5: 
    err++;
err4: 
    err++;
err3: 
    err++;
err2: 
    err++;
err1: 
    err++;
    ret = rdma_disconnect(id);
    dsm_printk(KERN_ERR, "fatal error %d", err);
    if (unlikely(ret))
        goto disconnect_err;

    return ret;

disconnect_err: 
    dsm_printk(KERN_ERR, "disconection failed");
    return ret;
}
EXPORT_SYMBOL(client_event_handler);

/*
 * this one is for the server part
 * It waits for a connection request as soon as the rcm has been created
 * Then it creates it's own connection element and accept the request to complete the connection
 */
int server_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
    char ip[32];
    int ret = 0;
    struct conn_element *ele = 0;
    struct rcm *rcm;

    switch (event->event) {
        case RDMA_CM_EVENT_ADDR_RESOLVED:
            break;

        case RDMA_CM_EVENT_CONNECT_REQUEST:
            ele = vzalloc(sizeof(struct conn_element));
            if (!ele)
                goto out;

            init_completion(&ele->completion);
            rcm = id->context;
            ele->rcm = rcm;
            ele->cm_id = id;
            id->context = ele;

            ret = setup_connection(ele, 1);
            if (ret) {
                printk("Connection could not be accepted\n");
                goto err;
            }

            scnprintf(ip, 32, "%p", id);
            ret = create_connection_sysfs_entry(&ele->sysfs,
                    get_dsm_module_state()->dsm_kobjects.rdma_kobject, ip);
            if (ret)
                goto err;

            atomic_set(&ele->alive, 1);
            break;

        case RDMA_CM_EVENT_ESTABLISHED:
            break;

        case RDMA_CM_EVENT_DISCONNECTED:
            ele = id->context;
            if (likely(atomic_cmpxchg(&ele->alive, 1, -1) == 1))
                schedule_destroy_conns();
            break;

        case RDMA_CM_EVENT_CONNECT_ERROR:
        case RDMA_CM_EVENT_DEVICE_REMOVAL:
        case RDMA_CM_EVENT_ROUTE_RESOLVED:
        case RDMA_CM_EVENT_ADDR_ERROR:
        case RDMA_CM_EVENT_ROUTE_ERROR:
        case RDMA_CM_EVENT_UNREACHABLE:
        case RDMA_CM_EVENT_REJECTED:
        case RDMA_CM_EVENT_ADDR_CHANGE:
            dsm_printk(KERN_ERR "unexpected event: %d", event->event);

            ret = rdma_disconnect(id);
            if (unlikely(ret))
                goto disconnect_err;
            break;

        default:
            dsm_printk(KERN_ERR "no special handling: %d", event->event);
            break;
    }

out: 
    return ret;

disconnect_err: 
    dsm_printk(KERN_ERR "disconnect failed");
err: 
    vfree(ele);
    ele = 0;
    return ret;
}
EXPORT_SYMBOL(server_event_handler);

