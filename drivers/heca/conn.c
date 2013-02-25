/*
 * drivers/dsm/dsm_conn.c
 *
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include <linux/list.h>
#include "core.h"
#include "trace.h"

unsigned long inet_addr(const char *cp)
{
    unsigned int a, b, c, d;
    unsigned char arr[4];

    sscanf(cp, "%u.%u.%u.%u", &a, &b, &c, &d);
    arr[0] = a;
    arr[1] = b;
    arr[2] = c;
    arr[3] = d;
    return *(unsigned int*) arr; /* network */
}

char *inet_ntoa(unsigned long s_addr, char *buf, int sz)
{
    unsigned char *b = (unsigned char *)&s_addr;

    if (!sz)
        return NULL;

    buf[0] = 0;
    snprintf(buf, sz - 1, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

char *port_ntoa(unsigned short port, char *buf, int sz)
{
    if (!sz)
        return NULL;

    buf[0] = 0;
    snprintf(buf, sz - 1, "%u", ntohs(port));
    return buf;
}

char *sockaddr_ntoa(struct sockaddr_in *sa, char *buf, int sz)
{
    char ip_str[20], port_str[10];

    if (!sz)
        return NULL;

    buf[0] = 0;
    inet_ntoa(sa->sin_addr.s_addr, ip_str, sizeof ip_str);
    port_ntoa(sa->sin_port, port_str, sizeof port_str);
    snprintf(buf, sz - 1, "%s:%s", ip_str, port_str);
    return buf;
}

char *conn_ntoa(struct sockaddr_in *local, struct sockaddr_in *remote,
        char *buf, int sz)
{
    char local_str[35], remote_str[35];

    if (!sz)
        return NULL;

    sockaddr_ntoa(local, local_str, sizeof local_str);
    sockaddr_ntoa(remote, remote_str, sizeof remote_str);
    buf[0] = 0;
    snprintf(buf, sz - 1, "%s-%s", local_str, remote_str);
    return buf;
}

static struct kmem_cache *kmem_request_cache;

static inline void init_kmem_request_cache_elm(void *obj)
{
    struct dsm_request *dpc = (struct dsm_request *) obj;
    memset(dpc, 0, sizeof(struct dsm_request));
}

void init_kmem_request_cache(void)
{
    kmem_request_cache = kmem_cache_create("dsm_request",
            sizeof(struct dsm_request), 0, SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY,
            init_kmem_request_cache_elm);
}

void destroy_kmem_request_cache(void)
{
    kmem_cache_destroy(kmem_request_cache);
}

inline struct dsm_request *alloc_dsm_request(void)
{
    return kmem_cache_alloc(kmem_request_cache, GFP_KERNEL);
}

inline void release_dsm_request(struct dsm_request *req)
{
    kmem_cache_free(kmem_request_cache, req);
}

static inline int get_nb_tx_buff_elements(struct conn_element *ele)
{
    return ele->qp_attr.cap.max_send_wr >> 1;
}

static inline int get_nb_rx_buff_elements(struct conn_element *ele)
{
    return ele->qp_attr.cap.max_recv_wr;
}

static int get_max_pushed_reqs(struct conn_element *ele)
{
    return get_nb_tx_buff_elements(ele) << 2;
}

static void schedule_delayed_request_flush(struct conn_element *ele)
{
    schedule_work(&ele->delayed_request_flush_work);
}

static inline void queue_dsm_request(struct conn_element *ele,
        struct dsm_request *req)
{
    trace_queued_request(req->dsm_id, req->local_svm_id, req->remote_svm_id,
            -1, 0, req->addr, req->type, -1);
    llist_add(&req->lnode, &ele->tx_buffer.request_queue);
    schedule_delayed_request_flush(ele);
}

int add_dsm_request(struct dsm_request *req, struct conn_element *ele,
        u16 type, struct subvirtual_machine *local_svm,
        struct memory_region *fault_mr, struct subvirtual_machine *remote_svm,
        uint64_t addr, int (*func)(struct tx_buf_ele *),
        struct dsm_page_cache *dpc, struct page *page,
        struct page_pool_ele *ppe)
{
    if (!req) {
        req = kmem_cache_alloc(kmem_request_cache, GFP_KERNEL);
        if (unlikely(!req))
            return -ENOMEM;
    }

    req->type = type;
    req->dsm_id = local_svm->dsm->dsm_id;
    req->mr_id = fault_mr->mr_id;
    req->local_svm_id = local_svm->svm_id;
    req->remote_svm_id = remote_svm->svm_id;
    req->addr = addr;
    req->func = func;
    req->dpc = dpc;
    req->page = page;
    req->ppe = ppe;
    queue_dsm_request(ele, req);

    return 0;
}

int add_dsm_request_msg(struct conn_element *ele, u16 type,
        struct dsm_message *msg)
{
    struct dsm_request *req = kmem_cache_alloc(kmem_request_cache, GFP_KERNEL);
    if (unlikely(!req))
        return -ENOMEM;

    req->type = type;
    dsm_msg_cpy(&req->dsm_buf, msg);
    queue_dsm_request(ele, req);

    return 0;
}

inline int request_queue_empty(struct conn_element *ele)
{
    /* we are not 100% accurate but it's ok we can have a few sneaking in */
    return (llist_empty(&ele->tx_buffer.request_queue) &&
            list_empty(&ele->tx_buffer.ordered_request_queue));
}

inline int request_queue_full(struct conn_element *ele)
{
    return ele->tx_buffer.request_queue_sz > get_max_pushed_reqs(ele);
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
        case CLAIM_PAGE:
            create_page_claim_request(tx_e, req->dsm_id, req->mr_id,
                    req->local_svm_id, req->remote_svm_id, req->addr);
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

static inline int flush_dsm_request_queue(struct conn_element *ele)
{
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

static void delayed_request_flush_work_fn(struct work_struct *w)
{
    struct conn_element *ele;
    udelay(REQUEST_FLUSH_DELAY);
    ele = container_of(w, struct conn_element , delayed_request_flush_work);
    if (flush_dsm_request_queue(ele))
        schedule_delayed_request_flush(ele);
}

void create_page_claim_request(struct tx_buf_ele *tx_e, u32 dsm_id, u32 mr_id,
        u32 local_id, u32 remote_id, uint64_t addr)
{
    struct dsm_message *msg = tx_e->dsm_buf;

    msg->type = CLAIM_PAGE;
    msg->dsm_id = dsm_id;
    msg->src_id = local_id;
    msg->dest_id = remote_id;
    msg->mr_id = mr_id;
    msg->req_addr = addr;
}

void create_page_request(struct conn_element *ele, struct tx_buf_ele *tx_e,
        u32 dsm_id, u32 mr_id, u32 local_id, u32 remote_id, uint64_t addr,
        struct page *page, u16 type, struct dsm_page_cache *dpc,
        struct page_pool_ele *ppe)
{
    struct dsm_message *msg = tx_e->dsm_buf;

    if (!ppe)
        ppe = dsm_prepare_ppe(ele, page);
    BUG_ON(!ppe); /* TODO: Handle gracefully */

    tx_e->wrk_req->dst_addr = ppe;
    tx_e->wrk_req->dpc = dpc;

    /*
     * we need to reset the offset just in case if we actually use the element
     * for reply as an error
     */
    msg->offset = tx_e->id;
    msg->dsm_id = dsm_id;
    msg->mr_id = mr_id;
    msg->dest_id = local_id;
    msg->src_id = remote_id;
    msg->dst_addr = (u64) ppe->page_buf;
    msg->req_addr = addr;
    msg->rkey = ele->mr->rkey;
    msg->type = type;
}

void create_page_pull_request(struct conn_element *ele,
        struct tx_buf_ele *tx_e, u32 dsm_id, u32 mr_id, u32 local_id,
        u32 remote_id, uint64_t addr)
{
    struct dsm_message *msg = tx_e->dsm_buf;

    tx_e->wrk_req->dst_addr = NULL;
    msg->offset = tx_e->id;
    msg->dsm_id = dsm_id;
    msg->mr_id = mr_id;
    msg->dest_id = local_id;
    msg->src_id = remote_id;
    msg->dst_addr = 0;
    msg->req_addr = addr;
    msg->rkey = ele->mr->rkey;
    msg->type = REQUEST_PAGE_PULL;
}

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

static int refill_recv_wr(struct conn_element *ele, struct rx_buf_ele *rx_e)
{
    int ret = 0;
    ret = ib_post_recv(ele->cm_id->qp, &rx_e->recv_wrk_rq_ele->sq_wr,
            &rx_e->recv_wrk_rq_ele->bad_wr);
    if (ret)
        printk(">[refill_recv_wr] - ERROR IN POSTING THE RECV WR"
                " ret : %d on offset %d\n", ret, rx_e->id);

    return ret;
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
        case PAGE_REQUEST_REPLY:
            BUG_ON(rx_e->dsm_buf->offset < 0 ||
                    rx_e->dsm_buf->offset >= ele->tx_buffer.len);
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            handle_tx_element(ele, tx_e, process_page_response);
            break;
        case PAGE_REQUEST_REDIRECT:
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            process_page_redirect(ele, tx_e, rx_e->dsm_buf->dest_id);
            break;
        case PAGE_REQUEST_FAIL:
            BUG_ON(rx_e->dsm_buf->offset < 0 ||
                    rx_e->dsm_buf->offset >= ele->tx_buffer.len);
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            tx_e->dsm_buf->type = PAGE_REQUEST_FAIL;
            handle_tx_element(ele, tx_e, process_page_response);
            break;
        case TRY_REQUEST_PAGE:
        case REQUEST_PAGE:
            process_page_request_msg(ele, rx_e->dsm_buf);
            break;
        case CLAIM_PAGE:
            process_page_claim(ele, rx_e->dsm_buf);
            break;
        case REQUEST_PAGE_PULL:
            process_pull_request(ele, rx_e);
            ack_msg(ele, rx_e);
            break;
        case SVM_STATUS_UPDATE:
            process_svm_status(ele, rx_e);
            break;
        case ACK:
            BUG_ON(rx_e->dsm_buf->offset < 0 ||
                    rx_e->dsm_buf->offset >= ele->tx_buffer.len);
            tx_e = &ele->tx_buffer.tx_buf[rx_e->dsm_buf->offset];
            handle_tx_element(ele, tx_e, NULL);
            break;

        default:
            printk("[dsm_recv_poll] unhandled message stats addr: %p, status %d"
                    " id %d\n", rx_e, rx_e->dsm_buf->type, rx_e->id);
            goto err;
    }

    refill_recv_wr(ele, rx_e);
    return 0;
err: 
    return 1;
}

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
        case CLAIM_PAGE:
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

static void dsm_cq_event_handler(struct ib_event *event, void *data)
{
    printk("event %u  data %p\n", event->event, data);
}

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

static void reg_rem_info(struct conn_element *ele)
{
    ele->rid.remote_info->node_ip = ntohl(ele->rid.recv_buf->node_ip);
    ele->rid.remote_info->buf_rx_addr = ntohll(ele->rid.recv_buf->buf_rx_addr);
    ele->rid.remote_info->buf_msg_addr = ntohll(ele->rid.recv_buf->buf_msg_addr);
    ele->rid.remote_info->rx_buf_size = ntohl(ele->rid.recv_buf->rx_buf_size);
    ele->rid.remote_info->rkey_msg = ntohl(ele->rid.recv_buf->rkey_msg);
    ele->rid.remote_info->rkey_rx = ntohl(ele->rid.recv_buf->rkey_rx);
    ele->rid.remote_info->flag = ele->rid.recv_buf->flag;
}

static int dsm_send_info(struct conn_element *ele)
{
    struct rdma_info_data *rid = &ele->rid;

    rid->send_sge.addr = rid->send_dma.addr;
    rid->send_sge.length = rid->send_dma.size;
    rid->send_sge.lkey = ele->mr->lkey;

    rid->send_wr.next = NULL;
    rid->send_wr.wr_id = 0;
    rid->send_wr.sg_list = &rid->send_sge;
    rid->send_wr.num_sge = 1;
    rid->send_wr.opcode = IB_WR_SEND;
    rid->send_wr.send_flags = IB_SEND_SIGNALED;
    printk(">[dsm_send_info] - sending info\n");
    return ib_post_send(ele->cm_id->qp, &rid->send_wr, &rid->send_bad_wr);
}

static int dsm_recv_info(struct conn_element *ele)
{
    struct rdma_info_data *rid = &ele->rid;

    rid->recv_sge.addr = rid->recv_dma.addr;
    rid->recv_sge.length = rid->recv_dma.size;
    rid->recv_sge.lkey = ele->mr->lkey;

    rid->recv_wr.next = NULL;
    rid->recv_wr.wr_id = 0; // DSM2: unique id - address of data_struct
    rid->recv_wr.num_sge = 1;
    rid->recv_wr.sg_list = &rid->recv_sge;

    return ib_post_recv(ele->cm_id->qp, &rid->recv_wr, &rid->recv_bad_wr);
}

static int setup_recv_wr(struct conn_element *ele)
{
    int i;
    struct rx_buf_ele *rx = ele->rx_buffer.rx_buf;

    if (unlikely(!rx))
        return -1;

    /* last rx elm reserved for initial info exchange */
    for (i = 0; i < ele->rx_buffer.len - 1; ++i) {
        if (refill_recv_wr(ele, &rx[i]))
            return -1;
    }
    return 0;
}

static int exchange_info(struct conn_element *ele, int id)
{
    int flag = (int) ele->rid.remote_info->flag;
    int ret = 0;
    struct conn_element * ele_found;

    BUG_ON(!ele);

    if (unlikely(!ele->rid.recv_buf))
        goto err;
    flag = (int) ele->rid.remote_info->flag;

    switch (flag) {
        case RDMA_INFO_CL: {
            ele->rid.send_buf->flag = RDMA_INFO_SV;
            goto recv_send;
        }
        case RDMA_INFO_SV: {
            ret = dsm_recv_info(ele);
            if (ret) {
                dsm_printk("could not post the receive work request");
                goto err;
            }
            ele->rid.send_buf->flag = RDMA_INFO_READY_CL;
            ret = setup_recv_wr(ele);
            goto send;
        }
        case RDMA_INFO_READY_CL: {
            ele->rid.send_buf->flag = RDMA_INFO_READY_SV;
            ret = setup_recv_wr(ele);
            refill_recv_wr(ele, &ele->rx_buffer.rx_buf[ele->rx_buffer.len - 1]);
            ele->rid.remote_info->flag = RDMA_INFO_NULL;

            ele->remote_node_ip = (u32) ele->rid.remote_info->node_ip;
            ele->remote.sin_addr.s_addr = (u32) ele->rid.remote_info->node_ip;
            ele->local = get_dsm_module_state()->rcm->sin;
            ele_found = search_rb_conn(ele->remote_node_ip);

            if (ele_found) {
                if (ele->remote_node_ip !=
                        get_dsm_module_state()->rcm->node_ip) {
                    char curr[20], prev[20];

                    inet_ntoa(ele->remote_node_ip, curr, sizeof curr);
                    inet_ntoa(ele_found->remote_node_ip, prev, sizeof prev);
                    dsm_printk("destroy_connection duplicate: %s former: %s",
                            curr, prev);
                    rdma_disconnect(ele->cm_id);
                } else {
                    dsm_printk("loopback, lets hope for the best");
                }
                erase_rb_conn(ele);
            } else {
                char curr[20];

                complete(&ele->completion);
                insert_rb_conn(ele);
                inet_ntoa(ele->remote_node_ip, curr, sizeof curr);
                dsm_printk("inserted conn_element to rb_tree: %s", curr);
            }
            goto send;

        }
        case RDMA_INFO_READY_SV: {
            refill_recv_wr(ele, &ele->rx_buffer.rx_buf[ele->rx_buffer.len - 1]);
            ele->rid.remote_info->flag = RDMA_INFO_NULL;
            //Server acknowledged --> connection is complete.
            //start sending messages.
            complete(&ele->completion);
            goto out;
        }
        default: {
            dsm_printk(KERN_ERR "unknown RDMA info flag");
            goto out;
        }
    }

recv_send:
    ret = dsm_recv_info(ele);
    if (ret < 0) {
        dsm_printk(KERN_ERR "could not post the receive work request");
        goto err;
    }

send:
    ret = dsm_send_info(ele);
    if (ret < 0) {
        dsm_printk(KERN_ERR "could not post the send work request");
        goto err;
    }

out:
    return ret;

err:
    dsm_printk(KERN_ERR "no receive info");
    return ret;
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

static void send_cq_handle_work(struct work_struct *work)
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

static void recv_cq_handle_work(struct work_struct *work)
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

static void send_cq_handle(struct ib_cq *cq, void *cq_context)
{
    queue_send_work((struct conn_element *) cq->cq_context);
}

static void recv_cq_handle(struct ib_cq *cq, void *cq_context)
{
    queue_recv_work((struct conn_element *) cq->cq_context);
}

static int connect_client(struct rdma_cm_id *id)
{
    int r;
    struct rdma_conn_param param;

    memset(&param, 0, sizeof(struct rdma_conn_param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = 10;

    r = rdma_connect(id, &param);
    if (r)
        printk(">[connect_client] - rdma_connect failed : %d\n", r);

    return r;
}

static inline void setup_IB_attr(struct ib_qp_init_attr *attr,
        struct ib_device_attr dev_attr)
{
    attr->cap.max_send_wr = min(dev_attr.max_qp_wr, IB_MAX_CAP_SCQ);
    attr->cap.max_recv_wr = min(dev_attr.max_qp_wr, IB_MAX_CAP_RCQ);
    attr->cap.max_send_sge = min(dev_attr.max_sge, IB_MAX_SEND_SGE);
    attr->cap.max_recv_sge = min(dev_attr.max_sge, IB_MAX_RECV_SGE);
}

static inline void setup_IW_attr(struct ib_qp_init_attr *attr,
        struct ib_device_attr dev_attr)
{
    attr->cap.max_send_wr = min(dev_attr.max_qp_wr, IW_MAX_CAP_SCQ);
    attr->cap.max_recv_wr = min(dev_attr.max_qp_wr, IW_MAX_CAP_RCQ);
    attr->cap.max_send_sge = min(dev_attr.max_sge, IW_MAX_SEND_SGE);
    attr->cap.max_recv_sge = min(dev_attr.max_sge, IW_MAX_RECV_SGE);
}

static inline int setup_qp_attr(struct conn_element *ele)
{
    struct ib_qp_init_attr * attr = &ele->qp_attr;
    int ret = -1;
    struct ib_device_attr dev_attr;

    if (ib_query_device(ele->cm_id->device, &dev_attr)) {
        dsm_printk("Query device failed for %s\n", ele->cm_id->device->name);
        goto out;
    }
    attr->sq_sig_type = IB_SIGNAL_ALL_WR;
    attr->qp_type = IB_QPT_RC;
    attr->port_num = ele->cm_id->port_num;
    attr->qp_context = (void *) ele;
    switch (rdma_node_get_transport(ele->cm_id->device->node_type)) {
    case RDMA_TRANSPORT_IB:
        setup_IB_attr(attr, dev_attr);
        break;
    case RDMA_TRANSPORT_IWARP:
        setup_IW_attr(attr, dev_attr);
        break;
    default:
        return -1;
    }

    ret = 0;
out:
    return ret;
}

static int create_qp(struct conn_element *ele)
{
    int ret = -1;
    struct ib_qp_init_attr * attr;

    attr = &ele->qp_attr;

    if (unlikely(!ele->cm_id))
        goto exit;

    if (unlikely(!ele->pd))
        goto exit;

    ret = rdma_create_qp(ele->cm_id, ele->pd, attr);

exit:
    return ret;
}

static int setup_qp(struct conn_element *ele)
{
    int ret = 0;

    INIT_WORK(&ele->send_work, send_cq_handle_work);
    INIT_WORK(&ele->recv_work, recv_cq_handle_work);

    ele->qp_attr.send_cq = ib_create_cq(ele->cm_id->device, send_cq_handle,
            dsm_cq_event_handler, (void *) ele, ele->qp_attr.cap.max_send_wr, 0);
    if (IS_ERR(ele->qp_attr.send_cq)) {
        printk(">[setup_qp] - Cannot create cq\n");
        goto err1;
    }

    if (ib_req_notify_cq(ele->qp_attr.send_cq, IB_CQ_NEXT_COMP)) {
        printk(">[setup_qp] - Cannot notify cq\n");
        goto err2;
    }

    ele->qp_attr.recv_cq = ib_create_cq(ele->cm_id->device, recv_cq_handle,
            dsm_cq_event_handler, (void *) ele, ele->qp_attr.cap.max_recv_wr,0);
    if (IS_ERR(ele->qp_attr.recv_cq)) {
        printk(">[setup_qp] - Cannot create cq\n");
        goto err3;
    }

    if (ib_req_notify_cq(ele->qp_attr.recv_cq, IB_CQ_NEXT_COMP)) {
        printk(">[setup_qp] - Cannot notify cq\n");
        goto err4;
    }

    if (create_qp(ele)) {
        goto err5;
        printk(">[setup_qp] - QP not created --> Cancelled\n");
    }

    return ret;

    err5: ret++;
    err4: ret++;
    ib_destroy_cq(ele->qp_attr.recv_cq);
    err3: ret++;
    err2: ret++;
    ib_destroy_cq(ele->qp_attr.send_cq);
    err1: ret++;
    printk(">[setup_qp] - Could not setup the qp, error %d occurred\n", ret);
    return ret;
}

static void init_tx_wr(struct tx_buf_ele *tx_ele, u32 lkey, int id)
{
    BUG_ON(!tx_ele);
    BUG_ON(!tx_ele->wrk_req);
    BUG_ON(!tx_ele->wrk_req->wr_ele);

    tx_ele->wrk_req->wr_ele->wr.wr_id = (u64) id;
    tx_ele->wrk_req->wr_ele->wr.opcode = IB_WR_SEND;
    tx_ele->wrk_req->wr_ele->wr.send_flags = IB_SEND_SIGNALED;
    tx_ele->wrk_req->wr_ele->wr.num_sge = 1;
    tx_ele->wrk_req->wr_ele->wr.sg_list =
        (struct ib_sge *) &tx_ele->wrk_req->wr_ele->sg;

    tx_ele->wrk_req->wr_ele->sg.addr = tx_ele->dsm_dma.addr;
    tx_ele->wrk_req->wr_ele->sg.length = tx_ele->dsm_dma.size;
    tx_ele->wrk_req->wr_ele->sg.lkey = lkey;

    tx_ele->wrk_req->wr_ele->wr.next = NULL;
}

static void init_reply_wr(struct reply_work_request *rwr, u64 msg_addr,
        u32 lkey, int id)
{
    struct ib_sge *reply_sge;

    BUG_ON(!rwr);
    BUG_ON(!rwr->wr_ele);

    reply_sge = &rwr->wr_ele->sg;
    BUG_ON(!reply_sge);
    reply_sge->addr = msg_addr;
    reply_sge->length = sizeof(struct dsm_message);
    reply_sge->lkey = lkey;

    rwr->wr_ele->dsm_dma.addr = msg_addr;
    rwr->wr_ele->wr.next = NULL;
    rwr->wr_ele->wr.num_sge = 1;
    rwr->wr_ele->wr.send_flags = IB_SEND_SIGNALED;
    rwr->wr_ele->wr.opcode = IB_WR_SEND;
    rwr->wr_ele->wr.sg_list = (struct ib_sge *) &rwr->wr_ele->sg;
    rwr->wr_ele->wr.wr_id = id;
}

static void init_page_wr(struct reply_work_request *rwr, u32 lkey, int id)
{
    rwr->page_sgl.addr = 0;
    rwr->page_sgl.length = PAGE_SIZE;
    rwr->page_sgl.lkey = lkey;

    rwr->wr.next = &rwr->wr_ele->wr;
    rwr->wr.sg_list = (struct ib_sge *) &rwr->page_sgl;
    rwr->wr.send_flags = IB_SEND_SIGNALED;
    rwr->wr.opcode = IB_WR_RDMA_WRITE;
    rwr->wr.num_sge = 1;
    rwr->wr.wr_id = id;
}

static void init_tx_ele(struct tx_buf_ele *tx_ele, struct conn_element *ele,
        int id)
{
    BUG_ON(!tx_ele);
    tx_ele->id = id;
    init_tx_wr(tx_ele, ele->mr->lkey, tx_ele->id);
    init_reply_wr(tx_ele->reply_work_req, tx_ele->dsm_dma.addr, ele->mr->lkey,
            tx_ele->id);
    BUG_ON(!ele->mr);
    init_page_wr(tx_ele->reply_work_req, ele->mr->lkey, tx_ele->id);
    tx_ele->dsm_buf->dest_id = ele->mr->rkey;
    tx_ele->dsm_buf->offset = tx_ele->id;
}

static void destroy_tx_buffer(struct conn_element *ele)
{
    int i;
    struct tx_buf_ele *tx_buf = ele->tx_buffer.tx_buf;

    if (!tx_buf)
        return;
    cancel_work_sync(&ele->delayed_request_flush_work);

    for (i = 0; i < ele->tx_buffer.len; ++i) {
        if (tx_buf[i].dsm_dma.addr) {
            ib_dma_unmap_single(ele->cm_id->device, tx_buf[i].dsm_dma.addr,
                    tx_buf[i].dsm_dma.size, tx_buf[i].dsm_dma.dir);
        }
        kfree(tx_buf[i].dsm_buf);
        kfree(tx_buf[i].wrk_req->wr_ele);
        kfree(tx_buf[i].wrk_req);
    }

    kfree(tx_buf);
    ele->tx_buffer.tx_buf = 0;
}

static void destroy_rx_buffer(struct conn_element *ele)
{
    int i;
    struct rx_buf_ele *rx = ele->rx_buffer.rx_buf;

    if (!rx)
        return;

    for (i = 0; i < ele->rx_buffer.len; ++i) {
        if (rx[i].dsm_dma.addr) {
            ib_dma_unmap_single(ele->cm_id->device, rx[i].dsm_dma.addr,
                    rx[i].dsm_dma.size, rx[i].dsm_dma.dir);
        }
        kfree(rx[i].dsm_buf);
        kfree(rx[i].recv_wrk_rq_ele);
    }
    kfree(rx);
    ele->rx_buffer.rx_buf = 0;
}

static int create_tx_buffer(struct conn_element *ele)
{
    int i, ret = 0;
    struct tx_buf_ele *tx_buff_e;

    BUG_ON(!ele);
    BUG_ON(IS_ERR(ele->cm_id));
    BUG_ON(!ele->cm_id->device);
    might_sleep();

    ele->tx_buffer.len = get_nb_tx_buff_elements(ele);
    tx_buff_e = kzalloc((sizeof(struct tx_buf_ele) * ele->tx_buffer.len),
            GFP_KERNEL);
    if (unlikely(!tx_buff_e)) {
        dsm_printk(KERN_ERR "Can't allocate memory");
        return -ENOMEM;
    }
    ele->tx_buffer.tx_buf = tx_buff_e;

    for (i = 0; i < ele->tx_buffer.len; ++i) {
        tx_buff_e[i].dsm_buf = kzalloc(sizeof(struct dsm_message), GFP_KERNEL);
        if (!tx_buff_e[i].dsm_buf) {
            dsm_printk(KERN_ERR "Failed to allocate .dsm_buf");
            ret = -ENOMEM;
            goto err;
        }

        tx_buff_e[i].dsm_dma.dir = DMA_TO_DEVICE;
        tx_buff_e[i].dsm_dma.size = sizeof(struct dsm_message);
        tx_buff_e[i].dsm_dma.addr = ib_dma_map_single(ele->cm_id->device,
                tx_buff_e[i].dsm_buf, tx_buff_e[i].dsm_dma.size,
                tx_buff_e[i].dsm_dma.dir);
        if (unlikely(!tx_buff_e[i].dsm_dma.addr)) {
            dsm_printk(KERN_ERR "unable to create ib mapping");
            ret = -EFAULT;
            goto err;
        }

        tx_buff_e[i].wrk_req = kzalloc(sizeof(struct msg_work_request),
                GFP_KERNEL);
        if (!tx_buff_e[i].wrk_req) {
            dsm_printk(KERN_ERR "Failed to allocate wrk_req");
            ret = -ENOMEM;
            goto err;
        }

        tx_buff_e[i].wrk_req->wr_ele = kzalloc(sizeof(struct work_request_ele),
                GFP_KERNEL);
        if (!tx_buff_e[i].wrk_req->wr_ele) {
            dsm_printk(KERN_ERR "Failed to allocate wrk_req->wr_ele");
            ret = -ENOMEM;
            goto err;
        }
        tx_buff_e[i].wrk_req->wr_ele->dsm_dma = tx_buff_e[i].dsm_dma;

        tx_buff_e[i].reply_work_req = kzalloc(sizeof(struct reply_work_request),
                GFP_KERNEL);
        if (!tx_buff_e[i].reply_work_req) {
            dsm_printk(KERN_ERR "Failed to allocate reply_work_req");
            ret = -ENOMEM;
            goto err;
        }

        tx_buff_e[i].reply_work_req->wr_ele = kzalloc(
                sizeof(struct work_request_ele), GFP_KERNEL);
        if (!tx_buff_e[i].reply_work_req->wr_ele) {
            dsm_printk(KERN_ERR "Failed to allocate reply_work_req->wr_ele");
            ret = -ENOMEM;
            goto err;
        }
        init_tx_ele(&tx_buff_e[i], ele, i);
    }
    goto done;

    err:
    BUG_ON(!tx_buff_e);
    destroy_tx_buffer(ele);
    kfree(tx_buff_e);
    done: return ret;
}

static void init_rx_ele(struct rx_buf_ele *rx_ele, struct conn_element *ele)
{
    struct recv_work_req_ele *rwr = rx_ele->recv_wrk_rq_ele;
    struct ib_sge *recv_sge = &rwr->recv_sgl;

    recv_sge->addr = rx_ele->dsm_dma.addr;
    recv_sge->length = rx_ele->dsm_dma.size;
    recv_sge->lkey = ele->mr->lkey;

    rwr->sq_wr.next = NULL;
    rwr->sq_wr.num_sge = 1;
    rwr->sq_wr.sg_list = &rwr->recv_sgl;
    rwr->sq_wr.wr_id = rx_ele->id;
}

static int create_rx_buffer(struct conn_element *ele)
{
    int i;
    int undo = 0;
    struct rx_buf_ele *rx;

    ele->rx_buffer.len = get_nb_rx_buff_elements(ele);
    rx = kzalloc((sizeof(struct rx_buf_ele) * ele->rx_buffer.len), GFP_KERNEL);
    if (!rx)
        goto err_buf;
    ele->rx_buffer.rx_buf = rx;

    for (i = 0; i < ele->rx_buffer.len; ++i) {
        rx[i].dsm_buf = kzalloc(sizeof(struct dsm_message), GFP_KERNEL);
        if (!rx[i].dsm_buf)
            goto err1;

        rx[i].dsm_dma.size = sizeof(struct dsm_message);
        rx[i].dsm_dma.dir = DMA_BIDIRECTIONAL;
        rx[i].dsm_dma.addr = ib_dma_map_single(ele->cm_id->device,
                rx[i].dsm_buf, rx[i].dsm_dma.size, rx[i].dsm_dma.dir);
        if (!rx[i].dsm_dma.addr)
            goto err2;

        rx[i].recv_wrk_rq_ele = kzalloc(sizeof(struct recv_work_req_ele),
                GFP_KERNEL);
        if (!rx[i].recv_wrk_rq_ele)
            goto err3;

        rx[i].id = i;
        init_rx_ele(&rx[i], ele);
    }

    return 0;

err3:
    ib_dma_unmap_single(ele->cm_id->device, rx[i].dsm_dma.addr,
            rx[i].dsm_dma.size, rx[i].dsm_dma.dir);
err2:
    kfree(rx[i].dsm_buf);
err1:
    for (undo = 0; undo < i; ++undo) {
        ib_dma_unmap_single(ele->cm_id->device, rx[undo].dsm_dma.addr,
                rx[undo].dsm_dma.size, rx[undo].dsm_dma.dir);
        kfree(rx[undo].dsm_buf);
        kfree(rx[undo].recv_wrk_rq_ele);
    }
    kfree(rx);
    ele->rx_buffer.rx_buf = 0;
err_buf:
    printk(">[create_rx_buffer] - RX BUFFER NOT CREATED\n");
    return -1;
}

static void format_rdma_info(struct conn_element *ele)
{
    ele->rid.send_buf->node_ip = htonl(ele->rcm->node_ip);
    ele->rid.send_buf->buf_rx_addr = htonll((u64) ele->rx_buffer.rx_buf);
    ele->rid.send_buf->buf_msg_addr = htonll((u64) ele->tx_buffer.tx_buf);
    ele->rid.send_buf->rx_buf_size = htonl(ele->rx_buffer.len);
    ele->rid.send_buf->rkey_msg = htonl(ele->mr->rkey);
    ele->rid.send_buf->rkey_rx = htonl(ele->mr->rkey);
    ele->rid.send_buf->flag = RDMA_INFO_CL;
}

static int create_rdma_info(struct conn_element *ele)
{
    int size = sizeof(struct rdma_info);
    struct rdma_info_data *rid = &ele->rid;

    rid->send_buf = kzalloc(size, GFP_KERNEL);
    if (unlikely(!rid->send_buf))
        goto send_mem_err;

    rid->send_dma.size = size;
    rid->send_dma.dir = DMA_TO_DEVICE;
    rid->send_dma.addr = ib_dma_map_single(ele->cm_id->device, rid->send_buf,
            rid->send_dma.size, rid->send_dma.dir);
    if (unlikely(!rid->send_dma.addr))
        goto send_info_err;

    rid->recv_buf = kzalloc(size, GFP_KERNEL);
    if (unlikely(!rid->recv_buf))
        goto recv_mem_err;

    rid->recv_dma.size = size;
    rid->recv_dma.dir = DMA_FROM_DEVICE;
    rid->recv_dma.addr = ib_dma_map_single(ele->cm_id->device, rid->recv_buf,
            rid->recv_dma.size, rid->recv_dma.dir);
    if (unlikely(!rid->send_dma.addr))
        goto recv_info_err;

    rid->remote_info = kzalloc(size, GFP_KERNEL);
    if (unlikely(!rid->remote_info))
        goto remote_info_buffer_err;

    rid->remote_info->flag = RDMA_INFO_CL;
    rid->exchanged = 2;
    format_rdma_info(ele);
    return 0;

    remote_info_buffer_err: printk(
            ">[create_rdma_info] - ERROR : NO REMOTE INFO BUFFER\n");
    ib_dma_unmap_single(ele->cm_id->device, rid->recv_dma.addr,
            rid->recv_dma.size, rid->recv_dma.dir);

    recv_info_err: printk(
            ">[create_rdma_info] - ERROR : NO RECV INFO BUFFER\n");
    kfree(rid->recv_buf);

    recv_mem_err: printk(
            ">[create_rdma_info] - no memory allocated for the reception buffer\n");
    ib_dma_unmap_single(ele->cm_id->device, rid->send_dma.addr,
            rid->send_dma.size, rid->send_dma.dir);

    send_info_err: printk(
            ">[create_rdma_info] - ERROR : NO SEND INFO BUFFER\n");
    kfree(rid->send_buf);

    send_mem_err: printk(
            ">[create_rdma_info] - no memory allocated for the sending buffer\n");
    return -1;
}

static int init_tx_lists(struct conn_element *ele)
{
    int i;
    struct tx_buffer *tx = &ele->tx_buffer;
    int max_tx_send = ele->tx_buffer.len / 3;

    tx->request_queue_sz = 0;
    init_llist_head(&tx->request_queue);
    init_llist_head(&tx->tx_free_elements_list);
    init_llist_head(&tx->tx_free_elements_list_reply);
    spin_lock_init(&tx->tx_free_elements_list_lock);
    spin_lock_init(&tx->tx_free_elements_list_reply_lock);
    INIT_LIST_HEAD(&tx->ordered_request_queue);
    mutex_init(&tx->flush_mutex);
    INIT_WORK(&ele->delayed_request_flush_work, delayed_request_flush_work_fn);

    for (i = 0; i < max_tx_send; ++i)
        release_tx_element(ele, &tx->tx_buf[i]);

    for (; i < ele->tx_buffer.len; ++i)
        release_tx_element_reply(ele, &tx->tx_buf[i]);

    return 0;
}

static int setup_connection(struct conn_element *ele, int type)
{
    int ret = 0, err = 0;
    struct rdma_conn_param conn_param;

    ele->pd = ib_alloc_pd(ele->cm_id->device);
    if (!ele->pd)
        goto err1;
    ele->mr = ib_get_dma_mr(ele->pd,
            IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
    if (!ele->mr)
        goto err2;
    if (setup_qp_attr(ele))
        goto err3;
    if (setup_qp(ele))
        goto err4;
    if (create_tx_buffer(ele))
        goto err5;
    if (create_rx_buffer(ele))
        goto err6;
    if (dsm_init_page_pool(ele))
        goto err7;
    if (create_rdma_info(ele))
        goto err8;
    if (init_tx_lists(ele))
        goto err9;

    if (type) {
        dsm_recv_info(ele);

        memset(&conn_param, 0, sizeof(struct rdma_conn_param));
        conn_param.responder_resources = 1;
        conn_param.initiator_depth = 1;

        if (rdma_accept(ele->cm_id, &conn_param))
            goto err10;
    }

    return ret;

    err10: err++;
    err9: err++;
    err8: err++;
    err7: err++;
    err6: err++;
    err5: err++;
    err4: err++;
    err3: err++;
    err2: err++;
    err1: err++;
    printk(">[setup_connection] - Could not setup connection: error %d\n", err);
    return err;
}

static int client_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *ev)
{
    int ret = 0, err = 0;
    struct conn_element *ele = id->context;

    switch (ev->event) {
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
            dsm_printk(KERN_ERR, "could not connect, %d\n", ev->event);
            complete(&ele->completion);
            break;

        case RDMA_CM_EVENT_DEVICE_REMOVAL:
        case RDMA_CM_EVENT_ADDR_CHANGE:
            dsm_printk(KERN_ERR "unexpected event: %d", ev->event);
            ret = rdma_disconnect(id);
            if (unlikely(ret))
                goto disconnect_err;
            break;

        default:
            dsm_printk(KERN_ERR "no special handling: %d", ev->event);
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

int server_event_handler(struct rdma_cm_id *id, struct rdma_cm_event *ev)
{
    int ret = 0;
    struct conn_element *ele = 0;
    struct rcm *rcm;

    switch (ev->event) {
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
                dsm_printk(KERN_ERR "setup_connection failed: %d", ret);
                goto err;
            }

            ret = create_conn_sysfs_entry(ele);
            if (ret) {
                dsm_printk(KERN_ERR "create_conn_sysfs_entry failed: %d",
                    ret);
                goto err;
            }

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
            dsm_printk(KERN_ERR "unexpected event: %d", ev->event);

            ret = rdma_disconnect(id);
            if (unlikely(ret))
                goto disconnect_err;
            break;

        default:
            dsm_printk(KERN_ERR "no special handling: %d", ev->event);
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

inline void dsm_msg_cpy(struct dsm_message *dst, struct dsm_message *orig)
{
    dst->dsm_id = orig->dsm_id;
    dst->src_id = orig->src_id;
    dst->dest_id = orig->dest_id;
    dst->type = orig->type;
    dst->offset = orig->offset;
    dst->req_addr = orig->req_addr;
    dst->dst_addr = orig->dst_addr;
    dst->rkey = orig->rkey;
}

static void free_rdma_info(struct conn_element *ele)
{
    if (ele->rid.send_dma.addr) {
        ib_dma_unmap_single(ele->cm_id->device, ele->rid.send_dma.addr,
                ele->rid.send_dma.size, ele->rid.send_dma.dir);
        kfree(ele->rid.send_buf);
    }

    if (ele->rid.recv_dma.addr) {
        ib_dma_unmap_single(ele->cm_id->device, ele->rid.recv_dma.addr,
                ele->rid.recv_dma.size, ele->rid.recv_dma.dir);
        kfree(ele->rid.recv_buf);
    }

    if (ele->rid.remote_info) {
        kfree(ele->rid.remote_info);
    }

    memset(&ele->rid, 0, sizeof(struct rdma_info_data));
}

void release_tx_element(struct conn_element *ele, struct tx_buf_ele *tx_e)
{
    struct tx_buffer *tx = &ele->tx_buffer;
    atomic_set(&tx_e->used, 0);
    atomic_set(&tx_e->released, 0);
    llist_add(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list);
}

void release_tx_element_reply(struct conn_element *ele, struct tx_buf_ele *tx_e)
{
    struct tx_buffer *tx = &ele->tx_buffer;
    atomic_set(&tx_e->used, 0);
    atomic_set(&tx_e->released, 0);
    llist_add(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list_reply);
}

void try_release_tx_element(struct conn_element *ele, struct tx_buf_ele *tx_e)
{
    if (atomic_add_return(1, &tx_e->released) == 2)
        release_tx_element(ele, tx_e);
}

static int create_connection(struct rcm *rcm, unsigned long ip,
	unsigned short port)
{
    struct rdma_conn_param param;
    struct conn_element *ele;

    ele = vzalloc(sizeof(struct conn_element));
    if (unlikely(!ele))
        goto err;

    memset(&param, 0, sizeof(struct rdma_conn_param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = 10;

    ele->local.sin_family = AF_INET;
    ele->local.sin_addr.s_addr = rcm->sin.sin_addr.s_addr;
    ele->local.sin_port = 0;

    ele->remote.sin_family = AF_INET;
    ele->remote.sin_addr.s_addr = ip;
    ele->remote.sin_port = port;

    init_completion(&ele->completion);
    ele->remote_node_ip = ip;
    insert_rb_conn(ele);

    ele->rcm = rcm;
    ele->cm_id = rdma_create_id(client_event_handler, ele, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(ele->cm_id))
        goto err1;

    if (create_conn_sysfs_entry(ele)) {
        dsm_printk(KERN_ERR "create_conn_sysfs_entry failed");
        goto err1;
    }

    return rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &ele->local,
            (struct sockaddr*) &ele->remote, 2000);

    err1: erase_rb_conn(ele);
    vfree(ele);
    err: return -1;
}

int connect_svm(__u32 dsm_id, __u32 svm_id, unsigned long ip_addr,
	unsigned short port)
{
    int r = 0;
    struct dsm *dsm;
    struct subvirtual_machine *svm;
    struct conn_element *cele;
    struct dsm_module_state *dsm_state = get_dsm_module_state();

    dsm = find_dsm(dsm_id);
    if (!dsm) {
        dsm_printk(KERN_ERR "can't find dsm %d", dsm_id);
        return -EFAULT;
    }

    dsm_printk(KERN_ERR "connecting to dsm_id: %u [0x%p], svm_id: %u",
        dsm_id, dsm, svm_id);

    mutex_lock(&dsm->dsm_mutex);
    svm = find_svm(dsm, svm_id);
    if (!svm) {
        dsm_printk(KERN_ERR "can't find svm %d", svm_id);
        goto no_svm;
    }

    cele = search_rb_conn(ip_addr);
    if (cele) {
        dsm_printk(KERN_ERR "has existing connection to %pI4", &ip_addr);
        /* BUG_ON(svm->ele != cele); */
        goto done;
    }

    r = create_connection(dsm_state->rcm, ip_addr, port);
    if (r) {
        dsm_printk(KERN_ERR "create_connection failed %d", r);
        goto failed;
    }

    might_sleep();
    cele = search_rb_conn(ip_addr);
    if (!cele) {
        dsm_printk(KERN_ERR "conneciton does not exist", r);
        r = -ENOLINK;
        goto failed;
    }

    wait_for_completion(&cele->completion);
    if (!atomic_read(&cele->alive)) {
        dsm_printk(KERN_ERR "conneciton is not alive ... aborting");
        r = -ENOLINK;
        goto failed;
    }

done:
    svm->ele = cele;

failed:
    release_svm(svm);
no_svm:
    mutex_unlock(&dsm->dsm_mutex);
    dsm_printk(KERN_INFO "dsm %d svm %d svm_connect ip %pI4: %d",
        dsm_id, svm_id, &ip_addr, r);
    return r;
}

struct tx_buf_ele *try_get_next_empty_tx_ele(struct conn_element *ele)
{
    struct tx_buf_ele *tx_e = NULL;
    struct llist_node *llnode;

    spin_lock(&ele->tx_buffer.tx_free_elements_list_lock);
    llnode = llist_del_first(&ele->tx_buffer.tx_free_elements_list);
    spin_unlock(&ele->tx_buffer.tx_free_elements_list_lock);

    if (llnode) {
        tx_e = container_of(llnode, struct tx_buf_ele, tx_buf_ele_ptr);
        atomic_set(&tx_e->used, 1);
    }
    return tx_e;
}

struct tx_buf_ele *try_get_next_empty_tx_reply_ele(struct conn_element *ele)
{
    struct tx_buf_ele *tx_e = NULL;
    struct llist_node *llnode;

    spin_lock(&ele->tx_buffer.tx_free_elements_list_reply_lock);
    llnode = llist_del_first(&ele->tx_buffer.tx_free_elements_list_reply);
    spin_unlock(&ele->tx_buffer.tx_free_elements_list_reply_lock);

    if (llnode) {
        tx_e = container_of(llnode, struct tx_buf_ele, tx_buf_ele_ptr);
        atomic_set(&tx_e->used, 1);
    }
    return tx_e;
}

static void remove_svms_for_conn(struct conn_element *ele)
{
    struct dsm *dsm;
    struct subvirtual_machine *svm;
    struct list_head *pos, *n, *it;

    list_for_each (pos, &get_dsm_module_state()->dsm_list) {
        dsm = list_entry(pos, struct dsm, dsm_ptr);
        list_for_each_safe (it, n, &dsm->svm_list) {
            svm = list_entry(it, struct subvirtual_machine, svm_ptr);
            if (svm->ele == ele)
                remove_svm(dsm->dsm_id, svm->svm_id);
        }
    }
}

int destroy_connection(struct conn_element *ele)
{
    int ret = 0;

    remove_svms_for_conn(ele);

    if (likely(ele->cm_id)) {
        synchronize_rcu();
        cancel_work_sync(&ele->recv_work);
        cancel_work_sync(&ele->send_work);

        if (likely(ele->cm_id->qp))
            ret |= ib_destroy_qp(ele->cm_id->qp);

        if (likely(ele->qp_attr.send_cq))
            ret |= ib_destroy_cq(ele->qp_attr.send_cq);

        if (likely(ele->qp_attr.recv_cq))
            ret |= ib_destroy_cq(ele->qp_attr.recv_cq);

        if (likely(ele->mr))
            ret |= ib_dereg_mr(ele->mr);

        if (likely(ele->pd))
            ret |= ib_dealloc_pd(ele->pd);

        destroy_rx_buffer(ele);
        destroy_tx_buffer(ele);
        free_rdma_info(ele);
        rdma_destroy_id(ele->cm_id);
    }

    dsm_destroy_page_pool(ele);

    erase_rb_conn(ele);
    delete_conn_sysfs_entry(ele);
    vfree(ele);

    return ret;
}

/*
 * Can either fail with:
 *  > -ENOMEM - in which case we sleep and let ib work thread finish.
 *  > -ENOTCONN - meaning the connection has been disrupted; we handle this
 *                in destroy_connection.
 *  > -EINVAL (or other) - we sent wrong output, shouldn't happen.
 *
 */
int tx_dsm_send(struct conn_element *ele, struct tx_buf_ele *tx_e)
{
    int ret;
    int type = tx_e->dsm_buf->type;

retry:
    switch (type) {
        case REQUEST_PAGE:
        case REQUEST_PAGE_PULL:
        case CLAIM_PAGE:
        case TRY_REQUEST_PAGE:
        case SVM_STATUS_UPDATE:
        case PAGE_REQUEST_REDIRECT:
        case PAGE_REQUEST_FAIL:
        case ACK:
            ret = ib_post_send(ele->cm_id->qp, &tx_e->wrk_req->wr_ele->wr,
                    &tx_e->wrk_req->wr_ele->bad_wr);
            break;
        case PAGE_REQUEST_REPLY:
            ret = ib_post_send(ele->cm_id->qp, &tx_e->reply_work_req->wr,
                    &tx_e->reply_work_req->wr_ele->bad_wr);
            break;
        default:
            BUG();
    }

    /*
     * we have no other choice but to postpone and try again (no memory for a
     * queued request). this should happen mainly with softiwarp.
     */
    if (unlikely(ret == -ENOMEM)) {
        cond_resched();
        goto retry;
    }

    if (ret && ret != -ENOTCONN) {
        dsm_printk("ib_post_send() returned %d on type 0x%x", ret, type);
        BUG();
    }
    return ret;
}

