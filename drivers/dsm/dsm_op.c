/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

#include <linux/list.h>
#include <dsm/dsm_module.h>

int get_nb_tx_buff_elements(struct conn_element *ele) {

    return ele->qp_attr.cap.max_send_wr >> 1;

}

int get_nb_rx_buff_elements(struct conn_element *ele) {

    return ele->qp_attr.cap.max_recv_wr;

}

int get_page_pool_size(struct conn_element *ele) {

    return (get_nb_rx_buff_elements(ele) + get_nb_tx_buff_elements(ele)) << 1;

}

int get_max_pushed_reqs(struct conn_element *ele) {

    return get_nb_tx_buff_elements(ele) << 2;
}

static int rcm_disconnect(struct rcm *rcm) {
    struct rb_root *root = &rcm->root_conn;
    struct rb_node *node, *next;
    struct conn_element *ele;

    for (node = rb_first(root); node; node = next) {
        ele = rb_entry(node, struct conn_element, rb_node);
        next = rb_next(node);
        if (atomic_cmpxchg(&ele->alive, 1, 0)) {
            rdma_disconnect(ele->cm_id);
            destroy_connection(ele);
        }
    }

    while (rb_first(root))
        ;

    return 0;
}

static void destroy_tx_buffer(struct conn_element *ele) {
    int i;
    struct tx_buf_ele *tx_buf = ele->tx_buffer.tx_buf;

    if (!tx_buf)
        return;
    cancel_work_sync(&ele->delayed_request_flush_work);

    for (i = 0; i < get_nb_tx_buff_elements(ele); ++i) {
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

static void destroy_rx_buffer(struct conn_element *ele) {
    int i;
    struct rx_buf_ele *rx = ele->rx_buffer.rx_buf;

    if (!rx)
        return;

    for (i = 0; i < get_nb_rx_buff_elements(ele); ++i) {
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

static void free_rdma_info(struct conn_element *ele) {
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

static void init_rx_ele(struct rx_buf_ele *rx_ele, struct conn_element *ele) {
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

/**
 * Buffer that catches the incoming messages and sends the response.
 * Also catches the responses from server.
 * one for each connection
 *
 * EACH element contains:
 *              a dsm_message
 *              a receive work request linked to the message buffer
 *              a page work request that WRITES the page onto the remote memory
 *              a send work request that SENDS the exact same message, to notify that the page is transferred.
 * The message wr is linked to the page wr and it's sent right after it.
 *
 * RETURN 0 if success,
 *               -1 if failure.
 */
static int create_rx_buffer(struct conn_element *ele) {
    int i;
    int undo = 0;
    struct rx_buf_ele *rx = kzalloc(
            (sizeof(struct rx_buf_ele) * get_nb_tx_buff_elements(ele)),
            GFP_KERNEL);

    if (!rx)
        goto err_buf;

    ele->rx_buffer.rx_buf = rx;

    for (i = 0; i < get_nb_tx_buff_elements(ele); ++i) {
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

    err3: ib_dma_unmap_single(ele->cm_id->device, rx[i].dsm_dma.addr,
            rx[i].dsm_dma.size, rx[i].dsm_dma.dir);
    err2: kfree(rx[i].dsm_buf);
    err1: for (undo = 0; undo < i; ++undo) {
        ib_dma_unmap_single(ele->cm_id->device, rx[undo].dsm_dma.addr,
                rx[undo].dsm_dma.size, rx[undo].dsm_dma.dir);
        kfree(rx[undo].dsm_buf);
        kfree(rx[undo].recv_wrk_rq_ele);
    }
    memset(rx, 0, sizeof(struct rx_buf_ele) * get_nb_tx_buff_elements(ele));
    kfree(rx);
    ele->rx_buffer.rx_buf = 0;
    err_buf: printk(">[create_rx_buffer] - RX BUFFER NOT CREATED\n");
    return -1;
}

static inline void  setup_IB_attr(struct ib_qp_init_attr * attr,
        struct ib_device_attr dev_attr) {
    attr->cap.max_send_wr = min(dev_attr.max_qp_wr, IB_MAX_CAP_SCQ);
    attr->cap.max_recv_wr = min(dev_attr.max_qp_wr, IB_MAX_CAP_RCQ);
    attr->cap.max_send_sge = min(dev_attr.max_sge, IB_MAX_SEND_SGE);
    attr->cap.max_recv_sge = min(dev_attr.max_sge, IB_MAX_RECV_SGE);

}

static inline void  setup_IW_attr(struct ib_qp_init_attr * attr,
        struct ib_device_attr dev_attr) {
    attr->cap.max_send_wr = min(dev_attr.max_qp_wr, IW_MAX_CAP_SCQ);
    attr->cap.max_recv_wr = min(dev_attr.max_qp_wr, IW_MAX_CAP_RCQ);
    attr->cap.max_send_sge = min(dev_attr.max_sge, IW_MAX_SEND_SGE);
    attr->cap.max_recv_sge = min(dev_attr.max_sge, IW_MAX_RECV_SGE);
}

static inline int setup_qp_attr(struct conn_element *ele) {
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
    if (ele->cm_id->device->node_type == RDMA_NODE_RNIC)
        setup_IW_attr(attr, dev_attr);
    else
        setup_IB_attr(attr, dev_attr);

    ret = 0;
    out: return ret;

}

/*
 * Creates the qp and links it to the two cq
 *
 * RETURN 0 if success,
 *               -1 if failure.
 */
static int create_qp(struct conn_element *ele) {
    int ret = -1;
    struct ib_qp_init_attr * attr;

    attr = &ele->qp_attr;

    if (unlikely(!ele->cm_id))
        goto exit;

    if (unlikely(!ele->pd))
        goto exit;

    ret = rdma_create_qp(ele->cm_id, ele->pd, attr);

    exit: return ret;
}

/*
 * Before creating the qp, creates two cq, one for the sending and one for the receiving.
 * Then links those cq to the qp
 *
 * RETURN 0 if success,
 *               -1 if failure.
 */
static int setup_qp(struct conn_element *ele) {
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
            dsm_cq_event_handler, (void *) ele, ele->qp_attr.cap.max_recv_wr, 0);
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

static void format_rdma_info(struct conn_element *ele) {

    ele->rid.send_buf->node_ip = htonl(ele->rcm->node_ip);
    ele->rid.send_buf->buf_rx_addr = htonll((u64) ele->rx_buffer.rx_buf);
    ele->rid.send_buf->buf_msg_addr = htonll((u64) ele->tx_buffer.tx_buf);
    ele->rid.send_buf->rx_buf_size = htonl(get_nb_tx_buff_elements(ele));
    ele->rid.send_buf->rkey_msg = htonl(ele->mr->rkey);
    ele->rid.send_buf->rkey_rx = htonl(ele->mr->rkey);
    ele->rid.send_buf->flag = RDMA_INFO_CL;
}

static int create_new_empty_page_pool_element(struct conn_element *ele) {
    struct page_pool *pp = &ele->page_pool;
    struct page_pool_ele *ppe;

    ppe = kmalloc(sizeof(struct page_pool_ele), GFP_ATOMIC);
    if (!ppe)
        return -1;
    memset(ppe, 0, sizeof(struct page_pool_ele));
    llist_add(&ppe->llnode, &pp->page_empty_pool_list);

    return 0;
}

static int create_page_pool(struct conn_element *ele) {
    int ret = 0;
    int i;
    struct page_pool * pp = &ele->page_pool;

    spin_lock_init(&pp->page_pool_empty_list_lock);

    init_llist_head(&pp->page_empty_pool_list);

    for (i = 0; i < get_page_pool_size(ele); i++) {
        ret = create_new_empty_page_pool_element(ele);
        if (ret)
            break;
    }
    return ret;
}

/**
 * To create the buffers for local and remote info used for RDMA exchange such as buffer addresses, keys and ip.
 * RETURN 0 in case of success,
 *               -1 in case of failure.
 */
static int create_rdma_info(struct conn_element *ele) {
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

static int init_tx_lists(struct conn_element *ele) {
    int i;
    struct tx_buffer *tx = &ele->tx_buffer;
    int max_tx_send = get_nb_tx_buff_elements(ele) / 3;
    int max_tx_reply = get_nb_tx_buff_elements(ele);

    tx->request_queue_sz = 0;
    init_llist_head(&tx->request_queue);
    init_llist_head(&tx->tx_free_elements_list);
    init_llist_head(&tx->tx_free_elements_list_reply);
    spin_lock_init(&tx->tx_free_elements_list_lock);
    spin_lock_init(&tx->tx_free_elements_list_reply_lock);
    INIT_LIST_HEAD(&tx->ordered_request_queue);
    mutex_init(&tx->flush_mutex);
    atomic_set(&ele->flushed,0);
    INIT_WORK(&ele->delayed_request_flush_work, delayed_request_flush_work_fn);

    for (i = 0; i < max_tx_send; ++i)
        release_tx_element(ele, &tx->tx_buf[i]);

    for (; i < max_tx_reply; ++i)
        release_tx_element_reply(ele, &tx->tx_buf[i]);

    return 0;
}

static void init_reply_wr(struct reply_work_request *rwr, u64 msg_addr,
        u32 lkey, int id) {
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

static void init_page_wr(struct reply_work_request *rwr, u32 lkey, int id) {
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

static void init_tx_wr(struct tx_buf_ele *tx_ele, u32 lkey, int id) {
    BUG_ON(!tx_ele);
    BUG_ON(!tx_ele->wrk_req);
    BUG_ON(!tx_ele->wrk_req->wr_ele);

    tx_ele->wrk_req->wr_ele->wr.wr_id = (u64) id;
    tx_ele->wrk_req->wr_ele->wr.opcode = IB_WR_SEND;
    tx_ele->wrk_req->wr_ele->wr.send_flags = IB_SEND_SIGNALED;
    tx_ele->wrk_req->wr_ele->wr.num_sge = 1;
    tx_ele->wrk_req->wr_ele->wr.sg_list = (struct ib_sge *) &tx_ele->wrk_req->wr_ele->sg;

    tx_ele->wrk_req->wr_ele->sg.addr = tx_ele->dsm_dma.addr;
    tx_ele->wrk_req->wr_ele->sg.length = tx_ele->dsm_dma.size;
    tx_ele->wrk_req->wr_ele->sg.lkey = lkey;

    tx_ele->wrk_req->wr_ele->wr.next = NULL;
}

void init_tx_ele(struct tx_buf_ele *tx_ele, struct conn_element *ele, int id) {
    BUG_ON(!tx_ele);
    tx_ele->id = id;
    init_tx_wr(tx_ele, ele->mr->lkey, id);
    init_reply_wr(tx_ele->reply_work_req, tx_ele->dsm_dma.addr, ele->mr->lkey,
            tx_ele->id);
    BUG_ON(!ele->mr);
    init_page_wr(tx_ele->reply_work_req, ele->mr->lkey, tx_ele->id);
    tx_ele->dsm_buf->dest_id = ele->mr->rkey;
    tx_ele->dsm_buf->offset = tx_ele->id;
}
EXPORT_SYMBOL(init_tx_ele);

/**
 * Buffer for the messages to be sent.
 * One for each connection.
 * Each element of the buffer contains:
 *                      a sending work request to send the message
 *                      and a mapped memory region to received the page replied
 *
 * RETURN 0 if success,
 *               -1 if failure.
 */
static int create_tx_buffer(struct conn_element *ele) {
    int i, ret = 0;
    struct tx_buf_ele *tx_buff_e;

    BUG_ON(!ele);
    BUG_ON(IS_ERR(ele->cm_id));
    BUG_ON(!ele->cm_id->device);
    might_sleep();

    tx_buff_e = kzalloc(
            (sizeof(struct tx_buf_ele) * get_nb_tx_buff_elements(ele)),
            GFP_KERNEL);
    if (unlikely(!tx_buff_e)) {
        dsm_printk(KERN_ERR "Can't allocate memory");
        return -ENOMEM;
    }
    ele->tx_buffer.tx_buf = tx_buff_e;

    for (i = 0; i < get_nb_tx_buff_elements(ele); ++i) {
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

int refill_recv_wr(struct conn_element *ele, struct rx_buf_ele * rx_e) {
    int ret = 0;
    ret = ib_post_recv(ele->cm_id->qp, &rx_e->recv_wrk_rq_ele->sq_wr,
            &rx_e->recv_wrk_rq_ele->bad_wr);
    if (ret)
        printk(">[refill_recv_wr] - ERROR IN POSTING THE RECV WR"
                " ret : %d on offset %d\n", ret, rx_e->id);

    return ret;
}

static inline void reset_tx_element_msg(struct dsm_message *msg) {
    //we just rest the dsm_id, id 0 can never be used !
    msg->dsm_id = 0;

}

void release_tx_element(struct conn_element *ele, struct tx_buf_ele *tx_e) {
    struct tx_buffer *tx = &ele->tx_buffer;
    reset_tx_element_msg(tx_e->dsm_buf);
    llist_add(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list);
}

void release_tx_element_reply(struct conn_element *ele, struct tx_buf_ele *tx_e) {
    struct tx_buffer *tx = &ele->tx_buffer;
    reset_tx_element_msg(tx_e->dsm_buf);
    llist_add(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list_reply);
}

int create_rcm(struct dsm_module_state *dsm_state, char *ip, int port) {
    int ret = 0;

    struct rcm *rcm = NULL;
    rcm = kzalloc(sizeof(struct rcm), GFP_KERNEL);
    BUG_ON(!(rcm));
    init_kmem_request_cache();
    init_dsm_cache_kmem();
    init_dsm_prefetch_cache_kmem();
    dsm_init_descriptors();
    mutex_init(&rcm->rcm_mutex);

    rcm->node_ip = inet_addr(ip);

    rcm->root_conn = RB_ROOT;
    seqlock_init(&rcm->conn_lock);

    rcm->sin.sin_family = AF_INET;
    rcm->sin.sin_addr.s_addr = (__u32) rcm->node_ip;
    rcm->sin.sin_port = (__u16) htons(port);

    rcm->cm_id = rdma_create_id(server_event_handler, rcm, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(rcm->cm_id))
        goto err_cm_id;

    if ((ret = rdma_bind_addr(rcm->cm_id, (struct sockaddr *) &(rcm->sin)))) {
        printk("{r = %d}\n", ret);
        goto err_bind;
    }

    if (!rcm->cm_id->device)
        goto nodevice;

    rcm->pd = ib_alloc_pd(rcm->cm_id->device);
    if (IS_ERR(rcm->pd))
        goto err_pd;

    rcm->listen_cq = ib_create_cq(rcm->cm_id->device, listener_cq_handle, NULL,
            rcm, 2, 0);
    if (IS_ERR(rcm->listen_cq))
        goto err_cq;

    if (ib_req_notify_cq(rcm->listen_cq, IB_CQ_NEXT_COMP))
        goto err_notify;

    rcm->mr = ib_get_dma_mr(rcm->pd,
            IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE);
    if (IS_ERR(rcm->mr))
        goto err_mr;

    dsm_state->rcm = rcm;
    return ret;

    err_mr: err_notify: ib_destroy_cq(rcm->listen_cq);
    err_cq: ib_dealloc_pd(rcm->pd);
    err_pd: err_bind: rdma_destroy_id(rcm->cm_id);
    err_cm_id: printk(">[create_rcm] Failed.\n");
    return ret;

    nodevice: printk(">[create_rcm] - NO DEVICE\n");
    return ret;
}

int create_connection(struct rcm *rcm, struct svm_data *conn_data) {
    struct sockaddr_in dst, src;
    struct rdma_conn_param param;
    struct conn_element *ele;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    memset(&param, 0, sizeof(struct rdma_conn_param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = 10;

    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = (__u32) inet_addr(conn_data->ip);
    dst.sin_port = (__u16) htons(conn_data->port);

    src.sin_family = AF_INET;
    src.sin_addr.s_addr = rcm->sin.sin_addr.s_addr;
    src.sin_port = 0; /* intentionally do not specify outgoing port */

    ele = vzalloc(sizeof(struct conn_element));
    if (unlikely(!ele))
        goto err;

    init_completion(&ele->completion);
    ele->remote_node_ip = inet_addr(conn_data->ip);
    insert_rb_conn(ele);

    ele->rcm = rcm;
    ele->cm_id = rdma_create_id(client_event_handler, ele, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(ele->cm_id))
        goto err1;

    if (create_connection_sysfs_entry(&ele->sysfs,
            dsm_state->dsm_kobjects.rdma_kobject, conn_data->ip))
        goto err1;

    return rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &src,
            (struct sockaddr*) &dst, 2000);

    err1: erase_rb_conn(ele);
    vfree(ele);
    err: return -1;
}

void reg_rem_info(struct conn_element *ele) {
    ele->rid.remote_info->node_ip = ntohl(ele->rid.recv_buf->node_ip);
    ele->rid.remote_info->buf_rx_addr = ntohll(ele->rid.recv_buf->buf_rx_addr);
    ele->rid.remote_info->buf_msg_addr = ntohll(ele->rid.recv_buf->buf_msg_addr);
    ele->rid.remote_info->rx_buf_size = ntohl(ele->rid.recv_buf->rx_buf_size);
    ele->rid.remote_info->rkey_msg = ntohl(ele->rid.recv_buf->rkey_msg);
    ele->rid.remote_info->rkey_rx = ntohl(ele->rid.recv_buf->rkey_rx);
    ele->rid.remote_info->flag = ele->rid.recv_buf->flag;
}

void release_ppe(struct conn_element *ele, struct tx_buf_ele *tx_e) {
    struct page_pool *pp = &ele->page_pool;
    struct page_pool_ele *ppe;

    if (likely(tx_e->wrk_req->dst_addr)) {
        ppe = (struct page_pool_ele *) tx_e->wrk_req->dst_addr;
        if (ppe->page_buf) {
            ib_dma_unmap_page(ele->cm_id->device, (u64) ppe->page_buf,
                    PAGE_SIZE, DMA_BIDIRECTIONAL);
            ppe->page_buf = NULL;
        }
        if (ppe->mem_page)
            page_cache_release(ppe->mem_page);
        llist_add(&ppe->llnode, &pp->page_empty_pool_list);
        tx_e->wrk_req->dst_addr = NULL;
    }
}

/*
 * Called once the two nodes have exchanged their rdma info
 * Getting the RX buffer prepared to receiving messages from remote node
 * One for each connection.
 *
 *RETURN 0 if success,
 *              -1 if failure.
 */
int setup_recv_wr(struct conn_element *ele) {
    int i;
    struct rx_buf_ele *rx = ele->rx_buffer.rx_buf;

    if (unlikely(!rx))
        return -1;

    for (i = 0; i < (get_nb_tx_buff_elements(ele) - 1); ++i) {
        if (refill_recv_wr(ele, &rx[i]))
            return -1;

    }
    return 0;
}

int connect_client(struct rdma_cm_id *id) {
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

unsigned int inet_addr(char *addr) {
    unsigned int a, b, c, d;
    char arr[4];

    sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d);
    arr[0] = a;
    arr[1] = b;
    arr[2] = c;
    arr[3] = d;
    return *(unsigned int*) arr;
}

void create_page_request(struct conn_element *ele, struct tx_buf_ele *tx_e,
        u32 dsm_id, u32 local_id, u32 remote_id, uint64_t addr,
        struct page *page, u16 type, struct dsm_page_cache *dpc) {
    struct dsm_message *msg = tx_e->dsm_buf;
    struct page_pool_ele *ppe = create_new_page_pool_element_from_page(ele,
            page);
    dsm_printk("ppe %p / page %p / dpc %p " , ppe , ppe->mem_page, dpc );
    tx_e->wrk_req->dst_addr = ppe;
    tx_e->wrk_req->dpc = dpc;

    //we need to reset the offset just in case if we actually use the element for reply as an error
    msg->offset = tx_e->id;
    msg->dsm_id = dsm_id;
    msg->dest_id = local_id;
    msg->src_id = remote_id;
    msg->dst_addr = (u64) ppe->page_buf;
    msg->req_addr = addr;
    msg->rkey = ele->mr->rkey;
    msg->type = type;
}

void create_page_pull_request(struct conn_element *ele,
        struct tx_buf_ele * tx_e, u32 dsm_id, u32 local_id, u32 remote_id,
        uint64_t addr) {
    struct dsm_message *msg = tx_e->dsm_buf;

    tx_e->wrk_req->dst_addr = NULL;

    msg->dsm_id = dsm_id;
    msg->dest_id = local_id;
    msg->src_id = remote_id;
    msg->dst_addr = 0;
    msg->req_addr = addr;
    msg->rkey = ele->mr->rkey;
    msg->type = REQUEST_PAGE_PULL;
}

struct page_pool_ele *get_empty_page_ele(struct conn_element *ele) {
    struct page_pool_ele *ppe = NULL;
    struct page_pool *pp = &ele->page_pool;
    struct llist_node *llnode = NULL;

    do {
        while (llist_empty(&pp->page_empty_pool_list))
            cond_resched();

        spin_lock(&pp->page_pool_empty_list_lock);
        llnode = llist_del_first(&pp->page_empty_pool_list);
        spin_unlock(&pp->page_pool_empty_list_lock);
    } while (!llnode);

    ppe = container_of(llnode, struct page_pool_ele, llnode);

    return ppe;
}

struct page_pool_ele *create_new_page_pool_element_from_page(
        struct conn_element *ele, struct page *page) {
    struct page_pool_ele *ppe;

    BUG_ON(!page);
    ppe = get_empty_page_ele(ele);
    ppe->mem_page = page;
    ppe->page_buf = (void *) ib_dma_map_page(ele->cm_id->device, ppe->mem_page,
            0, PAGE_SIZE, DMA_BIDIRECTIONAL);
    if (ib_dma_mapping_error(ele->cm_id->device,
            (u64) (unsigned long) ppe->page_buf))
        return NULL;

    return ppe;
}

int setup_connection(struct conn_element *ele, int type) {
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
    if (create_page_pool(ele))
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

struct tx_buf_ele *try_get_next_empty_tx_ele(struct conn_element *ele) {
    struct tx_buf_ele *tx_e = NULL;
    struct llist_node *llnode;
    spin_lock(&ele->tx_buffer.tx_free_elements_list_lock);
    llnode = llist_del_first(&ele->tx_buffer.tx_free_elements_list);
    spin_unlock(&ele->tx_buffer.tx_free_elements_list_lock);

    if (llnode)
        tx_e = container_of(llnode, struct tx_buf_ele, tx_buf_ele_ptr);



    return tx_e;
}

struct tx_buf_ele *try_get_next_empty_tx_reply_ele(struct conn_element *ele) {
    struct tx_buf_ele *tx_e = NULL;

    struct llist_node *llnode;
    spin_lock(&ele->tx_buffer.tx_free_elements_list_reply_lock);
    llnode = llist_del_first(&ele->tx_buffer.tx_free_elements_list_reply);
    spin_unlock(&ele->tx_buffer.tx_free_elements_list_reply_lock);

    if (llnode)
        tx_e = container_of(llnode, struct tx_buf_ele, tx_buf_ele_ptr);

    return tx_e;
}

int destroy_rcm(struct dsm_module_state *dsm_state) {
    struct rcm *rcm = dsm_state->rcm;

    if (likely(rcm)) {
        rcm_disconnect(rcm);

        if (likely(rcm->cm_id)) {
            if (likely(rcm->cm_id->qp))
                ib_destroy_qp(rcm->cm_id->qp);

            if (likely(rcm->listen_cq))
                ib_destroy_cq(rcm->listen_cq);

            if (likely(rcm->mr))
                ib_dereg_mr(rcm->mr);

            if (likely(rcm->pd))
                ib_dealloc_pd(rcm->pd);

            rdma_destroy_id(rcm->cm_id);
        }

        mutex_destroy(&rcm->rcm_mutex);
        dsm_state->rcm = NULL;
        kfree(rcm);
    }

    destroy_dsm_cache_kmem();
    destroy_dsm_prefetch_cache_kmem();
    destroy_kmem_request_cache();
    dsm_destroy_descriptors();

    return 0;
}

static void remove_svms_for_conn(struct conn_element *ele) {
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

int destroy_connection(struct conn_element *ele) {
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

    erase_rb_conn(ele);
    delete_connection_sysfs_entry(&ele->sysfs);
    vfree(ele);

    return ret;
}

static void replace_mr_descriptor(struct dsm *dsm, struct memory_region *mr,
        struct svm_list svms, u32 svm_id) {
    int i, j = 0;
    u32 svm_ids[svms.num - 1];

    for_each_valid_svm(svms, i) {
        if (svms.pp[i]->svm_id != svm_id)
            svm_ids[j++] = svms.pp[i]->svm_id;
    }
    svm_ids[j] = 0;

    mr->descriptor = dsm_get_descriptor(dsm, svm_ids);
}

void release_svm_from_mr_descriptors(struct subvirtual_machine *svm) {
    struct rb_root *root = &svm->dsm->mr_tree_root;
    struct rb_node *node;
    int i;

    write_seqlock(&svm->dsm->mr_seq_lock);
    for (node = rb_first(root); node; node = rb_next(node)) {
        struct memory_region *mr;
        struct svm_list svms;

        mr = rb_entry(node, struct memory_region, rb_node);
        svms = dsm_descriptor_to_svms(mr->descriptor);

        for_each_valid_svm(svms, i) {
            if (svms.pp[i]->svm_id == svm->svm_id) {
                if (svms.num > 1) {
                    replace_mr_descriptor(svm->dsm, mr, svms, svm->svm_id);
                } else {
                    rb_erase(&mr->rb_node, root);
                    kfree(mr);
                }

                /*
                 * We can either walk the entire page table, removing references
                 * to this descriptor; change the descriptor right now (which
                 * will require more complicated rcu locking everywhere); or
                 * hack - leave a "hole" in the arr to signal svm down.
                 *
                 */
                svms.pp[i] = 0;
                break;
            }
        }
    }
    write_sequnlock(&svm->dsm->mr_seq_lock);
}

static inline void dealloc_push_dpc(struct dsm_page_cache *dpc) {
    page_cache_release(dpc->pages[0]);
    rb_erase(&dpc->rb_node, &dpc->svm->push_cache);
    dsm_dealloc_dpc(&dpc);
}

static int surrogate_remote_response_push(struct dsm_page_cache *dpc,
        struct subvirtual_machine *remote_svm) {
    int i;

    if (remote_svm) {
        for_each_valid_svm(dpc->svms, i) {
            if (dpc->svms.pp[i] == remote_svm)
                goto surrogate;
        }
        return -EINVAL;
    }

    surrogate: if (likely(test_and_clear_bit(i, &dpc->bitmap))) {
        page_cache_release(dpc->pages[0]);
        atomic_dec(&dpc->nproc);
        if (atomic_cmpxchg(&dpc->nproc, 1, 0) == 1 && find_first_bit(
                &dpc->bitmap, dpc->svms.num) >= dpc->svms.num)
            dealloc_push_dpc(dpc);
        return 1;
    }
    return 0;
}

void surrogate_remote_response_pull(struct dsm_page_cache *dpc) {
    atomic_dec(&dpc->nproc);
    if (atomic_cmpxchg(&dpc->nproc, 1, 0) == 1) {
        BUG_ON(atomic_read(&dpc->found) < 0);
        dsm_push_finish_notify(dpc->pages[0]);
        page_cache_release(dpc->pages[0]);
        dsm_dealloc_dpc(&dpc);
    }
}

void release_svm_push_elements(struct subvirtual_machine *svm,
        struct subvirtual_machine *remote_svm) {
    struct rb_node *node;

    write_seqlock(&svm->push_cache_lock);
    for (node = rb_first(&svm->push_cache); node; node = rb_next(node)) {
        struct dsm_page_cache *dpc;

        dpc = rb_entry(node, struct dsm_page_cache, rb_node);
        if (remote_svm) {
            surrogate_remote_response_push(dpc, remote_svm);
        } else {
            int i;

            dsm_push_finish_notify(dpc->pages[0]);
            for_each_valid_svm(dpc->svms, i) {
                if (1 << i & dpc->bitmap)
                    page_cache_release(dpc->pages[0]);
            }
            dealloc_push_dpc(dpc);
            continue;
        }
    }
    write_sequnlock(&svm->push_cache_lock);
}

/*
 * pull ops tx_elements are only released after a response has returned.
 * therefore we can catch them and surrogate for them by iterating the tx
 * buffer.
 */
void release_svm_tx_elements(struct subvirtual_machine *svm,
        struct conn_element *ele) {
    struct tx_buf_ele *tx_buf;
    int i;

    /* killed before it was first connected */
    if (!ele || !ele->tx_buffer.tx_buf)
        return;

    tx_buf = ele->tx_buffer.tx_buf;

    for (i = 0; i < get_nb_tx_buff_elements(ele); i++) {
        struct dsm_message *msg = tx_buf[i].dsm_buf;

        if (msg->dsm_id == svm->dsm->dsm_id
                && (msg->src_id == svm->svm_id || msg->dest_id == svm->svm_id)) {

            switch (msg->type) {
                case PAGE_REQUEST_REPLY:
                case TRY_REQUEST_PAGE_FAIL: {

                    /*unhandled */
                    break;
                }
                case TRY_REQUEST_PAGE:
                case REQUEST_PAGE: {
                    tx_buf[i].wrk_req->dst_addr->mem_page = NULL;
                    surrogate_remote_response_pull(tx_buf[i].wrk_req->dpc);
                    release_ppe(ele, &tx_buf[i]);
                    release_tx_element(ele, &tx_buf[i]);
                    break;
                }
                case REQUEST_PAGE_PULL:
                case SVM_STATUS_UPDATE:
                case ACK: {
                    release_tx_element(ele,&tx_buf[i]);
                    break;
                }

                default: {
                    BUG();
                    break;
                }
            }
        }
    }
}



