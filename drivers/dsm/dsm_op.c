/*
 * dsm_op.c
 *
 *  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

struct dsm_conn_list {
    struct conn_element *ele;
    struct list_head list;
};

static int rcm_disconnect(struct rcm *rcm) {
    struct rb_root *root = &rcm->root_conn;
    struct rb_node *node;
    struct dsm_conn_list *it, *next;
    LIST_HEAD(conns);

    for (node = rb_first(root); node; node = rb_next(node)) {
        it = kmalloc(sizeof(struct dsm_conn_list), GFP_KERNEL);
        it->ele = rb_entry(node, struct conn_element, rb_node);
        list_add_tail(&it->list, &conns);
    }

    list_for_each_entry_safe (it, next, &conns, list) {
        rdma_disconnect(it->ele->cm_id);
        destroy_connection(&it->ele, rcm);
        kfree(it);
    }

    return 0;
}

static void destroy_tx_buffer(struct conn_element *ele) {
    int i;
    struct tx_buf_ele * tx_buf = ele->tx_buffer.tx_buf;
    if (tx_buf) {
        for (i = 0; i < TX_BUF_ELEMENTS_NUM; ++i) {
            ib_dma_unmap_single(ele->cm_id->device, (u64) tx_buf[i].dsm_msg,
                    sizeof(struct dsm_message), DMA_TO_DEVICE);

            vfree(tx_buf[i].mem);

            kfree(tx_buf[i].wrk_req->wr_ele);

            //                      if(likely(ele->tx_buf[i].wrk_req->page_buf))
            //                      {
            //                              ib_dma_unmap_page(ele->cm_id->device, (u64) (unsigned long) ele->tx_buf[i].wrk_req->page_buf, RDMA_PAGE_SIZE, DMA_FROM_DEVICE);
            //                              ele->tx_buf[i].wrk_req->page_buf = NULL;
            //
            //                              __free_pages(ele->tx_buf[i].wrk_req->mem_page, 0);
            //                              ele->tx_buf[i].wrk_req->mem_page = NULL;
            //                      }

            kfree(tx_buf[i].wrk_req);
        }

        kfree(tx_buf);
        ele->tx_buffer.tx_buf = 0;
    }
}

static void destroy_rx_buffer(struct conn_element *ele) {
    int i;
    struct rx_buf_ele * rx = ele->rx_buffer.rx_buf;

    if (rx) {
        for (i = 0; i < RX_BUF_ELEMENTS_NUM; ++i) {
            ib_dma_unmap_single(ele->cm_id->device, (u64) rx[i].dsm_msg,
                    sizeof(struct dsm_message), DMA_FROM_DEVICE);
            vfree(rx[i].mem);

            kfree(rx[i].recv_wrk_rq_ele);
        }
        kfree(rx);
        ele->rx_buffer.rx_buf = 0;
    }
}

static void free_rdma_info(struct conn_element *ele) {
    if (ele->rid.send_info) {
        ib_dma_unmap_single(ele->cm_id->device,
                (u64) (unsigned long) ele->rid.send_info,
                sizeof(struct rdma_info), DMA_TO_DEVICE);
        vfree(ele->rid.send_mem);
    }

    if (ele->rid.recv_info) {
        ib_dma_unmap_single(ele->cm_id->device,
                (u64) (unsigned long) ele->rid.recv_info,
                sizeof(struct rdma_info), DMA_FROM_DEVICE);
        vfree(ele->rid.recv_mem);
    }

    if (ele->rid.remote_info) {
        kfree(ele->rid.remote_info);
    }

    memset(&ele->rid, 0, sizeof(struct rdma_info_data));
}

static void try_recycle_empty_page_pool_element(struct conn_element *ele,
        struct page_pool_ele * ppe) {

    struct page_pool * pp = &ele->page_pool;
    struct page * page = ppe->mem_page;

    if (page)
        put_page(page);

    spin_lock(&pp->page_pool_empty_list_lock);
    list_add_tail(&ppe->page_ptr, &pp->page_empty_pool_list);
    spin_unlock(&pp->page_pool_empty_list_lock);

}

static void init_recv_wr(struct rx_buf_ele *rx_ele, struct conn_element * ele) {
    struct recv_work_req_ele * rwr = rx_ele->recv_wrk_rq_ele;
    struct ib_sge * recv_sge = &rwr->recv_sgl;

    recv_sge->addr = (u64) rx_ele->dsm_msg;
    recv_sge->length = sizeof(struct dsm_message);
    recv_sge->lkey = ele->mr->lkey;

    rwr->sq_wr.next = NULL;
    rwr->sq_wr.num_sge = 1;
    rwr->sq_wr.sg_list = &rwr->recv_sgl;
    rwr->sq_wr.wr_id = rx_ele->id;
}

static void init_rx_ele(struct rx_buf_ele *rx_ele, struct conn_element *ele) {
    init_recv_wr(rx_ele, ele);
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
    struct rx_buf_ele * rx = kmalloc(
            (sizeof(struct rx_buf_ele) * RX_BUF_ELEMENTS_NUM), GFP_KERNEL);

    if (!rx)
        goto err_buf;

    ele->rx_buffer.rx_buf = rx;
    memset(rx, 0, (sizeof(struct rx_buf_ele) * RX_BUF_ELEMENTS_NUM));

    for (i = 0; i < RX_BUF_ELEMENTS_NUM; ++i) {
        rx[i].mem = vmalloc(sizeof(struct dsm_message));
        if (!rx[i].mem)
            goto err1;
        memset(rx[i].mem, 0, sizeof(struct dsm_message));

        rx[i].dsm_msg = (struct dsm_message *) ib_dma_map_single(
                ele->cm_id->device, rx[i].mem, sizeof(struct dsm_message),
                DMA_BIDIRECTIONAL);
        if (!rx[i].dsm_msg)
            goto err2;

        rx[i].recv_wrk_rq_ele = kmalloc(sizeof(struct recv_work_req_ele),
                GFP_KERNEL);
        if (!rx[i].recv_wrk_rq_ele)
            goto err3;
        memset(rx[i].recv_wrk_rq_ele, 0, sizeof(struct recv_work_req_ele));

        rx[i].id = i;

        init_rx_ele(&rx[i], ele);
    }

    return 0;

    err3: ib_dma_unmap_single(ele->cm_id->device,
            (u64) (unsigned long) rx[i].dsm_msg, sizeof(struct dsm_message),
            DMA_FROM_DEVICE);
    err2: vfree(rx[i].mem);

    err1: for (undo = 0; undo < i; ++undo) {
        ib_dma_unmap_single(ele->cm_id->device,
                (u64) (unsigned long) rx[undo].dsm_msg,
                sizeof(struct dsm_message), DMA_FROM_DEVICE);
        vfree(rx[undo].mem);
        kfree(rx[undo].recv_wrk_rq_ele);
    }

    memset(rx, 0, sizeof(struct rx_buf_ele) * RX_BUF_ELEMENTS_NUM);
    kfree(rx);
    ele->rx_buffer.rx_buf = 0;

    err_buf: printk(">[create_rx_buffer] - RX BUFFER NOT CREATED\n");
    return -1;
}

/*
 * Creates the qp and links it to the two cq
 *
 * RETURN 0 if success,
 *               -1 if failure.
 */
static int create_qp(struct conn_element *ele) {
    int ret = 0;
    struct ib_qp_init_attr attr;

    memset(&attr, 0, sizeof attr);

//The attribute shall be modifiable
    attr.send_cq = ele->send_cq;
    attr.recv_cq = ele->recv_cq;
    attr.sq_sig_type = IB_SIGNAL_ALL_WR;
    attr.cap.max_send_wr = MAX_CAP_SCQ;
    attr.cap.max_recv_wr = MAX_CAP_RCQ;
    attr.cap.max_send_sge = 4;
    attr.cap.max_recv_sge = 4;
    attr.qp_type = IB_QPT_RC;
    attr.port_num = ele->cm_id->port_num;
    attr.qp_context = (void *) ele;

    if (unlikely(!ele->cm_id))
        goto err;

    if (unlikely(!ele->pd))
        goto err;

    ret = rdma_create_qp(ele->cm_id, ele->pd, &attr);
    err: return ret;

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

    ele->send_cq = ib_create_cq(ele->cm_id->device, send_cq_handle,
            dsm_cq_event_handler, (void *) ele, MAX_CAP_SCQ, 0);
    if (IS_ERR(ele->send_cq)) {
        printk(">[setup_qp] - Cannot create cq\n");
        goto err1;
    }

    if (ib_req_notify_cq(ele->send_cq, IB_CQ_NEXT_COMP)) {
        printk(">[setup_qp] - Cannot notify cq\n");
        goto err2;
    }

    ele->recv_cq = ib_create_cq(ele->cm_id->device, recv_cq_handle,
            dsm_cq_event_handler, (void *) ele, MAX_CAP_RCQ, 0);
    if (IS_ERR(ele->recv_cq)) {
        printk(">[setup_qp] - Cannot create cq\n");
        goto err3;
    }

    if (ib_req_notify_cq(ele->recv_cq, IB_CQ_NEXT_COMP)) {
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
    ib_destroy_cq(ele->recv_cq);
    err3: ret++;
    err2: ret++;
    ib_destroy_cq(ele->send_cq);
    err1: ret++;
    printk(">[setup_qp] - Could not setup the qp, error %d occurred\n", ret);
    return ret;
}

static void format_rdma_info(struct conn_element *ele) {

    ele->rid.send_info->node_ip = htonl(ele->rcm->node_ip);
    ele->rid.send_info->buf_rx_addr = htonll((u64) ele->rx_buffer.rx_buf);
    ele->rid.send_info->buf_msg_addr = htonll((u64) ele->tx_buffer.tx_buf);
    ele->rid.send_info->rx_buf_size = htonl(RX_BUF_ELEMENTS_NUM);
    ele->rid.send_info->rkey_msg = htonl(ele->mr->rkey);
    ele->rid.send_info->rkey_rx = htonl(ele->mr->rkey);
    ele->rid.send_info->flag = RDMA_INFO_CL;
}

static int create_new_empty_page_pool_element(struct conn_element * ele) {
    struct page_pool * pp = &ele->page_pool;

    struct page_pool_ele *ppe;

    ppe = kmalloc(sizeof(struct page_pool_ele), GFP_ATOMIC);
    if (!ppe)
        return -1;
    memset(ppe, 0, sizeof(struct page_pool_ele));
    spin_lock(&pp->page_pool_empty_list_lock);
    list_add_tail(&ppe->page_ptr, &pp->page_empty_pool_list);
    spin_unlock(&pp->page_pool_empty_list_lock);
    return 0;

}

static int create_page_pool(struct conn_element * ele) {
    int ret = 0;
    int i;
    struct page_pool * pp = &ele->page_pool;

    spin_lock_init(&pp->page_release_lock);
    spin_lock_init(&pp->page_pool_empty_list_lock);

    INIT_WORK(&pp->page_release_work, release_page_work);
    INIT_LIST_HEAD(&pp->page_empty_pool_list);
    INIT_LIST_HEAD(&pp->page_release_list);

    for (i = 0; i < PAGE_POOL_SIZE; i++) {
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
    struct rdma_info_data * rid = &ele->rid;

    rid->send_mem = vmalloc(size);
    if (unlikely(!rid->send_mem))
        goto send_mem_err;

    rid->send_info = (struct rdma_info *) ib_dma_map_single(ele->cm_id->device,
            rid->send_mem, size, DMA_TO_DEVICE);
    if (unlikely(!rid->send_info))
        goto send_info_err;

    rid->recv_mem = vmalloc(size);
    if (unlikely(!rid->send_mem))
        goto recv_mem_err;

    rid->recv_info = (struct rdma_info *) ib_dma_map_single(ele->cm_id->device,
            rid->recv_mem, size, DMA_FROM_DEVICE);
    if (unlikely(!rid->send_info))
        goto recv_info_err;

    rid->remote_info = kmalloc(size, GFP_KERNEL);
    if (unlikely(!rid->remote_info))
        goto remote_info_buffer_err;

    memset(rid->send_info, 0, size);
    memset(rid->recv_info, 0, size);
    memset(rid->remote_info, 0, size);

    rid->remote_info->flag = RDMA_INFO_CL;
    rid->exchanged = 2;

    format_rdma_info(ele);

    return 0;

    remote_info_buffer_err: printk(
            ">[create_rdma_info] - ERROR : NO REMOTE INFO BUFFER\n");
    ib_dma_unmap_single(ele->cm_id->device,
            (u64) (unsigned long) rid->recv_info, sizeof(struct rdma_info),
            DMA_FROM_DEVICE);

    recv_info_err: printk(
            ">[create_rdma_info] - ERROR : NO RECV INFO BUFFER\n");
    vfree(rid->recv_mem);

    recv_mem_err: printk(
            ">[create_rdma_info] - no memory allocated for the reception buffer\n");
    ib_dma_unmap_single(ele->cm_id->device,
            (u64) (unsigned long) rid->send_info, sizeof(struct rdma_info),
            DMA_TO_DEVICE);

    send_info_err: printk(
            ">[create_rdma_info] - ERROR : NO SEND INFO BUFFER\n");
    vfree(rid->send_mem);

    send_mem_err: printk(
            ">[create_rdma_info] - no memory allocated for the sending buffer\n");
    return -1;
}

static int init_tx_lists(struct conn_element *ele) {
    int i;
    struct tx_buffer * tx = &ele->tx_buffer;
    int max_tx_send = TX_BUF_ELEMENTS_NUM / 3;
    int max_tx_reply = TX_BUF_ELEMENTS_NUM;
    INIT_LIST_HEAD(&tx->request_queue);
    INIT_LIST_HEAD(&tx->tx_free_elements_list);
    INIT_LIST_HEAD(&tx->tx_free_elements_list_reply);
    spin_lock_init(&tx->tx_free_elements_list_lock);
    spin_lock_init(&tx->tx_free_elements_list_reply_lock);
    spin_lock_init(&tx->request_queue_lock);

    for (i = 0; i < max_tx_send; ++i)
        release_tx_element(ele, &tx->tx_buf[i]);

    for (; i < max_tx_reply; ++i)
        release_tx_element_reply(ele, &tx->tx_buf[i]);

    return 0;
}

static void init_reply_wr(struct reply_work_request *rwr, u64 msg_addr,
        u32 lkey, int id) {
    struct ib_sge * reply_sge = &rwr->wr_ele->sg;
    rwr->wr_ele->dsm_msg = (struct dsm_message *) msg_addr;

    reply_sge->addr = msg_addr;
    reply_sge->length = sizeof(struct dsm_message);
    reply_sge->lkey = lkey;

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
    tx_ele->wrk_req->wr_ele->wr.wr_id = (u64) id;
    tx_ele->wrk_req->wr_ele->wr.opcode = IB_WR_SEND;
    tx_ele->wrk_req->wr_ele->wr.send_flags = IB_SEND_SIGNALED;
    tx_ele->wrk_req->wr_ele->wr.num_sge = 1;
    tx_ele->wrk_req->wr_ele->wr.sg_list =
            (struct ib_sge *) &tx_ele->wrk_req->wr_ele->sg;

    tx_ele->wrk_req->wr_ele->sg.addr = (u64) tx_ele->dsm_msg;
    tx_ele->wrk_req->wr_ele->sg.length = sizeof(struct dsm_message);
    tx_ele->wrk_req->wr_ele->sg.lkey = lkey;

    tx_ele->wrk_req->wr_ele->wr.next = NULL;
}

static void init_tx_ele(struct tx_buf_ele * tx_ele, struct conn_element *ele,
        int id) {
    tx_ele->id = id;
    init_tx_wr(tx_ele, ele->mr->lkey, id);
    init_reply_wr(tx_ele->reply_work_req, (u64) tx_ele->dsm_msg, ele->mr->lkey,
            tx_ele->id);
    init_page_wr(tx_ele->reply_work_req, ele->mr->lkey, tx_ele->id);
    tx_ele->dsm_msg->dest_id = ele->mr->rkey;
    tx_ele->dsm_msg->offset = tx_ele->id;
}

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
    int i = 0;
    int undo;
    int ret = 0;

    struct tx_buf_ele * tx_buff_e = kmalloc(
            (sizeof(struct tx_buf_ele) * TX_BUF_ELEMENTS_NUM), GFP_KERNEL);
    if (unlikely(!tx_buff_e)) {
        ret = -1;
        goto err_buf;
    }
    ele->tx_buffer.tx_buf = tx_buff_e;
    for (i = 0; i < TX_BUF_ELEMENTS_NUM; ++i) {
        tx_buff_e[i].mem = vmalloc(sizeof(struct dsm_message));
        if (unlikely(!tx_buff_e[i].mem))
            goto err1;

        tx_buff_e[i].dsm_msg = (struct dsm_message *) ib_dma_map_single(
                ele->cm_id->device, tx_buff_e[i].mem,
                sizeof(struct dsm_message), DMA_TO_DEVICE);
        if (unlikely(!tx_buff_e[i].dsm_msg))
            goto err2;

        memset(tx_buff_e[i].dsm_msg, 0, sizeof(struct dsm_message));

        tx_buff_e[i].wrk_req = kmalloc(sizeof(struct msg_work_request),
                GFP_KERNEL);
        if (unlikely(!tx_buff_e[i].wrk_req))
            goto err3;

        memset(tx_buff_e[i].wrk_req, 0, sizeof(struct msg_work_request));

        tx_buff_e[i].wrk_req->wr_ele = kmalloc(sizeof(struct work_request_ele),
                GFP_KERNEL);
        if (unlikely(!tx_buff_e[i].wrk_req->wr_ele))
            goto err4;

        memset(tx_buff_e[i].wrk_req->wr_ele, 0,
                sizeof(struct work_request_ele));

        tx_buff_e[i].wrk_req->wr_ele->dsm_msg = tx_buff_e[i].dsm_msg;

        tx_buff_e[i].reply_work_req = kmalloc(sizeof(struct reply_work_request),
                GFP_KERNEL);
        if (!tx_buff_e[i].reply_work_req)
            goto err5;
        memset(tx_buff_e[i].reply_work_req, 0,
                sizeof(struct reply_work_request));

        tx_buff_e[i].reply_work_req->wr_ele = kmalloc(
                sizeof(struct work_request_ele), GFP_KERNEL);
        if (!tx_buff_e[i].reply_work_req->wr_ele)
            goto err6;
        memset(tx_buff_e[i].reply_work_req->wr_ele, 0,
                sizeof(struct work_request_ele));

        init_tx_ele(&tx_buff_e[i], ele, i);
    }

    return ret;

    kfree(tx_buff_e[i].reply_work_req->wr_ele);
    ++ret;
    err6: kfree(tx_buff_e[i].reply_work_req);
    ++ret;
    err5: ++ret;
    err4: ++ret;
    printk("> [create_tx_buffer][ERR] - Freed the work request\n");
    kfree(tx_buff_e[i].wrk_req);
    err3: ++ret;
    ib_dma_unmap_single(ele->cm_id->device,
            (u64) (unsigned long) tx_buff_e[i].dsm_msg,
            sizeof(struct dsm_message), DMA_TO_DEVICE);
    printk("> [create_tx_buffer][ERR] - Removed dsm_msg registration\n");
    err2: printk(">[create_tx_buffer] - 5\n");
    vfree(tx_buff_e[i].mem);
    printk("> [create_tx_buffer][ERR] - Freed dsm_msg\n");
    ++ret;

    err1: for (undo = 0; undo < i; ++undo) {
        kfree(tx_buff_e[undo].reply_work_req->wr_ele);
        kfree(tx_buff_e[undo].reply_work_req);
        kfree(tx_buff_e[undo].wrk_req);
        ib_dma_unmap_single(ele->cm_id->device,
                (u64) (unsigned long) tx_buff_e[undo].dsm_msg,
                sizeof(struct dsm_message), DMA_TO_DEVICE);
        vfree(tx_buff_e[undo].mem);
    }

    memset(tx_buff_e, 0, sizeof(struct tx_buf_ele) * TX_BUF_ELEMENTS_NUM);
    kfree(tx_buff_e);
    ele->tx_buffer.tx_buf = NULL;
    printk("> [create_tx_buffer][ERR] - Zeroing the tx buffer\n");
    ++ret;

    err_buf: printk(
            ">[create_tx_buffer][ERR] - TX BUFFER NOT CREATED - index %d\n", i);
    return ret;
}

int refill_recv_wr(struct conn_element *ele, struct rx_buf_ele * rx_e) {

    int ret = 0;
    ret = ib_post_recv(ele->cm_id->qp, &rx_e->recv_wrk_rq_ele->sq_wr,
            &rx_e->recv_wrk_rq_ele->bad_wr);
    if (ret)
        printk(
                ">[refill_recv_wr] - ERROR IN POSTING THE RECV WR ret : %d on offset %d\n",
                ret, rx_e->id);

    return ret;
}

void release_tx_element(struct conn_element * ele, struct tx_buf_ele * tx_e) {

    struct tx_buffer * tx = &ele->tx_buffer;
    spin_lock(&tx->tx_free_elements_list_lock);
    list_add_tail(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list);
    spin_unlock(&tx->tx_free_elements_list_lock);
    tx_e->used = 0;
}
void release_tx_element_reply(struct conn_element * ele,
        struct tx_buf_ele * tx_e) {

    struct tx_buffer * tx = &ele->tx_buffer;
    spin_lock(&tx->tx_free_elements_list_reply_lock);
    list_add_tail(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list_reply);
    spin_unlock(&tx->tx_free_elements_list_reply_lock);
    tx_e->used = 0;
}

int create_rcm(struct dsm_module_state *dsm_state, char *ip, int port) {
    int ret = 0;

    struct rcm *rcm = NULL;
    rcm = kmalloc(sizeof(struct rcm), GFP_KERNEL);
    BUG_ON(!(rcm));
    memset(rcm, 0, sizeof(struct rcm));
    init_kmem_request_cache();
    init_dsm_cache_kmem();
    dsm_init_descriptors();
    mutex_init(&rcm->rcm_mutex);

    rcm->node_ip = inet_addr(ip);

    rcm->root_conn = RB_ROOT;

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

    rcm->mr = ib_get_dma_mr(
            rcm->pd,
            IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ
                    | IB_ACCESS_REMOTE_WRITE);
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
    //TODO catch error
    create_connection_sysfs_entry(&ele->sysfs,
        dsm_state->dsm_kobjects.rdma_kobject, conn_data->ip);
    ele->remote_node_ip = inet_addr(conn_data->ip);

    insert_rb_conn(ele);

    ele->rcm = rcm;
    ele->cm_id = rdma_create_id(connection_event_handler, ele, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(ele->cm_id))
        goto err1;

    ele->alive = 1;
    return rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &src,
            (struct sockaddr*) &dst, 2000);

    err1: erase_rb_conn(&rcm->root_conn, ele);
    vfree(ele);
    err: return -1;
}

void reg_rem_info(struct conn_element *ele) {
    ele->rid.remote_info->node_ip = ntohl(ele->rid.recv_info->node_ip);
    ele->rid.remote_info->buf_rx_addr = ntohll(ele->rid.recv_info->buf_rx_addr);
    ele->rid.remote_info->buf_msg_addr =
            ntohll(ele->rid.recv_info->buf_msg_addr);
    ele->rid.remote_info->rx_buf_size = ntohl(ele->rid.recv_info->rx_buf_size);
    ele->rid.remote_info->rkey_msg = ntohl(ele->rid.recv_info->rkey_msg);
    ele->rid.remote_info->rkey_rx = ntohl(ele->rid.recv_info->rkey_rx);
    ele->rid.remote_info->flag = ele->rid.recv_info->flag;
}

void release_page_work(struct work_struct *work) {
    struct page_pool_ele * ppe = NULL;
    struct conn_element * ele;
    struct page_pool * pp;

    pp= container_of(work, struct page_pool ,page_release_work );
    ele= container_of(pp, struct conn_element ,page_pool );

    do {
        spin_lock(&pp->page_release_lock);
        if (list_empty(&pp->page_release_list)) {
            spin_unlock(&pp->page_release_lock);
            break;
        }

        ppe = list_first_entry(&pp->page_release_list, struct page_pool_ele, page_ptr);
        list_del(&ppe->page_ptr);
        spin_unlock(&pp->page_release_lock);
        try_recycle_empty_page_pool_element(ele, ppe);
    } while (1);

}

void release_page(struct conn_element * ele, struct tx_buf_ele * tx_e) {

    struct page_pool * pp = &ele->page_pool;
    struct page_pool_ele * ppe;
    if (likely(tx_e->wrk_req->dst_addr)) {
        ppe = (struct page_pool_ele *) tx_e->wrk_req->dst_addr;
        if (ppe->page_buf) {
            ib_dma_unmap_page(ele->cm_id->device, (u64) ppe->page_buf,
                    PAGE_SIZE, DMA_BIDIRECTIONAL);
            ppe->page_buf = NULL;
        }
    } else
        return;

    spin_lock(&pp->page_release_lock);
    list_add_tail(&ppe->page_ptr, &pp->page_release_list);
    spin_unlock(&pp->page_release_lock);
    schedule_work(&pp->page_release_work);

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
    int r = 0;
    struct rx_buf_ele * rx = ele->rx_buffer.rx_buf;

    if (unlikely(!rx))
        return -1;

    for (i = 0; i < (RX_BUF_ELEMENTS_NUM - 1); ++i) {
        if (refill_recv_wr(ele, &rx[i]))
            return -1;

    }

    return r;

}

int connect_client(struct rdma_cm_id *id) {
    int r = 0;
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

void create_page_request(struct conn_element *ele, struct tx_buf_ele * tx_e,
        u32 dsm_id, u32 local_id, u32 remote_id, uint64_t addr, 
        struct page *page, u16 type, struct dsm_page_cache *dpc) {
    struct dsm_message *msg = tx_e->dsm_msg;
    struct page_pool_ele * ppe = create_new_page_pool_element_from_page(ele,
            page);

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

    return;
}

void create_page_pull_request(struct conn_element *ele,
        struct tx_buf_ele * tx_e, u32 dsm_id, u32 local_id, u32 remote_id,
        uint64_t addr) {
    struct dsm_message *msg = tx_e->dsm_msg;

    tx_e->wrk_req->dst_addr = NULL;

    msg->dsm_id = dsm_id;
    msg->dest_id = local_id;
    msg->src_id = remote_id;
    msg->dst_addr = 0;
    msg->req_addr = addr;
    msg->rkey = ele->mr->rkey;
    msg->type = REQUEST_PAGE_PULL;

    return;
}

void free_page_ele(struct conn_element *ele, struct page_pool_ele * ppe) {
    if (likely(ppe)) {

        if (ppe->page_buf)
            ib_dma_unmap_page(ele->cm_id->device, (u64) ppe->page_buf,
                    PAGE_SIZE, DMA_BIDIRECTIONAL);
        if (ppe->mem_page)
            __free_page(ppe->mem_page);

        kfree(ppe);

    }
    return;
}

struct page_pool_ele * get_empty_page_ele(struct conn_element * ele) {
    struct page_pool_ele * ppe;

    struct page_pool * pp = &ele->page_pool;

    loop: spin_lock(&pp->page_pool_empty_list_lock);
    if (list_empty(&pp->page_empty_pool_list)) {
        spin_unlock(&pp->page_pool_empty_list_lock);
        printk("[get_empty_page_ele] forcing a page refill\n");
        release_page_work(&ele->page_pool.page_release_work);
        goto loop;
    }

    ppe =
    list_first_entry(&pp->page_empty_pool_list , struct page_pool_ele, page_ptr);
    list_del(&ppe->page_ptr);
    spin_unlock(&pp->page_pool_empty_list_lock);

    return ppe;

}
struct page_pool_ele * create_new_page_pool_element_from_page(
        struct conn_element * ele, struct page *page) {
    struct page_pool_ele *ppe;

    ppe = get_empty_page_ele(ele);
    ppe->mem_page = page;
    if (unlikely(!ppe->mem_page))
        return NULL;

    ppe->page_buf = (void *) ib_dma_map_page(ele->cm_id->device, ppe->mem_page,
            0, PAGE_SIZE, DMA_BIDIRECTIONAL);
    if (ib_dma_mapping_error(ele->cm_id->device,
            (u64) (unsigned long) ppe->page_buf))
        return NULL;

    return ppe;

}

int setup_connection(struct conn_element *ele, int type) {
    int ret = 0;
    int err = 0;
    struct rdma_conn_param conn_param;

    ele->pd = ib_alloc_pd(ele->cm_id->device);
    if (!ele->pd)
        goto err1;
    ele->mr = ib_get_dma_mr(
            ele->pd,
            IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ
                    | IB_ACCESS_REMOTE_WRITE);
    if (!ele->mr)
        goto err2;

    reset_dsm_connection_stats(&ele->sysfs);

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

    ele->alive = 1;

    return ret;

    err10: err++;
    err9: err++;
    err8: err++;
    err7: err++;
    err6: err++;
    err5: err++;
    err4: err++;
    /*err3: -unused-*/ err++;
    err2: err++;
    err1: err++;
    printk(
            ">[setup_connection] - Could not setup connection : error %d occurred\n",
            err);
    return err;
}

struct tx_buf_ele * try_get_next_empty_tx_ele(struct conn_element *ele) {

    struct tx_buf_ele *tx_e = NULL;
    struct tx_buffer *tx = &ele->tx_buffer;

    spin_lock(&tx->tx_free_elements_list_lock);
    if (!list_empty(&tx->tx_free_elements_list)) {
        tx_e = list_first_entry(&tx->tx_free_elements_list, struct tx_buf_ele, 
                tx_buf_ele_ptr);
        list_del(&tx_e->tx_buf_ele_ptr);
        tx_e->used = 1;
    }
    spin_unlock(&tx->tx_free_elements_list_lock);

    return tx_e;
}

struct tx_buf_ele * try_get_next_empty_tx_reply_ele(struct conn_element *ele) {

    struct tx_buf_ele *tx_e = NULL;
    struct tx_buffer *tx = &ele->tx_buffer;

    spin_lock(&tx->tx_free_elements_list_reply_lock);
    if (!list_empty(&tx->tx_free_elements_list_reply)) {
        tx_e = list_first_entry(&tx->tx_free_elements_list_reply, 
                struct tx_buf_ele, tx_buf_ele_ptr);
        list_del(&tx_e->tx_buf_ele_ptr);
        tx_e->used = 1;
    }
    spin_unlock(&tx->tx_free_elements_list_reply_lock);

    return tx_e;
}

int destroy_rcm(struct dsm_module_state *dsm_state) {
    struct rcm *rcm = dsm_state->rcm;

    if (likely(rcm)) {

        rcm_disconnect(dsm_state->rcm);

        if (likely(rcm->cm_id)) {
            int r;

            if (rcm->cm_id->qp)
                if ((r = ib_destroy_qp(rcm->cm_id->qp)))
                    printk(">[destroy_rcm] - Cannot destroy qp %d\n", r);

            if (rcm->listen_cq)
                if ((r = ib_destroy_cq(rcm->listen_cq)))
                    printk(">[destroy_rcm] - Cannot destroy cq %d\n", r);

            if (rcm->mr)
                if ((r = ib_dereg_mr(rcm->mr)))
                    printk(">[destroy_rcm] - Cannot dereg mr %d\n", r);

            if (rcm->pd)
                if ((r = ib_dealloc_pd(rcm->pd)))
                    printk(">[destroy_rcm] - Cannot dealloc pd %d\n", r);

            rdma_destroy_id(rcm->cm_id);

        } else {
            printk(">[destroy_rcm] - no cm_id\n");
        }

        mutex_destroy(&rcm->rcm_mutex);
        dsm_state->rcm = NULL;
        kfree(rcm);
    }

    destroy_dsm_cache_kmem();
    destroy_kmem_request_cache();
    dsm_destroy_descriptors();

    return 0;
}

int destroy_connection(struct conn_element **ele, struct rcm *rcm) {
    int ret = 0;

    if (*ele && (*ele)->alive) {
        (*ele)->alive = 0;

        if ((*ele)->cm_id) {
            if ((*ele)->cm_id->qp)
                if ((ret = ib_destroy_qp((*ele)->cm_id->qp)))
                    printk(">[destroy_connection] - Cannot destroy qp\n");
 
            if ((*ele)->send_cq)
                if ((ret = ib_destroy_cq((*ele)->send_cq)))
                    printk(">[destroy_connection] - Cannot destroy send cq\n");

            if ((*ele)->recv_cq)
                if ((ret = ib_destroy_cq((*ele)->recv_cq)))
                    printk(">[destroy_connection] - Cannot destroy recv cq\n");

            if ((*ele)->mr)
                if ((ret = ib_dereg_mr((*ele)->mr)))
                    printk(">[destroy_connection] - Cannot dereg mr\n");

            if ((*ele)->pd)
                if ((ret = ib_dealloc_pd((*ele)->pd)))
                    printk(">[destroy_connection] -Cannot dealloc pd\n");

            destroy_rx_buffer((*ele));
            destroy_tx_buffer((*ele));

            free_rdma_info(*ele);

            rdma_destroy_id((*ele)->cm_id);
        }

        erase_rb_conn(&rcm->root_conn, *ele);

        vfree(*ele);
        *ele = NULL;
    }

    return 0;
}

static inline u32 *svm_ids_without_svm(struct svm_list svms, u32 svm_id) {
    u32 *svm_ids;
    int i, j;

    svm_ids = kmalloc(sizeof(u32)*svms.num-1, GFP_KERNEL);
    for (i = 0; i < svms.num; i++)
        if (svms.pp[i] && svms.pp[i]->svm_id != svm_id)
            svm_ids[j++] = svms.pp[i]->svm_id;
    svm_ids[j] = 0;
    return svm_ids;
}

/*
 * TODO: Currently unused, insanely expensive (spin_lock_irq every call to
 * dsm_cache_release). We have to iterate the radix_tree explicitly.
 *
 */
static inline void clean_svm_page_cache(struct dsm *dsm,
        struct subvirtual_machine *svm) {
    unsigned long addr;
    struct dsm_page_cache *dpc;
    struct rb_root *root = &dsm->mr_tree_root;
    struct rb_node *node;
    struct memory_region *mr;

    for (node = rb_first(root); node; node = rb_next(node)) {
        mr = rb_entry(node, struct memory_region, rb_node);
        for (addr = mr->addr; addr < (addr + mr->sz); addr += PAGE_SIZE) {
            dpc = dsm_cache_release(svm, addr);
            if (dpc) {
                synchronize_rcu();
                /* perhaps we need to release pages in there! */
                dsm_dealloc_dpc(&dpc);
            }
        }
    }
}

static void clean_svm_from_mrs(struct dsm *dsm, struct subvirtual_machine *svm){
    struct rb_root *root = &dsm->mr_tree_root;
    struct rb_node *node;
    struct memory_region *mr;
    struct svm_list svms;
    int i;
    u32 *svm_ids;

    write_seqlock(&dsm->mr_seq_lock);
    for (node = rb_first(root); node; node = rb_next(node)) {
        mr = rb_entry(node, struct memory_region, rb_node);
        svms = dsm_descriptor_to_svms(mr->descriptor);

        for (i = 0; i < svms.num; i++) {
            if (svms.pp[i] && svms.pp[i]->svm_id == svm->svm_id) {

                svm_ids = svm_ids_without_svm(svms, svm->svm_id);
                if (svm_ids[0]) {
                    mr->descriptor = dsm_get_descriptor(dsm, svm_ids);
                } else {
                    rb_erase(&mr->rb_node, root);
                    kfree(mr);
                }
                kfree(svm_ids);

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
    write_sequnlock(&dsm->mr_seq_lock);
}

void clean_svm_data(struct work_struct *work) {
    struct subvirtual_machine *svm = container_of(work,
            struct subvirtual_machine, dtor);
    struct dsm *dsm = svm->dsm;

    /*
    if (svm->priv)
        clean_svm_page_cache(svm, mr);
     */
    clean_svm_from_mrs(dsm, svm);

    mutex_lock(&dsm->dsm_mutex);
    list_del(&svm->svm_ptr);
    mutex_unlock(&dsm->dsm_mutex);

    kfree(svm);

    if (atomic_read(&dsm->dtor) && list_empty(&dsm->svm_list))
        remove_dsm(dsm);
}

