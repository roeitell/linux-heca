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
#include <dsm/dsm_stats.h>

int create_rcm(rcm **rcm, char *ip, int port) {
        int ret = 0;

        *rcm = kmalloc(sizeof(struct rcm), GFP_KERNEL);
        memset(*rcm, 0, sizeof(rcm));

        (*rcm)->dsm_wq = create_workqueue("dsm_wq");
        (*rcm)->node_ip = inet_addr(ip);

        (*rcm)->root_conn = RB_ROOT;
        (*rcm)->root_route = RB_ROOT;

        spin_lock_init(&(*rcm)->rcm_lock);
        spin_lock_init(&(*rcm)->route_lock);

        (*rcm)->sin.sin_family = AF_INET;
        (*rcm)->sin.sin_addr.s_addr = (__u32) (*rcm)->node_ip;
        (*rcm)->sin.sin_port = (__u16) htons(port);

        (*rcm)->cm_id = rdma_create_id(server_event_handler, *rcm, RDMA_PS_TCP,
                        IB_QPT_RC);
        if (IS_ERR((*rcm)->cm_id))
                goto err_cm_id;

        if ((ret = rdma_bind_addr((*rcm)->cm_id,
                        (struct sockaddr *) &((*rcm)->sin)))) {
                printk("{r = %d}\n", ret);
                goto err_bind;
        }

        if (!(*rcm)->cm_id->device)
                goto nodevice;

        (*rcm)->pd = ib_alloc_pd((*rcm)->cm_id->device);
        if (IS_ERR((*rcm)->pd))
                goto err_pd;

        (*rcm)->listen_cq = ib_create_cq((*rcm)->cm_id->device,
                        listener_cq_handle, NULL, (*rcm), 2, 0);
        if (IS_ERR((*rcm)->listen_cq))
                goto err_cq;

        if (ib_req_notify_cq((*rcm)->listen_cq, IB_CQ_NEXT_COMP))
                goto err_notify;

        (*rcm)->mr = ib_get_dma_mr(
                        (*rcm)->pd,
                        IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_READ
                                        | IB_ACCESS_REMOTE_WRITE);
        if (IS_ERR((*rcm)->mr))
                goto err_mr;

        return ret;

        err_mr: err_notify: ib_destroy_cq((*rcm)->listen_cq);
        err_cq: ib_dealloc_pd((*rcm)->pd);
        err_pd: err_bind: rdma_destroy_id((*rcm)->cm_id);
        err_cm_id: printk(">[create_rcm] Failed.\n");

        return ret;

        nodevice: printk(">[create_rcm] - NO DEVICE\n");

        return ret;
}

int create_connection(rcm *rcm, struct svm_data *conn_data) {
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
        if (unlikely(!ele))
                goto err;

        ele->remote_node_ip = inet_addr(conn_data->ip);

        insert_rb_conn(rcm, ele);

        ele->rcm = rcm;

        ele->cm_id = rdma_create_id(connection_event_handler, ele, RDMA_PS_TCP,
                        IB_QPT_RC);
        if (IS_ERR(ele->cm_id))
                goto err1;

        return rdma_resolve_addr(ele->cm_id, (struct sockaddr *) &src,
                        (struct sockaddr*) &dst, 2000);

        err1: erase_rb_conn(&rcm->root_conn, ele);
        vfree(ele);
        err: return -1;
}

void reg_rem_info(conn_element *ele) {
        ele->rid.remote_info->node_ip = ntohl(ele->rid.recv_info->node_ip);
        ele->rid.remote_info->buf_rx_addr =
                        ntohll(ele->rid.recv_info->buf_rx_addr);
        ele->rid.remote_info->buf_msg_addr =
                        ntohll(ele->rid.recv_info->buf_msg_addr);
        ele->rid.remote_info->rx_buf_size =
                        ntohl(ele->rid.recv_info->rx_buf_size);
        ele->rid.remote_info->rkey_msg = ntohl(ele->rid.recv_info->rkey_msg);
        ele->rid.remote_info->rkey_rx = ntohl(ele->rid.recv_info->rkey_rx);
        ele->rid.remote_info->flag = ele->rid.recv_info->flag;
}

void format_rdma_info(conn_element *ele) {

        ele->rid.send_info->node_ip = htonl(ele->rcm->node_ip);
        ele->rid.send_info->buf_rx_addr = htonll((u64) ele->rx_buffer.rx_buf);
        ele->rid.send_info->buf_msg_addr = htonll((u64) ele->tx_buffer.tx_buf);
        ele->rid.send_info->rx_buf_size = htonl(RX_BUF_ELEMENTS_NUM);
        ele->rid.send_info->rkey_msg = htonl(ele->mr->rkey);
        ele->rid.send_info->rkey_rx = htonl(ele->mr->rkey);
        ele->rid.send_info->flag = RDMA_INFO_CL;
}

void create_message(conn_element *ele, struct tx_buf_ele * tx_e,
                int message_num, int status) {
        struct dsm_message *msg = tx_e->dsm_msg;
        page_pool_ele * ppe = get_page_ele(ele);

        if (unlikely(!ppe)) {
                printk(">[create_message] - Cannot grab a page\n");
                return;
        }

        //in order to find the element on the reception of the page, and free it
        tx_e->wrk_req->dst_addr = ppe;

        msg->dest = (u32) ele->rid.recv_info->node_ip;
        msg->dst_addr = (u64) ppe->page_buf;
        msg->msg_num = message_num;
        msg->req_addr = 0;
        msg->rkey = ele->mr->rkey;
        msg->src = (u32) ele->rcm->node_ip;
        msg->status = status;

        return;
}

void create_page_request(conn_element *ele, struct tx_buf_ele * tx_e,
                struct dsm_vm_id local_id, struct dsm_vm_id remote_id,
                uint64_t addr, struct page *page) {
        struct dsm_message *msg = tx_e->dsm_msg;
        page_pool_ele * ppe = create_new_page_pool_element_from_page(ele, page);

        //in order to find the element on the reception of the page, and free it
        tx_e->wrk_req->dst_addr = ppe;

        msg->dest = dsm_vm_id_to_u32(&local_id);
        msg->dst_addr = (u64) ppe->page_buf;
        msg->msg_num = 0;
        msg->req_addr = addr;
        msg->rkey = ele->mr->rkey;
        msg->src = dsm_vm_id_to_u32(&remote_id);
        msg->status = REQ_PROC;

        return;
}

void free_page_ele(conn_element *ele, page_pool_ele * ppe) {
        if (likely(ppe)) {

                if (ppe->page_buf)
                        ib_dma_unmap_page(ele->cm_id->device,
                                        (u64) ppe->page_buf, PAGE_SIZE,
                                        DMA_BIDIRECTIONAL);
                if (ppe->mem_page)
                        __free_page(ppe->mem_page);

                kfree(ppe);

        }
        return;
}

page_pool_ele * get_page_ele(conn_element * ele) {
        page_pool_ele * ppe;

        struct page_pool * pp = &ele->page_pool;

        loop: spin_lock(&pp->page_pool_list_lock);
        if (list_empty(&pp->page_pool_list)) {
                spin_unlock(&pp->page_pool_list_lock);
                printk("[get_page_ele] forcing a page refill\n");
                release_replace_page_work(&ele->page_pool.page_release_work);
                goto loop;
        }

        ppe = list_first_entry(&pp->page_pool_list, page_pool_ele, page_ptr);
        list_del(&ppe->page_ptr);
        pp->nb_full_element--;
        spin_unlock(&pp->page_pool_list_lock);

        return ppe;

}

page_pool_ele * get_empty_page_ele(conn_element * ele) {
        page_pool_ele * ppe;

        struct page_pool * pp = &ele->page_pool;

        loop: spin_lock(&pp->page_pool_empty_list_lock);
        if (list_empty(&pp->page_empty_pool_list)) {
                spin_unlock(&pp->page_pool_empty_list_lock);
                printk("[get_empty_page_ele] forcing a page refill\n");
                release_replace_page_work(&ele->page_pool.page_release_work);
                goto loop;
        }

        ppe =
                        list_first_entry(&pp->page_empty_pool_list , page_pool_ele, page_ptr);
        list_del(&ppe->page_ptr);
        spin_unlock(&pp->page_pool_empty_list_lock);

        return ppe;

}

/*
 * Allocates a new page, register it, warp it in a page pool element stucture and and this ppe to the list
 * Registered as DMA_BIDIRECTIONNAL as it could be use as a send or receiving buffer.
 */
int create_new_page_pool_element(conn_element * ele) {
        struct page_pool * pp = &ele->page_pool;
        int ret = 0;
        struct page_pool_ele *ppe;

        ppe = kmalloc(sizeof(page_pool_ele), GFP_USER);
        memset(ppe, 0, sizeof(page_pool_ele));

        ppe->mem_page = alloc_page( GFP_USER | __GFP_ZERO);
        if (unlikely(!ppe->mem_page))
                goto err1;

        ppe->page_buf = (void *) ib_dma_map_page(ele->cm_id->device,
                        ppe->mem_page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
        if (ib_dma_mapping_error(ele->cm_id->device,
                        (u64) (unsigned long) ppe->page_buf))
                goto err2;

        spin_lock(&pp->page_pool_list_lock);
        list_add_tail(&ppe->page_ptr, &pp->page_pool_list);
        pp->nb_full_element++;
        spin_unlock(&pp->page_pool_list_lock);

        return ret;

        err2: ret++;
        err1: ret++;

        return ret;
}

int create_new_empty_page_pool_element(conn_element * ele) {
        struct page_pool * pp = &ele->page_pool;

        struct page_pool_ele *ppe;

        ppe = kmalloc(sizeof(page_pool_ele), GFP_ATOMIC);
        if (!ppe)
                return -1;
        memset(ppe, 0, sizeof(page_pool_ele));

        spin_lock(&pp->page_pool_empty_list_lock);
        list_add_tail(&ppe->page_ptr, &pp->page_empty_pool_list);
        spin_unlock(&pp->page_pool_empty_list_lock);
        return 0;

}

struct page_pool_ele * create_new_page_pool_element_from_page(
                conn_element * ele, struct page *page) {
        struct page_pool_ele *ppe;

        ppe = get_empty_page_ele(ele);
        ppe->mem_page = page;
        if (unlikely(!ppe->mem_page))
                return NULL;

        ppe->page_buf = (void *) ib_dma_map_page(ele->cm_id->device,
                        ppe->mem_page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
        if (ib_dma_mapping_error(ele->cm_id->device,
                        (u64) (unsigned long) ppe->page_buf))
                return NULL;

        return ppe;

}

int create_page_pool(conn_element * ele) {
        int ret = 0;
        int i;
        struct page_pool * pp = &ele->page_pool;
        pp->nb_full_element = 0;
        spin_lock_init(&pp->page_pool_list_lock);
        spin_lock_init(&pp->page_release_lock);
        spin_lock_init(&pp->page_pool_empty_list_lock);
        spin_lock_init(&pp->page_recycle_lock);

        INIT_WORK(&pp->page_release_work, release_replace_page_work);
        INIT_LIST_HEAD(&pp->page_pool_list);
        INIT_LIST_HEAD(&pp->page_empty_pool_list);
        INIT_LIST_HEAD(&pp->page_recycle_list);
        INIT_LIST_HEAD(&pp->page_release_list);
        for (i = 0; i < PAGE_POOL_SIZE; i++) {
                ret = create_new_page_pool_element(ele);
                if (ret)
                        break;
        }

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

int create_rdma_info(conn_element *ele) {
        int size = sizeof(rdma_info);
        struct rdma_info_data * rid = &ele->rid;

        rid->send_mem = vmalloc(size);
        if (unlikely(!rid->send_mem))
                goto send_mem_err;

        rid->send_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device,
                        rid->send_mem, size, DMA_TO_DEVICE);
        if (unlikely(!rid->send_info))
                goto send_info_err;

        rid->recv_mem = vmalloc(size);
        if (unlikely(!rid->send_mem))
                goto recv_mem_err;

        rid->recv_info = (rdma_info *) ib_dma_map_single(ele->cm_id->device,
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
                        (u64) (unsigned long) rid->recv_info, sizeof(rdma_info),
                        DMA_FROM_DEVICE);

        recv_info_err: printk(
                        ">[create_rdma_info] - ERROR : NO RECV INFO BUFFER\n");
        vfree(rid->recv_mem);

        recv_mem_err: printk(
                        ">[create_rdma_info] - no memory allocated for the reception buffer\n");
        ib_dma_unmap_single(ele->cm_id->device,
                        (u64) (unsigned long) rid->send_info, sizeof(rdma_info),
                        DMA_TO_DEVICE);

        send_info_err: printk(
                        ">[create_rdma_info] - ERROR : NO SEND INFO BUFFER\n");
        vfree(rid->send_mem);

        send_mem_err: printk(
                        ">[create_rdma_info] - no memory allocated for the sending buffer\n");
        return -1;
}

int setup_connection(conn_element *ele, int type) {
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

        if (create_dsm_stats_data(&ele->stats))
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
        printk(
                        ">[setup_connection] - Could not setup connection : error %d occurred\n",
                        err);
        return err;
}

tx_buf_ele * try_get_next_empty_tx_ele(conn_element *ele) {

        tx_buf_ele *tx_e;
        struct tx_buffer * tx = &ele->tx_buffer;

        if (!tx) {
                printk(
                                ">[try_get_next_empty_tx_ele] - no connection element\n");
        }

        spin_lock(&tx->tx_free_elements_list_lock);

        if (list_empty(&tx->tx_free_elements_list)) {

                spin_unlock(&tx->tx_free_elements_list_lock);

                return NULL;
        }

        tx_e= list_first_entry(&tx->tx_free_elements_list, struct tx_buf_ele, tx_buf_ele_ptr);
        list_del(&tx_e->tx_buf_ele_ptr);
        spin_unlock(&tx->tx_free_elements_list_lock);

        return tx_e;

}

tx_buf_ele * get_next_empty_tx_ele(conn_element *ele) {

        tx_buf_ele *tx_e;
        struct timespec time;
        struct tx_buffer * tx = &ele->tx_buffer;

        dsm_stats_get_time_request(&time);
        wait_for_completion_interruptible(&tx->completion_free_tx_element);
        spin_lock(&tx->tx_free_elements_list_lock);
        BUG_ON(list_empty(&tx->tx_free_elements_list));

        tx_e= list_first_entry(&tx->tx_free_elements_list, struct tx_buf_ele, tx_buf_ele_ptr);
        list_del(&tx_e->tx_buf_ele_ptr);
        spin_unlock(&tx->tx_free_elements_list_lock);
        dsm_stats_set_time_request(&tx_e->stats, time);
        return tx_e;

}

tx_buf_ele * try_get_next_empty_tx_reply_ele(conn_element *ele) {

        tx_buf_ele *tx_e;
        struct tx_buffer * tx = &ele->tx_buffer;

        spin_lock(&tx->tx_free_elements_list_reply_lock);

        if (list_empty(&tx->tx_free_elements_list_reply)) {

                spin_unlock(&tx->tx_free_elements_list_reply_lock);

                return NULL;
        }

        tx_e= list_first_entry(&tx->tx_free_elements_list_reply, struct tx_buf_ele, tx_buf_ele_ptr);
        list_del(&tx_e->tx_buf_ele_ptr);
        spin_unlock(&tx->tx_free_elements_list_reply_lock);

        return tx_e;

}

int init_tx_lists(conn_element *ele) {
        int i;
        struct tx_buffer * tx = &ele->tx_buffer;
        int max_tx_send = TX_BUF_ELEMENTS_NUM / 3;
        int max_tx_reply = TX_BUF_ELEMENTS_NUM;

        INIT_LIST_HEAD(&tx->tx_free_elements_list);
        INIT_LIST_HEAD(&tx->tx_free_elements_list_reply);
        spin_lock_init(&tx->tx_free_elements_list_lock);
        spin_lock_init(&tx->tx_free_elements_list_reply_lock);

        init_completion(&tx->completion_free_tx_element);

        for (i = 0; i < max_tx_send; ++i) {
                release_tx_element(ele, &tx->tx_buf[i]);

        }

        for (; i < max_tx_reply; ++i) {
                release_tx_element_reply(ele, &tx->tx_buf[i]);

        }

        return 0;
}

void init_reply_wr(reply_work_request *rwr, u64 msg_addr, u32 lkey, int id) {
        struct ib_sge * reply_sge = &rwr->wr_ele->sg;
        rwr->wr_ele->dsm_msg = (dsm_message *) msg_addr;

        reply_sge->addr = msg_addr;
        reply_sge->length = sizeof(dsm_message);
        reply_sge->lkey = lkey;

        rwr->wr_ele->wr.next = NULL;
        rwr->wr_ele->wr.num_sge = 1;
        rwr->wr_ele->wr.send_flags = IB_SEND_SIGNALED;
        rwr->wr_ele->wr.opcode = IB_WR_SEND;
        rwr->wr_ele->wr.sg_list = (struct ib_sge *) &rwr->wr_ele->sg;
        rwr->wr_ele->wr.wr_id = id;
}

void init_page_wr(reply_work_request *rwr, u32 lkey, int id) {
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

void init_tx_wr(tx_buf_ele *tx_ele, u32 lkey, int id) {
        tx_ele->wrk_req->wr_ele->wr.wr_id = (u64) id;
        tx_ele->wrk_req->wr_ele->wr.opcode = IB_WR_SEND;
        tx_ele->wrk_req->wr_ele->wr.send_flags = IB_SEND_SIGNALED;
        tx_ele->wrk_req->wr_ele->wr.num_sge = 1;
        tx_ele->wrk_req->wr_ele->wr.sg_list =
                        (struct ib_sge *) &tx_ele->wrk_req->wr_ele->sg;

        tx_ele->wrk_req->wr_ele->sg.addr = (u64) tx_ele->dsm_msg;
        tx_ele->wrk_req->wr_ele->sg.length = sizeof(dsm_message);
        tx_ele->wrk_req->wr_ele->sg.lkey = lkey;

        tx_ele->wrk_req->wr_ele->wr.next = NULL;
}

void init_tx_ele(tx_buf_ele * tx_ele, conn_element *ele, int id) {
        tx_ele->id = id;
        init_tx_wr(tx_ele, ele->mr->lkey, id);
        init_reply_wr(tx_ele->reply_work_req, (u64) tx_ele->dsm_msg,
                        ele->mr->lkey, tx_ele->id);
        init_page_wr(tx_ele->reply_work_req, ele->mr->lkey, tx_ele->id);
        tx_ele->dsm_msg->dest = ele->mr->rkey;
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
int create_tx_buffer(conn_element *ele) {
        int i = 0;
        int undo;
        int ret = 0;

        struct tx_buf_ele * tx_buff_e = kmalloc(
                        (sizeof(tx_buf_ele) * TX_BUF_ELEMENTS_NUM), GFP_KERNEL);
        if (unlikely(!tx_buff_e)) {
                ret = -1;
                goto err_buf;
        }
        ele->tx_buffer.tx_buf = tx_buff_e;
        for (i = 0; i < TX_BUF_ELEMENTS_NUM; ++i) {
                tx_buff_e[i].mem = vmalloc(sizeof(dsm_message));
                if (unlikely(!tx_buff_e[i].mem))
                        goto err1;

                tx_buff_e[i].dsm_msg = (dsm_message *) ib_dma_map_single(
                                ele->cm_id->device, tx_buff_e[i].mem,
                                sizeof(dsm_message), DMA_TO_DEVICE);
                if (unlikely(!tx_buff_e[i].dsm_msg))
                        goto err2;

                memset(tx_buff_e[i].dsm_msg, 0, sizeof(dsm_message));

                tx_buff_e[i].wrk_req = kmalloc(sizeof(msg_work_request),
                                GFP_KERNEL);
                if (unlikely(!tx_buff_e[i].wrk_req))
                        goto err3;

                memset(tx_buff_e[i].wrk_req, 0, sizeof(msg_work_request));

                tx_buff_e[i].wrk_req->wr_ele = kmalloc(sizeof(work_request_ele),
                                GFP_KERNEL);
                if (unlikely(!tx_buff_e[i].wrk_req->wr_ele))
                        goto err4;

                memset(tx_buff_e[i].wrk_req->wr_ele, 0,
                                sizeof(work_request_ele));

                tx_buff_e[i].wrk_req->wr_ele->dsm_msg = tx_buff_e[i].dsm_msg;

                tx_buff_e[i].reply_work_req = kmalloc(
                                sizeof(reply_work_request), GFP_KERNEL);
                if (!tx_buff_e[i].reply_work_req)
                        goto err5;
                memset(tx_buff_e[i].reply_work_req, 0,
                                sizeof(reply_work_request));

                tx_buff_e[i].reply_work_req->wr_ele = kmalloc(
                                sizeof(work_request_ele), GFP_KERNEL);
                if (!tx_buff_e[i].reply_work_req->wr_ele)
                        goto err6;
                memset(tx_buff_e[i].reply_work_req->wr_ele, 0,
                                sizeof(work_request_ele));

                init_tx_ele(&tx_buff_e[i], ele, i);
        }

        return ret;

        err7: kfree(tx_buff_e[i].reply_work_req->wr_ele);
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
                        sizeof(dsm_message), DMA_TO_DEVICE);
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
                                sizeof(dsm_message), DMA_TO_DEVICE);
                vfree(tx_buff_e[undo].mem);
        }

        memset(tx_buff_e, 0, sizeof(tx_buf_ele) * TX_BUF_ELEMENTS_NUM);
        kfree(tx_buff_e);
        ele->tx_buffer.tx_buf = NULL;
        printk("> [create_tx_buffer][ERR] - Zeroing the tx buffer\n");
        ++ret;

        err_buf: printk(
                        ">[create_tx_buffer][ERR] - TX BUFFER NOT CREATED - index %d\n",
                        i);
        return ret;
}

int refill_recv_wr(conn_element *ele, rx_buf_ele * rx_e) {

        int ret = 0;
        ret = ib_post_recv(ele->cm_id->qp, &rx_e->recv_wrk_rq_ele->sq_wr,
                        &rx_e->recv_wrk_rq_ele->bad_wr);
        if (ret)
                printk(
                                ">[refill_recv_wr] - ERROR IN POSTING THE RECV WR ret : %d on offset %d\n",
                                ret, rx_e->id);

        return ret;
}

void release_tx_element(conn_element * ele, tx_buf_ele * tx_e) {

        struct tx_buffer * tx = &ele->tx_buffer;
        spin_lock(&tx->tx_free_elements_list_lock);
        list_add_tail(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list);
        spin_unlock(&tx->tx_free_elements_list_lock);
        complete(&tx->completion_free_tx_element);

}
void release_tx_element_reply(conn_element * ele, tx_buf_ele * tx_e) {

        struct tx_buffer * tx = &ele->tx_buffer;
        spin_lock(&tx->tx_free_elements_list_reply_lock);
        list_add_tail(&tx_e->tx_buf_ele_ptr, &tx->tx_free_elements_list_reply);
        spin_unlock(&tx->tx_free_elements_list_reply_lock);

}

void try_recycle_page_pool_element(conn_element *ele, page_pool_ele * ppe) {

        struct page_pool * pp = &ele->page_pool;
        spin_lock(&pp->page_pool_list_lock);
        if (pp->nb_full_element < PAGE_POOL_SIZE) {
                memset(ppe->page_buf, 0, RDMA_PAGE_SIZE);
                list_add_tail(&ppe->page_ptr, &pp->page_pool_list);
                pp->nb_full_element++;

        } else {
                spin_lock(&pp->page_pool_empty_list_lock);

                ib_dma_unmap_page(ele->cm_id->device, (u64) ppe->page_buf,
                                PAGE_SIZE, DMA_BIDIRECTIONAL);
                __free_page(ppe->mem_page);

                list_add_tail(&ppe->page_ptr, &pp->page_empty_pool_list);
                spin_unlock(&pp->page_pool_empty_list_lock);

        }
        spin_unlock(&pp->page_pool_list_lock);
}

void try_regenerate_empty_page_pool_element(conn_element *ele,
                page_pool_ele * ppe) {

        struct page_pool * pp = &ele->page_pool;

        ib_dma_unmap_page(ele->cm_id->device, (u64) ppe->page_buf, PAGE_SIZE,
                        DMA_BIDIRECTIONAL);

        spin_lock(&pp->page_pool_list_lock);
        if (pp->nb_full_element < PAGE_POOL_SIZE) {

                ppe->mem_page = alloc_page( GFP_ATOMIC | __GFP_ZERO);
                BUG_ON(!ppe->mem_page);

                ppe->page_buf = (void *) ib_dma_map_page(ele->cm_id->device,
                                ppe->mem_page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
                if (ib_dma_mapping_error(ele->cm_id->device,
                                (u64) (unsigned long) ppe->page_buf))
                        errk(
                                        "[try_regenerate_empty_page_pool_element] couldn't map page \n");

                list_add_tail(&ppe->page_ptr, &pp->page_pool_list);
                pp->nb_full_element++;

        } else {
                spin_lock(&pp->page_pool_empty_list_lock);

                list_add_tail(&ppe->page_ptr, &pp->page_empty_pool_list);
                spin_unlock(&pp->page_pool_empty_list_lock);

        }
        spin_unlock(&pp->page_pool_list_lock);
}

void release_replace_page_work(struct work_struct *work) {
        page_pool_ele * ppe = NULL;

        conn_element * ele;
        struct page_pool * pp;
        pp= container_of(work, struct page_pool ,page_release_work );
        ele= container_of(pp, struct conn_element ,page_pool );

        do {
                spin_lock(&pp->page_recycle_lock);
                if (list_empty(&pp->page_recycle_list)) {
                        spin_unlock(&pp->page_recycle_lock);
                        break;
                }
                ppe =
                                list_first_entry(&pp->page_recycle_list, page_pool_ele, page_ptr);
                list_del(&ppe->page_ptr);
                spin_unlock(&pp->page_recycle_lock);
                try_recycle_page_pool_element(ele, ppe);
        } while (1);

        do {
                spin_lock(&pp->page_release_lock);
                if (list_empty(&pp->page_release_list)) {
                        spin_unlock(&pp->page_release_lock);
                        break;
                }
                ppe =
                                list_first_entry(&pp->page_release_list, page_pool_ele, page_ptr);
                list_del(&ppe->page_ptr);
                spin_unlock(&pp->page_release_lock);
                try_regenerate_empty_page_pool_element(ele, ppe);
        } while (1);

}

void release_replace_page(conn_element * ele, struct tx_buf_ele * tx_e) {

        struct page_pool * pp = &ele->page_pool;
        page_pool_ele * ppe = (page_pool_ele *) tx_e->wrk_req->dst_addr;
        tx_e->wrk_req->dst_addr = NULL;
        if (ppe->mem_page) {
                spin_lock(&pp->page_recycle_lock);
                list_add_tail(&ppe->page_ptr, &pp->page_recycle_list);
                spin_unlock(&pp->page_recycle_lock);
        } else {
                spin_lock(&pp->page_release_lock);
                list_add_tail(&ppe->page_ptr, &pp->page_release_list);
                spin_unlock(&pp->page_release_lock);
        }
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
int setup_recv_wr(conn_element *ele) {
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

void init_recv_wr(rx_buf_ele *rx_ele, conn_element * ele) {
        struct recv_work_req_ele * rwr = rx_ele->recv_wrk_rq_ele;
        struct ib_sge * recv_sge = &rwr->recv_sgl;

        recv_sge->addr = (u64) rx_ele->dsm_msg;
        recv_sge->length = sizeof(dsm_message);
        recv_sge->lkey = ele->mr->lkey;

        rwr->sq_wr.next = NULL;
        rwr->sq_wr.num_sge = 1;
        rwr->sq_wr.sg_list = &rwr->recv_sgl;
        rwr->sq_wr.wr_id = rx_ele->id;
}

void init_rx_ele(rx_buf_ele *rx_ele, conn_element *ele) {
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
int create_rx_buffer(conn_element *ele) {
        int i;
        int undo = 0;
        struct rx_buf_ele * rx = kmalloc(
                        (sizeof(rx_buf_ele) * RX_BUF_ELEMENTS_NUM), GFP_KERNEL);

        if (!rx)
                goto err_buf;

        ele->rx_buffer.rx_buf = rx;
        memset(rx, 0, (sizeof(rx_buf_ele) * RX_BUF_ELEMENTS_NUM));

        for (i = 0; i < RX_BUF_ELEMENTS_NUM; ++i) {
                rx[i].mem = vmalloc(sizeof(dsm_message));
                if (!rx[i].mem)
                        goto err1;
                memset(rx[i].mem, 0, sizeof(dsm_message));

                rx[i].dsm_msg = (dsm_message *) ib_dma_map_single(
                                ele->cm_id->device, rx[i].mem,
                                sizeof(dsm_message), DMA_BIDIRECTIONAL);
                if (!rx[i].dsm_msg)
                        goto err2;

                rx[i].recv_wrk_rq_ele = kmalloc(sizeof(recv_work_req_ele),
                                GFP_KERNEL);
                if (!rx[i].recv_wrk_rq_ele)
                        goto err3;
                memset(rx[i].recv_wrk_rq_ele, 0, sizeof(recv_work_req_ele));

                rx[i].id = i;

                init_rx_ele(&rx[i], ele);
        }

        return 0;

        err3: ib_dma_unmap_single(ele->cm_id->device,
                        (u64) (unsigned long) rx[i].dsm_msg,
                        sizeof(dsm_message), DMA_FROM_DEVICE);
        err2: vfree(rx[i].mem);

        err1: for (undo = 0; undo < i; ++undo) {
                ib_dma_unmap_single(ele->cm_id->device,
                                (u64) (unsigned long) rx[undo].dsm_msg,
                                sizeof(dsm_message), DMA_FROM_DEVICE);
                vfree(rx[undo].mem);
                kfree(rx[undo].recv_wrk_rq_ele);
        }

        memset(rx, 0, sizeof(rx_buf_ele) * RX_BUF_ELEMENTS_NUM);
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
int create_qp(conn_element *ele) {
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

int setup_qp(conn_element *ele) {
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
        printk(">[setup_qp] - Could not setup the qp, error %d occurred\n",
                        ret);
        return ret;
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
        int a, b, c, d;
        char arr[4];

        sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d);
        arr[0] = a;
        arr[1] = b;
        arr[2] = c;
        arr[3] = d;
        return *(unsigned int*) arr;
}

