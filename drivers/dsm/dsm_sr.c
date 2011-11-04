/*
 * dsm_sr.c
 *
 *  Created on: 26 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_sr.h>
#include <dsm/dsm_core.h>

/**
 * Read the message received in the wc, to get the offset and then find where the page has been written
 *
 * RETURN 0 if a page exists in the buffer at this offset
 *               -1 if the page cannot be found
 */
int process_response(conn_element *ele, struct tx_buf_ele * tx_buf_e) {

        if (tx_buf_e->callback.func) {
                tx_buf_e->callback.func(tx_buf_e, tx_buf_e->callback.data);
        }
        release_replace_page(ele, tx_buf_e);
        release_tx_element(ele, tx_buf_e);

        return 0;
}

int rx_tx_message_transfer(conn_element * ele, struct rx_buf_ele * rx_buf_e) {
        page_pool_ele * ppe;
        tx_buf_ele *tx_e = NULL;
        struct page * page;
        int ret = 0;

        //Find a free slot in the TX buffer

        tx_e = try_get_next_empty_tx_reply_ele(ele);
        if (!tx_e) {
                printk(
                                ">[rx_tx_message_transfer][FATAL_ERROR] - Shouldn't be empty at that stage\n");
                return -1;
        }

        if (unlikely(tx_e->wrk_req->dst_addr))
                printk(
                                "[rx_tx_message_transfer][FATAL_ERROR] this slot has a link to a former page\n");
        //Then get a new page
        page = dsm_extract_page_from_remote(rx_buf_e->dsm_msg);
        if (unlikely(!page)) {
                printk(
                                "[rx_tx_message_transfer][FATAL_ERROR] - Couldn't grab a the page\n");
                return -1;
        }
        ppe = create_new_page_pool_element_from_page(ele, page);
        if (unlikely(!ppe)) {
                printk(
                                "[rx_tx_message_transfer][FATAL_ERROR] - couldn't create papge pool element\n");
                return -1;
        }

        //Copy the received message in it
        memcpy(tx_e->dsm_msg, rx_buf_e->dsm_msg, sizeof(dsm_message));
        tx_e->dsm_msg->status = REQ_RCV_PROC;
        //Filling up the response details
        tx_e->reply_work_req->wr.wr.rdma.remote_addr = tx_e->dsm_msg->dst_addr;
        tx_e->reply_work_req->wr.wr.rdma.rkey = tx_e->dsm_msg->rkey;
        tx_e->wrk_req->dst_addr = ppe;
        tx_e->reply_work_req->page_sgl.addr = (u64) ppe->page_buf;

        ret = tx_dsm_send(ele, tx_e);
        return ret;
}

int request_dsm_page(conn_element *ele, struct dsm_vm_id local_id,
                struct dsm_vm_id remote_id, uint64_t addr,
                void(*func)(struct tx_buf_ele *, unsigned long),
                unsigned long data) {
        struct tx_buf_ele *tx_e;
        int ret = 0;

        //find free slot

        tx_e = get_next_empty_tx_ele(ele);

        //populate it with a new message
        create_page_request(ele, tx_e, local_id, remote_id, addr);

        if (func) {
                tx_e->callback.func = func;
                tx_e->callback.data = data;
        } else {
                tx_e->callback.func = NULL;
        }
        if (!ele->cm_id->qp)
                printk(">[send_dsm_message] - no more qp\n");

        ret = tx_dsm_send(ele, tx_e);
        return ret;

}

int send_dsm_message(conn_element *ele, int nb,
                void(*func)(struct tx_buf_ele *, unsigned long),
                unsigned long data) {
        struct tx_buf_ele *tx_e;
        int ret = 0;

        //find free slot

        tx_e = get_next_empty_tx_ele(ele);

        //populate it with a new message
        create_message(ele, tx_e, nb, REQ_PROC);

        if (func) {
                tx_e->callback.func = func;
                tx_e->callback.data = data;
        } else {
                tx_e->callback.func = NULL;
        }
        if (!ele->cm_id->qp)
                printk(">[send_dsm_message] - no more qp\n");

        ret = tx_dsm_send(ele, tx_e);
        return ret;

}

int tx_dsm_send(conn_element * ele, struct tx_buf_ele *tx_e) {
        int ret = 0;
        stats_update_time_send(&tx_e->stats);
        switch (tx_e->dsm_msg->status) {
                case REQ_PROC: {

                        ret = ib_post_send(ele->cm_id->qp,
                                        &tx_e->wrk_req->wr_ele->wr,
                                        &tx_e->wrk_req->wr_ele->bad_wr);
                        break;
                }
                case REQ_RCV_PROC: {
                        ret = ib_post_send(ele->cm_id->qp,
                                        &tx_e->reply_work_req->wr,
                                        &tx_e->reply_work_req->wr_ele->bad_wr);
                        break;
                }
                default: {
                        printk(
                                        ">[tx_flush_queue][ERROR] - wrong message status\n");
                        ret = 1;
                }
        }
        if (unlikely(ret))
                printk(
                                ">[tx_flush_queue][ERROR] - ib_post_send failed ret : %d\n",
                                ret);

        return ret;
}

/**
 * Before the connection can be used, the nodes need to have these information about each other :
 *      u8      flag;
 *      u16 node_ip;
 *      u64 buf_msg_addr;
 *      u32 rkey_msg;
 *      u64 buf_rx_addr;
 *      u32 rkey_rx;
 *      u32 rx_buf_size;
 */
int exchange_info(conn_element *ele, int id) {
        int flag = (int) ele->rid.remote_info->flag;
        int ret = 0;
        conn_element * ele_found;

        if (unlikely(!ele->rid.recv_info))
                goto err;

        switch (flag) {
                case RDMA_INFO_CL: {

                        --ele->rid.send_info->flag;

                        goto recv_send;
                }
                case RDMA_INFO_SV: {

                        ret = dsm_recv_info(ele);
                        if (ret) {
                                printk(
                                                ">[exchange_info] - Could not post the receive work request\n");
                                goto err;
                        }

                        ele->rid.send_info->flag = ele->rid.send_info->flag - 2;
                        ret = setup_recv_wr(ele);

                        goto send;
                }
                case RDMA_INFO_READY_CL: {

                        ele->rid.send_info->flag = ele->rid.send_info->flag - 2;
                        ret = setup_recv_wr(ele);
                        refill_recv_wr(
                                        ele,
                                        &ele->rx_buffer.rx_buf[RX_BUF_ELEMENTS_NUM
                                                        - 1]);
                        ele->rid.remote_info->flag = RDMA_INFO_NULL;

                        ele->remote_node_ip =
                                        (int) ele->rid.remote_info->node_ip;
                        ele_found = search_rb_conn(ele->rcm,
                                        ele->remote_node_ip);

                        // We find that a connection is already open with that node - delete this connection request.
                        if (ele_found) {
                                printk(
                                                ">[exchange_info] - destroy_connection duplicate : %d\n former : %d\n",
                                                ele->remote_node_ip,
                                                ele_found->remote_node_ip);
                                rdma_disconnect(ele->cm_id);
                        }
                        //ok, inserting this connection to the tree
                        else {
                                insert_rb_conn(ele->rcm, ele);
                                printk(
                                                ">[exchange_info] inserted conn_element to rb_tree :  %d\n",
                                                ele->remote_node_ip);
                        }

                        goto send;

                }
                case RDMA_INFO_READY_SV: {
                        refill_recv_wr(
                                        ele,
                                        &ele->rx_buffer.rx_buf[RX_BUF_ELEMENTS_NUM
                                                        - 1]);

                        ele->rid.remote_info->flag = RDMA_INFO_NULL;
                        //Server acknowledged --> connection is complete.
                        //start sending messages.

                        goto out;
                }
                default: {
                        printk(">[exchange_info] - UNKNOWN RDMA INFO FLAG\n");
                        goto out;
                }
        }

        recv_send: ret = dsm_recv_info(ele);
        if (ret) {
                printk(
                                ">[exchange_info] - Could not post the receive work request\n");
                goto err;
        }

        send: ret = dsm_send_info(ele);
        if (ret < 0) {
                printk(
                                ">[exchange_info] - Could not post the send work request\n");
                goto err;
        }

        out: return ret;

        err: printk(">[exchange_info] - No receive info\n");
        return ret;

}

/**
 * Creating and posting the work request that sends its info over.
 *
 * RETURN dsm_post_send
 */

int dsm_send_info(conn_element *ele) {
        struct rdma_info_data *rid = &ele->rid;

        rid->send_sge.addr = (u64) rid->send_info;
        rid->send_sge.length = sizeof(rdma_info);
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

/**
 * Creating and posting the work request that receives remote info
 *
 * RETURN ib_post_recv
 */
int dsm_recv_info(conn_element *ele) {
        struct rdma_info_data *rid = &ele->rid;

        rid->recv_sge.addr = (u64) rid->recv_info;
        rid->recv_sge.length = sizeof(rdma_info);
        rid->recv_sge.lkey = ele->mr->lkey;

        rid->recv_wr.next = NULL;
        rid->recv_wr.wr_id = 0; // DSM2: unique id - address of data_struct
        rid->recv_wr.num_sge = 1;
        rid->recv_wr.sg_list = &rid->recv_sge;

        return ib_post_recv(ele->cm_id->qp, &rid->recv_wr, &rid->recv_bad_wr);

}
