/*
 *  Benoit Hudzia <benoit.hudzia@sap.com>
 *  Aidan Shribman <aidan.shribman@sap.com>
 */

#include <dsm/dsm_module.h>

#include <dsm/dsm_trace.h>

static struct kmem_cache *kmem_request_cache;


static inline void init_kmem_request_cache_elm(void *obj) {
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

void release_dsm_request(struct dsm_request *req)
{
    kmem_cache_free(kmem_request_cache, req);
}

static inline void queue_dsm_request(struct conn_element *ele,
        struct dsm_request *req) {
    trace_queued_request(0, 0, 0, 0, req->addr, req->type);
    llist_add(&req->lnode, &ele->tx_buffer.request_queue);
    schedule_delayed_request_flush(ele);

}

static int add_dsm_request(struct dsm_request *req, struct conn_element *ele,
        u16 type, struct subvirtual_machine *fault_svm,
        struct subvirtual_machine *svm, uint64_t addr,
        int (*func)(struct tx_buf_ele *), struct dsm_page_cache *dpc,
        struct page *page)
{
    if (!req) {
        req = kmem_cache_alloc(kmem_request_cache, GFP_KERNEL);
        if (unlikely(!req))
            return -ENOMEM;
    }

    req->type = type;
    req->fault_svm = fault_svm;
    req->svm = svm;
    req->addr = addr;
    req->func = func;
    req->dpc = dpc;
    req->page = page;

    queue_dsm_request(ele, req);

    return 0;
}

static int add_dsm_request_msg(struct conn_element *ele, u16 type,
        struct dsm_message *msg)
{
    struct dsm_request *req = kmem_cache_alloc(kmem_request_cache, GFP_KERNEL);
    if (unlikely(!req))
        return -ENOMEM;

    req->type = type;
    memcpy(&req->dsm_buf, msg, sizeof(struct dsm_message));
    queue_dsm_request(ele, req);

    return 0;
}

inline int request_queue_empty(struct conn_element *ele)
{
    /* we are not 100% accurate but that's ok we can have a few send sneaking in */
    if ( llist_empty(&ele->tx_buffer.request_queue) && list_empty(&ele->tx_buffer.ordered_request_queue) )
       return 1;
    return 0;

}

static inline int request_queue_full(struct conn_element *ele)
{
    return ele->tx_buffer.request_queue_sz > get_max_pushed_reqs(ele);
}

static int send_request_dsm_page_pull(struct subvirtual_machine *fault_svm,
        struct svm_list svms, unsigned long addr)
{
    struct tx_buf_ele *tx_elms[svms.num];
    struct dsm_request *reqs[svms.num];
    int i, j, r = 0;

    for_each_valid_svm(svms, i) {
        tx_elms[i] = NULL;
        reqs[i] = NULL;

        if (request_queue_empty(svms.pp[i]->ele))
            tx_elms[i] = try_get_next_empty_tx_ele(svms.pp[i]->ele);

        if (!tx_elms[i]) {
            reqs[i] = kmem_cache_alloc(kmem_request_cache, GFP_KERNEL);
            if (!reqs[i])
                goto nomem;
        }
    }

    for_each_valid_svm(svms, i) {
        if (tx_elms[i]) {
            create_page_pull_request(svms.pp[i]->ele, tx_elms[i],
                    fault_svm->dsm->dsm_id, fault_svm->svm_id,
                    svms.pp[i]->svm_id, (uint64_t) addr);
            tx_elms[i]->callback.func = NULL;
            tx_dsm_send(svms.pp[i]->ele, tx_elms[i]);
        } else {
            BUG_ON(!reqs[i]);
            r |= add_dsm_request(reqs[i], svms.pp[i]->ele, REQUEST_PAGE_PULL,
                    fault_svm, svms.pp[i], addr, NULL, NULL, NULL);
        }
    }

    return r;

nomem:
    for (j = 0; j < i; j++) {
        if (unlikely(!svms.pp[j]))
            continue;

        if (tx_elms[j])
            release_tx_element(svms.pp[j]->ele, tx_elms[j]);
        else 
            kmem_cache_free(kmem_request_cache, reqs[j]);
    }
    return -ENOMEM;
}

static int send_svm_status_update(struct conn_element *ele,
        struct rx_buf_ele *rx_buf_e)
{
    struct tx_buf_ele *tx_e = NULL;
    int ret = 0;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (likely(tx_e)) {
            memcpy(tx_e->dsm_buf, rx_buf_e->dsm_buf,
                    sizeof(struct dsm_message));
            tx_e->dsm_buf->type = SVM_STATUS_UPDATE;
            ret = tx_dsm_send(ele, tx_e);
            goto out;
        }
    }

    ret = add_dsm_request_msg(ele, SVM_STATUS_UPDATE, rx_buf_e->dsm_buf);

out:
    return ret;
}

int request_dsm_page(struct page *page, struct subvirtual_machine *remote_svm,
        struct subvirtual_machine *fault_svm, uint64_t addr,
        int (*func)(struct tx_buf_ele *), int tag, struct dsm_page_cache *dpc)
{

    struct conn_element *ele;
    struct tx_buf_ele *tx_e;
    int ret = -EINVAL;
    int req_tag = (tag == PULL_TRY_TAG) ? TRY_REQUEST_PAGE : REQUEST_PAGE;

    /*
     * Svm has been fenced out; fail silently (another svm should answer, if
     * available).
     *
     */
    if (!remote_svm)
        goto out;

    ele = remote_svm->ele;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (tx_e) {
            create_page_request(ele, tx_e, fault_svm->dsm->dsm_id,
                    fault_svm->svm_id, remote_svm->svm_id, addr, page, req_tag,
                    dpc);

            tx_e->callback.func = func;
            ret = tx_dsm_send(ele, tx_e);
            trace_send_request(fault_svm->dsm->dsm_id, fault_svm->svm_id,
                        ret, ret, addr, tag);
            goto out;
        }
    }

    ret = add_dsm_request(NULL, ele, req_tag, fault_svm, remote_svm,
            addr, func, dpc, page);
    BUG_ON(ret); /* FIXME: Handle req alloc failure */

out: 
    return ret;
}

int process_pull_request(struct conn_element *ele, struct rx_buf_ele *rx_buf_e)
{
    struct subvirtual_machine *local_svm;
    unsigned long norm_addr;
    struct dsm *dsm;
   
    BUG_ON(!rx_buf_e);
    BUG_ON(!rx_buf_e->dsm_buf);

    dsm = find_dsm(rx_buf_e->dsm_buf->dsm_id);
    if (unlikely(!dsm))
        goto fail;

    local_svm = find_svm(dsm, rx_buf_e->dsm_buf->src_id);
    if (unlikely(!local_svm || !local_svm->priv))
        goto fail;

    norm_addr = rx_buf_e->dsm_buf->req_addr + local_svm->priv->offset;
    return dsm_trigger_page_pull(dsm, local_svm, norm_addr);

fail:
    return send_svm_status_update(ele, rx_buf_e);
}

int process_svm_status(struct conn_element *ele, struct rx_buf_ele *rx_buf_e) {
    printk("[process_svm_status] removing svm %d\n", rx_buf_e->dsm_buf->src_id);
    remove_svm(rx_buf_e->dsm_buf->dsm_id, rx_buf_e->dsm_buf->src_id);
    return 1;
}


int process_page_redirect(struct conn_element *ele, struct tx_buf_ele *tx_e,
        u32 redirect_svm_id) {

    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct page *page = tx_e->wrk_req->dst_addr->mem_page;
    u64 req_addr = tx_e->dsm_buf->req_addr;
    int (*func)(struct tx_buf_ele *) = tx_e->callback.func;
    struct subvirtual_machine *svm = NULL;
    int ret = 0;

    tx_e->wrk_req->dst_addr->mem_page = NULL;
    //release_ppe(ele, tx_e);
    //release_tx_element(ele, tx_e);

    svm = find_svm(dpc->svm->dsm, redirect_svm_id);
    if (svm) {
        trace_redirect(dpc->svm->dsm->dsm_id, dpc->svm->svm_id,
                svm->dsm->dsm_id, svm->svm_id, req_addr, dpc->tag);
        ret = request_dsm_page(page, svm, dpc->svm, req_addr, func, dpc->tag,
                dpc);
    } else
        ret = -1;

    // we need to release the page as something failed..
    //FIXME: not sure about refcount
    if (ret != 0)
        page_cache_release(page);
    return ret;
}


int process_page_response(struct conn_element *ele, struct tx_buf_ele *tx_e)
{
    if (tx_e->callback.func && !tx_e->callback.func(tx_e))
        goto out;

    release_ppe(ele, tx_e);
    release_tx_element(ele, tx_e);

out:
    return 0;
}

int process_page_request(struct conn_element *ele,
        struct rx_buf_ele *rx_buf_e)
{
    struct page_pool_ele *ppe;
    struct tx_buf_ele *tx_e = NULL;
    struct page * page;
    int ret = 0;
    struct dsm *dsm;
    struct subvirtual_machine *local_svm, *remote_svm;
    unsigned long norm_addr;
    struct dsm_message *msg = rx_buf_e->dsm_buf;

    dsm = find_dsm(msg->dsm_id);
    if (!dsm)
        goto no_svm;

    local_svm = find_svm(dsm, msg->src_id);
    if (!local_svm)
        goto no_svm;

    remote_svm = find_svm(dsm, msg->dest_id);
    if (!remote_svm)
        goto fail;

    norm_addr = msg->req_addr + local_svm->priv->offset;

    trace_process_page_request(local_svm->dsm->dsm_id, local_svm->svm_id,
            remote_svm->dsm->dsm_id, remote_svm->svm_id, norm_addr, msg->type);
retry:
    tx_e = try_get_next_empty_tx_reply_ele(ele);
    if (unlikely(!tx_e)) {
        cond_resched();
        goto retry;
    }
    BUG_ON(!tx_e);

    memcpy(tx_e->dsm_buf, msg, sizeof(struct dsm_message));
    tx_e->dsm_buf->type = PAGE_REQUEST_REPLY;
    tx_e->reply_work_req->wr.wr.rdma.remote_addr = tx_e->dsm_buf->dst_addr;
    tx_e->reply_work_req->wr.wr.rdma.rkey = tx_e->dsm_buf->rkey;
    tx_e->reply_work_req->mm = local_svm->priv->mm;
    tx_e->reply_work_req->addr = norm_addr;

    page = dsm_extract_page_from_remote(dsm, local_svm, remote_svm, norm_addr,
            msg->type, &tx_e->reply_work_req->pte, &msg->dest_id);

    if (unlikely(!page)) {
        ret = -EINVAL;

        switch (msg->type) {
            case REQUEST_PAGE: {
                release_tx_element_reply(ele, tx_e);
                if (request_queue_empty(ele)) {
                    tx_e = try_get_next_empty_tx_ele(ele);
                    if (likely(tx_e)) {
                        memcpy(tx_e->dsm_buf, msg, sizeof(struct dsm_message));
                        tx_e->dsm_buf->type = PAGE_REQUEST_REDIRECT;
                        tx_e->wrk_req->dst_addr = NULL;
                        tx_e->callback.func = NULL;
                        ret = tx_dsm_send(ele, tx_e);
                    }
                }
                if (ret)
                    ret = add_dsm_request_msg(ele, PAGE_REQUEST_REDIRECT, msg);

                return ret;
            }
            case TRY_REQUEST_PAGE: {
                release_tx_element_reply(ele, tx_e);
                if (request_queue_empty(ele)) {
                    tx_e = try_get_next_empty_tx_ele(ele);
                    if (likely(tx_e)) {
                        memcpy(tx_e->dsm_buf, msg, sizeof(struct dsm_message));
                        tx_e->dsm_buf->type = TRY_REQUEST_PAGE_FAIL;
                        tx_e->wrk_req->dst_addr = NULL;
                        tx_e->callback.func = NULL;
                        ret = tx_dsm_send(ele, tx_e);
                    }
                }
                if (ret)
                    ret = add_dsm_request_msg(ele, TRY_REQUEST_PAGE_FAIL, msg);
                break;
            }
            default: {
                dsm_printk("Un-handled type : %d ", msg->type);
                break;
            }

        }

        goto fail;
    }

    ppe = create_new_page_pool_element_from_page(ele, page);
    BUG_ON(!ppe);

    tx_e->wrk_req->dst_addr = ppe;
    tx_e->reply_work_req->page_sgl.addr = (u64) ppe->page_buf;

    trace_process_page_request_complete(local_svm->dsm->dsm_id, local_svm->svm_id,
                remote_svm->dsm->dsm_id, remote_svm->svm_id, norm_addr, msg->type);
    tx_dsm_send(ele, tx_e);
    return ret;

no_svm: 
    ret = send_svm_status_update(ele, rx_buf_e);
fail: 
    printk("[process_page_request] failure to answer page fault\n");
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
int tx_dsm_send(struct conn_element * ele, struct tx_buf_ele *tx_e)
{
    int ret;
    int type = tx_e->dsm_buf->type;

retry:
    switch (type) {
        case REQUEST_PAGE:
        case REQUEST_PAGE_PULL:
        case TRY_REQUEST_PAGE:
        case SVM_STATUS_UPDATE:
        case TRY_REQUEST_PAGE_FAIL:
        case PAGE_REQUEST_REDIRECT:
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
EXPORT_SYMBOL(tx_dsm_send);

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
int exchange_info(struct conn_element *ele, int id)
{
    int flag = (int) ele->rid.remote_info->flag;
    int ret = 0;
    struct conn_element * ele_found;
    unsigned int arr[4];
    char charid[20];

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
            refill_recv_wr(ele,
                    &ele->rx_buffer.rx_buf[get_nb_tx_buff_elements(ele) - 1]);
            ele->rid.remote_info->flag = RDMA_INFO_NULL;

            ele->remote_node_ip = (int) ele->rid.remote_info->node_ip;
            ele_found = search_rb_conn(ele->remote_node_ip);

            // We find that a connection is already open with that node - delete this connection request.
            if (ele_found) {
                if (ele->remote_node_ip != get_dsm_module_state()->rcm->node_ip) {
                    dsm_printk("destroy_connection duplicate: %d former: %d",
                            ele->remote_node_ip, ele_found->remote_node_ip);
                    rdma_disconnect(ele->cm_id);
                } else {
                    dsm_printk("loopback, lets hope for the best");
                }
                erase_rb_conn(ele);
            } else {
                //ok, inserting this connection to the tree
                complete(&ele->completion);
                insert_rb_conn(ele);
                arr[0] = (ele->remote_node_ip) & 0x000000ff;
                arr[1] = (ele->remote_node_ip >> 8) & 0x000000ff;
                arr[2] = (ele->remote_node_ip >> 16) & 0x000000ff;
                arr[3] = (ele->remote_node_ip >> 24) & 0x000000ff;
                scnprintf(charid, 20, "%u.%u.%u.%u", arr[0], arr[1], arr[2],
                        arr[3]);
                kobject_rename(&ele->sysfs.connection_kobject, charid);
                dsm_printk("inserted conn_element to rb_tree: %d",
                        ele->remote_node_ip);
            }
            goto send;

        }
        case RDMA_INFO_READY_SV: {
            refill_recv_wr(ele,
                    &ele->rx_buffer.rx_buf[get_nb_tx_buff_elements(ele) - 1]);

            ele->rid.remote_info->flag = RDMA_INFO_NULL;
            //Server acknowledged --> connection is complete.
            //start sending messages.
            complete(&ele->completion);
            goto out;
        }
        default: {
            printk(KERN_ERR "unknown RDMA info flag");
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

/**
 * Creating and posting the work request that sends its info over.
 *
 * RETURN dsm_post_send
 */

int dsm_send_info(struct conn_element *ele)
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

/**
 * Creating and posting the work request that receives remote info
 *
 * RETURN ib_post_recv
 */
int dsm_recv_info(struct conn_element *ele)
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

int dsm_request_page_pull(struct dsm *dsm, struct subvirtual_machine *fault_svm,
        struct page *page, unsigned long request_addr, struct mm_struct *mm,
        struct memory_region *mr)
{
    unsigned long addr = request_addr & PAGE_MASK;
    struct svm_list svms;
    int ret = 0, i;

    rcu_read_lock();
    svms = dsm_descriptor_to_svms(mr->descriptor);
    rcu_read_unlock();

    /*
     * This is a useful heuristic; it's possible that tx_elms have been freed in
     * the meanwhile, but we don't have to use them now as a work thread will 
     * use them anyway to free the req_queue.
     */
    for_each_valid_svm(svms, i) {
        if (request_queue_full(svms.pp[i]->ele))
            return -ENOMEM;
    }

    ret = dsm_prepare_page_for_push(fault_svm, svms, page, addr, mm,
            mr->descriptor);
    if (unlikely(ret))
        goto out;

    ret = send_request_dsm_page_pull(fault_svm, svms,
            addr - fault_svm->priv->offset);
    if (unlikely(ret == -ENOMEM))
        dsm_cancel_page_push(fault_svm, addr, page);

out:
    return ret;
}

int ack_msg(struct conn_element *ele, struct rx_buf_ele *rx_e) {

    struct tx_buf_ele *tx_e = NULL;
    struct dsm_message *msg = rx_e->dsm_buf;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (likely(tx_e)) {
            memcpy(tx_e->dsm_buf, msg, sizeof(struct dsm_message));
            tx_e->dsm_buf->type = ACK;
            tx_e->wrk_req->dst_addr = NULL;
            tx_e->callback.func = NULL;
            return tx_dsm_send(ele, tx_e);

        }
    }
    return add_dsm_request_msg(ele, ACK, msg);
}



