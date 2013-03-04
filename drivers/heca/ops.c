/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include "core.h"
#include "trace.h"
#include "struct.h"
#include "ops.h"
#include "pull.h"
#include "push.h"
#include "conn.h"
#include "base.h"

static struct kmem_cache *kmem_deferred_gup_cache;

static inline void init_kmem_deferred_gup_cache_elm(void *obj)
{
    struct deferred_gup *dgup = (struct deferred_gup *) obj;
    memset(dgup, 0, sizeof(struct deferred_gup));
}

void init_kmem_deferred_gup_cache(void)
{
    kmem_deferred_gup_cache = kmem_cache_create("kmem_deferred_gup_cache",
            sizeof(struct deferred_gup), 0, SLAB_HWCACHE_ALIGN | SLAB_TEMPORARY,
            init_kmem_deferred_gup_cache_elm);
}

void destroy_kmem_deferred_gup_cache(void)
{
    kmem_cache_destroy(kmem_deferred_gup_cache);
}

static void release_kmem_deferred_gup_cache_elm(struct deferred_gup *req)
{

    kmem_cache_free(kmem_deferred_gup_cache, req);
}

static int send_request_dsm_page_pull(struct subvirtual_machine *fault_svm,
        struct memory_region *fault_mr, struct svm_list svms,
        unsigned long addr)
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
            reqs[i] = alloc_dsm_request();
            if (!reqs[i])
                goto nomem;
        }
    }

    for_each_valid_svm(svms, i) {
        if (tx_elms[i]) {
            create_page_pull_request(svms.pp[i]->ele, tx_elms[i],
                    fault_svm->dsm->dsm_id, fault_mr->mr_id, fault_svm->svm_id,
                    svms.pp[i]->svm_id, (uint64_t) addr);
            tx_elms[i]->callback.func = NULL;
            tx_dsm_send(svms.pp[i]->ele, tx_elms[i]);
        } else {
            BUG_ON(!reqs[i]);
            r |= add_dsm_request(reqs[i], svms.pp[i]->ele, REQUEST_PAGE_PULL,
                    fault_svm, fault_mr, svms.pp[i], addr, NULL, NULL, NULL,
                    NULL);
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
            release_dsm_request(reqs[j]);
    }
    return -ENOMEM;
}

static int send_svm_status_update(struct conn_element *ele,
        struct dsm_message *msg)
{
    struct tx_buf_ele *tx_e = NULL;
    int ret = 0;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (likely(tx_e)) {
            dsm_msg_cpy(tx_e->dsm_buf, msg);
            tx_e->dsm_buf->type = SVM_STATUS_UPDATE;
            ret = tx_dsm_send(ele, tx_e);
            goto out;
        }
    }

    ret = add_dsm_request_msg(ele, SVM_STATUS_UPDATE, msg);

out:
    return ret;
}

int dsm_claim_page(struct subvirtual_machine *fault_svm,
        struct subvirtual_machine *remote_svm, struct memory_region *fault_mr,
        unsigned long addr)
{
    struct conn_element *ele = remote_svm->ele;
    struct tx_buf_ele *tx_e;
    int ret = -EINVAL;
    unsigned long shared_addr = addr - fault_mr->addr;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (tx_e) {
            create_page_claim_request(tx_e, fault_svm->dsm->dsm_id,
                    fault_mr->mr_id, fault_svm->svm_id, remote_svm->svm_id,
                    shared_addr);

            ret = tx_dsm_send(ele, tx_e);
            trace_send_request(fault_svm->dsm->dsm_id, fault_svm->svm_id,
                    remote_svm->svm_id, fault_mr->mr_id, addr, shared_addr,
                    CLAIM_TAG);
            goto out;
        }
    }

    ret = add_dsm_request(NULL, ele, CLAIM_PAGE, fault_svm, fault_mr,
            remote_svm, shared_addr, NULL, NULL, NULL, NULL);
    BUG_ON(ret); /* FIXME: Handle req alloc failure */

out:
    return ret;
}

int request_dsm_page(struct page *page, struct subvirtual_machine *remote_svm,
        struct subvirtual_machine *fault_svm, struct memory_region *fault_mr,
        unsigned long addr, int (*func)(struct tx_buf_ele *), int tag,
        struct dsm_page_cache *dpc, struct page_pool_ele *ppe)
{
    struct conn_element *ele = remote_svm->ele;
    struct tx_buf_ele *tx_e;
    int ret = -EINVAL;
    int req_tag = (tag == PULL_TRY_TAG) ? TRY_REQUEST_PAGE : REQUEST_PAGE;
    unsigned long shared_addr = addr - fault_mr->addr;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (tx_e) {
            create_page_request(ele, tx_e, fault_svm->dsm->dsm_id,
                    fault_mr->mr_id, fault_svm->svm_id, remote_svm->svm_id,
                    shared_addr, page, req_tag, dpc, ppe);

            tx_e->callback.func = func;
            ret = tx_dsm_send(ele, tx_e);
            trace_send_request(fault_svm->dsm->dsm_id, fault_svm->svm_id,
                    remote_svm->svm_id, fault_mr->mr_id, addr, shared_addr,tag);
            goto out;
        }
    }

    ret = add_dsm_request(NULL, ele, req_tag, fault_svm, fault_mr,
            remote_svm, shared_addr, func, dpc, page, ppe);
    BUG_ON(ret); /* FIXME: Handle req alloc failure */

out:
    return ret;
}

int process_pull_request(struct conn_element *ele, struct rx_buf_ele *rx_buf_e)
{
    struct subvirtual_machine *local_svm;
    struct dsm *dsm;
    struct dsm_message *msg;
    struct memory_region *mr;
    int r = 0;

    BUG_ON(!rx_buf_e);
    BUG_ON(!rx_buf_e->dsm_buf);
    msg = rx_buf_e->dsm_buf;

    dsm = find_dsm(msg->dsm_id);
    if (unlikely(!dsm))
        goto fail;

    local_svm = find_svm(dsm, msg->src_id);
    if (unlikely(!local_svm || !local_svm->mm))
        goto fail;

    /* push only happens to mr owners! */
    mr = find_mr(local_svm, msg->mr_id);
    if (unlikely(!mr || !(mr->flags & MR_LOCAL) || (mr->flags & MR_COPY_ON_ACCESS)))
        goto fail;

    // we get -1 if something bad happened, or >0 if we had dpc or we requested the page
    if (dsm_trigger_page_pull(dsm, local_svm, mr, msg->req_addr) < 0)
        r = -1;
    release_svm(local_svm);

    return r;


fail:
    return send_svm_status_update(ele, msg);

}

int process_svm_status(struct conn_element *ele, struct rx_buf_ele *rx_buf_e)
{
    heca_printk(KERN_DEBUG "removing svm %d", rx_buf_e->dsm_buf->src_id);
    remove_svm(rx_buf_e->dsm_buf->dsm_id, rx_buf_e->dsm_buf->src_id);
    return 1;
}

int process_page_redirect(struct conn_element *ele, struct tx_buf_ele *tx_e,
        u32 redirect_svm_id)
{
    struct dsm_page_cache *dpc = tx_e->wrk_req->dpc;
    struct page *page = tx_e->wrk_req->dst_addr->mem_page;
    u64 req_addr = tx_e->dsm_buf->req_addr;
    int (*func)(struct tx_buf_ele *) = tx_e->callback.func;
    struct subvirtual_machine *svm = NULL;
    struct memory_region *fault_mr;
    int ret = -1;

    tx_e->wrk_req->dst_addr->mem_page = NULL;
    dsm_ppe_clear_release(ele, &tx_e->wrk_req->dst_addr);
    release_tx_element(ele, tx_e);

    fault_mr = find_mr(dpc->svm, tx_e->dsm_buf->mr_id);
    if (!fault_mr)
        goto out;

    svm = find_svm(dpc->svm->dsm, redirect_svm_id);
    if (!svm)
        goto out;

    trace_redirect(dpc->svm->dsm->dsm_id, dpc->svm->svm_id,
            svm->svm_id, fault_mr->mr_id, req_addr + fault_mr->addr, req_addr,
            dpc->tag);
    ret = request_dsm_page(page, svm, dpc->svm, fault_mr, req_addr, func,
            dpc->tag, dpc, NULL);

    // we need to release the page as something failed..
    //FIXME: not sure about refcount
out:
    if (ret != 0)
        page_cache_release(page);
    return ret;
}

int process_page_response(struct conn_element *ele, struct tx_buf_ele *tx_e)
{
    if (!tx_e->callback.func || tx_e->callback.func(tx_e))
        dsm_ppe_clear_release(ele, &tx_e->wrk_req->dst_addr);
    return 0;
}

static void handle_page_request_fail(struct conn_element *ele,
    struct dsm_message *msg, struct subvirtual_machine *remote_svm, u32 id)
{
    struct tx_buf_ele *tx_e;
    int r = -EINVAL, type;

    switch (msg->type) {
        case REQUEST_PAGE:
            if ((!remote_svm) || ( id == remote_svm->svm_id))
                type = PAGE_REQUEST_FAIL;
            else{
                msg->dest_id= id;
                type = PAGE_REQUEST_REDIRECT;
            }
            break;
        case TRY_REQUEST_PAGE:
            type = PAGE_REQUEST_FAIL;
            break;
        default:
            heca_printk("Unhandled type: %d", msg->type);
            return;
    }

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (likely(tx_e)) {
            dsm_msg_cpy(tx_e->dsm_buf, msg);
            tx_e->dsm_buf->type = type;
            tx_e->wrk_req->dst_addr = NULL;
            tx_e->callback.func = NULL;
            r = tx_dsm_send(ele, tx_e);
        }
    }
    if (r)
        add_dsm_request_msg(ele, type, msg);
}

static inline void defer_gup(struct dsm_message *msg,
        struct subvirtual_machine *local_svm, struct memory_region *mr,
        struct subvirtual_machine *remote_svm, struct conn_element *ele) 
{
    struct deferred_gup *dgup = NULL;

retry:
    dgup = kmem_cache_alloc(kmem_deferred_gup_cache, GFP_KERNEL);
    if (unlikely(!dgup)) {
        might_sleep();
        goto retry;
    }
    dgup->origin_ele = ele;
    dgup->remote_svm = remote_svm;
    dgup->mr = mr;
    dsm_msg_cpy(&dgup->dsm_buf, msg);
    llist_add(&dgup->lnode, &local_svm->deferred_gups);
    schedule_work(&local_svm->deferred_gup_work);
}

int process_page_claim(struct conn_element *ele, struct dsm_message *msg)
{
    struct dsm *dsm;
    struct subvirtual_machine *local_svm, *remote_svm;
    struct memory_region *mr;
    unsigned long addr;
    int r = -EFAULT;

    dsm = find_dsm(msg->dsm_id);
    if (unlikely(!dsm))
        goto out;

    local_svm = find_svm(dsm, msg->dest_id);
    if (unlikely(!local_svm))
        goto out;

    mr = find_mr(local_svm, msg->mr_id);
    if (unlikely(!mr))
        goto out_svm;

    remote_svm = find_svm(dsm, msg->src_id);
    if (unlikely(!remote_svm))
        goto out_svm;

    addr = msg->req_addr + mr->addr;

    BUG_ON(!local_svm->mm);
    r = dsm_try_unmap_page(local_svm->mm, addr, remote_svm);

    release_svm(remote_svm);
out_svm:
    release_svm(local_svm);
out:
    return r;
}

static int process_page_request(struct conn_element *origin_ele,
        struct subvirtual_machine *local_svm, struct memory_region *mr,
        struct subvirtual_machine *remote_svm, struct dsm_message *msg,
        int deferred)
{
    struct page_pool_ele *ppe;
    struct tx_buf_ele *tx_e = NULL;
    struct page *page;
    unsigned long addr = 0;
    struct conn_element *ele = NULL;
    u32 redirect_id = 0;

    if (!local_svm) {
        send_svm_status_update(origin_ele, msg);
        goto fail_svm;
    }

    if (!remote_svm)
        goto fail_svm;

    ele = remote_svm->ele;
    addr = msg->req_addr + mr->addr;
    BUG_ON(addr < mr->addr || addr > mr->addr + mr->sz);

    trace_process_page_request(local_svm->dsm->dsm_id, local_svm->svm_id,
            remote_svm->svm_id, mr->mr_id, addr, msg->req_addr, msg->type);

retry:
    tx_e = try_get_next_empty_tx_reply_ele(ele);
    if (unlikely(!tx_e)) {
        cond_resched();
        goto retry;
    }
    BUG_ON(!tx_e);

    dsm_msg_cpy(tx_e->dsm_buf, msg);
    tx_e->dsm_buf->type = PAGE_REQUEST_REPLY;
    tx_e->reply_work_req->wr.wr.rdma.remote_addr = tx_e->dsm_buf->dst_addr;
    tx_e->reply_work_req->wr.wr.rdma.rkey = tx_e->dsm_buf->rkey;
    tx_e->reply_work_req->mm = local_svm->mm;
    tx_e->reply_work_req->addr = addr;

    page = dsm_extract_page_from_remote(local_svm, remote_svm, addr,
            msg->type, &tx_e->reply_work_req->pte, &redirect_id, deferred, mr);
    if (unlikely(!page))
        goto fail;

    ppe = dsm_prepare_ppe(ele, page);
    if (!ppe)
        goto fail;

    tx_e->wrk_req->dst_addr = ppe;
    tx_e->reply_work_req->page_sgl.addr = (u64) ppe->page_buf;

    trace_process_page_request_complete(local_svm->dsm->dsm_id,
            local_svm->svm_id, remote_svm->svm_id, mr->mr_id,
            addr, msg->req_addr, msg->type);
    tx_dsm_send(ele, tx_e);
    release_svm(local_svm);
    release_svm(remote_svm);
    return 0;

fail:
    release_tx_element_reply(ele, tx_e);
    if (!redirect_id && msg->type == REQUEST_PAGE) {
        trace_dsm_defer_gup(local_svm->dsm->dsm_id, local_svm->svm_id,
                remote_svm->svm_id, mr->mr_id, addr, msg->req_addr,
                msg->type);
        defer_gup(msg, local_svm, mr, remote_svm, origin_ele);
        /* we release the svms when we actually solve the gup */
        goto out;
    }
    release_svm(remote_svm);

fail_svm:
    handle_page_request_fail(ele, msg, remote_svm, redirect_id);
    if (local_svm)
        release_svm(local_svm);

out:
    return -EINVAL;
}


/*
 *  FIXME: NOTE: we really would like to do NOIO GUP with fast iteration over list in order to process the GUP in the fastest order
 */
static inline void process_deferred_gups(struct subvirtual_machine *svm)
{
    struct deferred_gup *dgup = NULL;
    struct llist_node *llnode = llist_del_all(&svm->deferred_gups);

    do {
        while (llnode) {
            dgup = container_of(llnode, struct deferred_gup, lnode);
            llnode = llnode->next;
            /*the deferred is set to one i.e if we need to gup we will block */
            trace_dsm_defer_gup_execute(svm->dsm->dsm_id, svm->svm_id,
                    dgup->remote_svm->svm_id, dgup->mr->mr_id,
                    dgup->dsm_buf.req_addr + dgup->mr->addr,
                    dgup->dsm_buf.req_addr, dgup->dsm_buf.type);
            process_page_request(dgup->origin_ele, svm, dgup->mr,
                    dgup->remote_svm, &dgup->dsm_buf, 1);
            /*release the element*/
            release_kmem_deferred_gup_cache_elm(dgup);
        }
        llnode = llist_del_all(&svm->deferred_gups);
    } while (llnode);

}

void deferred_gup_work_fn(struct work_struct *w) 
{
    struct subvirtual_machine *svm;

    svm = container_of(w, struct subvirtual_machine, deferred_gup_work);
    process_deferred_gups(svm);
}

int process_page_request_msg(struct conn_element *ele, struct dsm_message *msg)
{
    struct subvirtual_machine *local_svm = NULL, *remote_svm = NULL;
    struct dsm *dsm = NULL;
    struct memory_region *mr = NULL;

    dsm = find_dsm(msg->dsm_id);
    if (unlikely(!dsm))
        goto fail;

    local_svm = find_svm(dsm, msg->src_id);
    if (unlikely(!local_svm))
        goto fail;

    mr = find_mr(local_svm, msg->mr_id);
    if (unlikely(!mr))
        goto fail;

    remote_svm = find_svm(dsm, msg->dest_id);
    if (unlikely(!remote_svm)) {
        release_svm(local_svm);
        goto fail;
    }

    return process_page_request(ele, local_svm, mr, remote_svm, msg, 0);

fail:
    return -EFAULT;
}

int dsm_request_page_pull(struct dsm *dsm, struct subvirtual_machine *fault_svm,
        struct page *page, unsigned long addr, struct mm_struct *mm,
        struct memory_region *mr)
{
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

    ret = send_request_dsm_page_pull(fault_svm, mr, svms, addr - mr->addr);
    if (unlikely(ret == -ENOMEM))
        dsm_cancel_page_push(fault_svm, addr, page);

out:
    return ret;
}

int ack_msg(struct conn_element *ele, struct rx_buf_ele *rx_e)
{
    struct tx_buf_ele *tx_e = NULL;

    if (request_queue_empty(ele)) {
        tx_e = try_get_next_empty_tx_ele(ele);
        if (likely(tx_e)) {
            dsm_msg_cpy(tx_e->dsm_buf, rx_e->dsm_buf);
            tx_e->dsm_buf->type = ACK;
            tx_e->wrk_req->dst_addr = NULL;
            tx_e->callback.func = NULL;
            return tx_dsm_send(ele, tx_e);
        }
    }
    return add_dsm_request_msg(ele, ACK, rx_e->dsm_buf);
}

int unmap_range(struct dsm *dsm, int dsc, pid_t pid, unsigned long addr,
        unsigned long sz)
{
    int r = 0;
    unsigned long it = addr, end = (addr + sz - 1);
    struct mm_struct *mm;

    BUG_ON(!pid);
  
    mm = find_mm_by_pid(pid);

    for (it = addr; it < end; it += PAGE_SIZE) {
        r = dsm_flag_page_remote(mm, dsm, dsc, it);
        if (r)
            break;
    }

    return r;
}

