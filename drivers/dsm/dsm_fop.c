/*
 * dsm_fop.c
 *
 *  Created on: 2 Aug 2011
 *      Author: jn
 */

#include <dsm/dsm_fop.h>
#include <dsm/dsm_sr.h>

int destroy_rcm(rcm **rcm) {
        int ret = 0;

        if (*rcm) {
                if ((ret = destroy_connections(*rcm)))
                        ;
                printk(">[destroy_rcm] - Cannot destroy connections\n");

                if (likely((*rcm)->cm_id)) {
                        if ((*rcm)->cm_id->qp)
                                if ((ret = ib_destroy_qp((*rcm)->cm_id->qp)))
                                        printk(
                                                        ">[destroy_rcm] - Cannot destroy qp\n");

                        if ((*rcm)->mr)
                                if ((ret = (*rcm)->cm_id->device->dereg_mr(
                                                (*rcm)->mr)))
                                        printk(
                                                        ">[destroy_rcm] - Cannot dereg mr\n");

                        if ((*rcm)->pd)
                                if ((ret = ib_dealloc_pd((*rcm)->pd)))
                                        printk(
                                                        ">[destroy_rcm] -Cannot dealloc pd\n");

                        if ((*rcm)->cm_id)

                                rdma_destroy_id((*rcm)->cm_id);

                } else
                        printk(">[destroy_rcm] - no cm_id\n");

                kfree(*rcm);
                *rcm = 0;
        } else
                printk(">[destroy_rcm] - no rcm\n");
        destroy_kmem_request_cache();
        return ret;

}

int destroy_connections(rcm *rcm) {
        conn_element *ele;
        int i = 0;

        // DSM3: Temporarily using i - this doesn't make sense - what if nodes = 1, 3, 4?  We only free first!
        while ((ele = search_rb_conn(rcm, i))) {

                if (destroy_connection(&ele, rcm))
                        goto err;
                ++i;
        }

        i = 0;
        err: return i; //returns which connection failed
}

int destroy_connection(conn_element **ele, rcm *rcm) {
        int ret = 0;

        if (*ele) {
                if ((*ele)->cm_id) {
                        if ((*ele)->cm_id->qp)
                                if ((ret = ib_destroy_qp((*ele)->cm_id->qp)))
                                        printk(
                                                        ">[destroy_connection] - Cannot destroy qp\n");

                        if ((*ele)->mr)
                                if ((ret = (*ele)->cm_id->device->dereg_mr(
                                                (*ele)->mr)))
                                        printk(
                                                        ">[destroy_connection] - Cannot dereg mr\n");

                        if ((*ele)->pd)
                                if ((ret = (*ele)->cm_id->device->dealloc_pd(
                                                (*ele)->pd)))
                                        printk(
                                                        ">[destroy_connection] -Cannot dealloc pd\n");

                        rdma_destroy_id((*ele)->cm_id);
                }

                if ((*ele)->send_cq)
                        if ((ret = ib_destroy_cq((*ele)->send_cq)))
                                printk(
                                                ">[destroy_connection] - Cannot destroy send cq\n");

                if ((*ele)->recv_cq)
                        if ((ret = ib_destroy_cq((*ele)->recv_cq)))
                                printk(
                                                ">[destroy_connection] - Cannot destroy recv cq\n");

                destroy_rx_buffer((*ele));

                destroy_tx_buffer((*ele));

                free_rdma_info(*ele);

                // free_stat_data(*ele);

                erase_rb_conn(&rcm->root_conn, *ele);

                vfree(*ele);
                *ele = 0;
        }
        return 0;
}

void free_rdma_info(conn_element *ele) {
        if (ele->rid.send_info) {
                ib_dma_unmap_single(ele->cm_id->device,
                                (u64) (unsigned long) ele->rid.send_info,
                                sizeof(rdma_info), DMA_TO_DEVICE);
                vfree(ele->rid.send_mem);
        }

        if (ele->rid.recv_info) {
                ib_dma_unmap_single(ele->cm_id->device,
                                (u64) (unsigned long) ele->rid.recv_info,
                                sizeof(rdma_info), DMA_FROM_DEVICE);
                vfree(ele->rid.recv_mem);
        }

        if (ele->rid.remote_info) {
                kfree(ele->rid.remote_info);
        }

        memset(&ele->rid, 0, sizeof(struct rdma_info_data));
}

void destroy_tx_buffer(conn_element *ele) {
        int i;
        struct tx_buf_ele * tx_buf = ele->tx_buffer.tx_buf;
        if (tx_buf) {
                for (i = 0; i < TX_BUF_ELEMENTS_NUM; ++i) {
                        ib_dma_unmap_single(ele->cm_id->device,
                                        (u64) tx_buf[i].dsm_msg,
                                        sizeof(dsm_message), DMA_TO_DEVICE);

                        vfree(tx_buf[i].mem);

                        kfree(tx_buf[i].wrk_req->wr_ele);

                        //			if(likely(ele->tx_buf[i].wrk_req->page_buf))
                        //			{
                        //				ib_dma_unmap_page(ele->cm_id->device, (u64) (unsigned long) ele->tx_buf[i].wrk_req->page_buf, RDMA_PAGE_SIZE, DMA_FROM_DEVICE);
                        //				ele->tx_buf[i].wrk_req->page_buf = NULL;
                        //
                        //				__free_pages(ele->tx_buf[i].wrk_req->mem_page, 0);
                        //				ele->tx_buf[i].wrk_req->mem_page = NULL;
                        //			}

                        kfree(tx_buf[i].wrk_req);
                }

                kfree(tx_buf);
                ele->tx_buffer.tx_buf = 0;
        }
}

void destroy_rx_buffer(conn_element *ele) {
        int i;
        struct rx_buf_ele * rx = ele->rx_buffer.rx_buf;

        if (rx) {
                for (i = 0; i < RX_BUF_ELEMENTS_NUM; ++i) {
                        ib_dma_unmap_single(ele->cm_id->device,
                                        (u64) rx[i].dsm_msg,
                                        sizeof(dsm_message), DMA_FROM_DEVICE);
                        vfree(rx[i].mem);

                        kfree(rx[i].recv_wrk_rq_ele);
                }
                kfree(rx);
                ele->rx_buffer.rx_buf = 0;
        }
}
