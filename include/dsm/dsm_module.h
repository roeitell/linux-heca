/*
 * dsm_op.h
 *
 *  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#ifndef DSM_OP_H_
#define DSM_OP_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/byteorder/generic.h>
#include <linux/miscdevice.h>

#include <linux/fs.h>
#include <linux/rculist.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/stat.h>

#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <asm-generic/memory_model.h>

#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>
#include <linux/kobject.h>

#include <dsm/dsm_def.h>
#include <dsm/dsm_core.h>

/*
 *DSM OP
 */
unsigned int inet_addr(char *);

int create_rcm(struct dsm_module_state *, char *, int);
int destroy_rcm(struct dsm_module_state *);
int destroy_connection(struct conn_element **, struct rcm *);
void create_page_request(struct conn_element *, struct tx_buf_ele *,
        struct dsm_vm_id, struct dsm_vm_id, uint64_t, struct page*, u16);
void create_page_pull_request(struct conn_element *, struct tx_buf_ele *,
        struct dsm_vm_id, struct dsm_vm_id, uint64_t);
struct tx_buf_ele * try_get_next_empty_tx_ele(struct conn_element *);
struct tx_buf_ele * try_get_next_empty_tx_reply_ele(struct conn_element *);
int create_connection(struct rcm *, struct svm_data *);
int setup_connection(struct conn_element *, int);
int connect_client(struct rdma_cm_id *);
struct page_pool_ele * create_new_page_pool_element_from_page(
        struct conn_element *, struct page *);
void release_page(struct conn_element *, struct tx_buf_ele *);
void release_page_work(struct work_struct *);
void release_tx_element(struct conn_element *, struct tx_buf_ele *);
void release_tx_element_reply(struct conn_element *, struct tx_buf_ele *);
int setup_recv_wr(struct conn_element *);
int refill_recv_wr(struct conn_element *, struct rx_buf_ele *);
void reg_rem_info(struct conn_element *);

/*
 * CTL
 */

#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)

/*
 * RB
 */
void insert_rb_conn(struct conn_element *);
struct conn_element* search_rb_conn(int);
void erase_rb_conn(struct rb_root *, struct conn_element*);
struct dsm_module_state * get_dsm_module_state(void);
struct dsm_module_state * create_dsm_module_state(void);
void destroy_dsm_module_state(void);
struct subvirtual_machine *find_svm(struct dsm_vm_id *);
struct dsm *find_dsm(u32);
struct subvirtual_machine *find_local_svm(struct dsm *, struct mm_struct *);
void remove_svm(struct subvirtual_machine *);
void remove_dsm(struct dsm *);
struct subvirtual_machine *find_svm(struct dsm_vm_id *);
void insert_mr(struct dsm *dsm, struct memory_region *);
struct memory_region * search_mr(struct dsm *, unsigned long);

/*
 * handler
 */
int connection_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void listener_cq_handle(struct ib_cq *, void *);
int server_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void recv_cq_handle(struct ib_cq *, void *);
void send_cq_handle(struct ib_cq *, void *);
void dsm_cq_event_handler(struct ib_event *, void *);
void send_cq_handle_work(struct work_struct *);
void recv_cq_handle_work(struct work_struct *);

/*
 * SR
 */

void init_kmem_request_cache(void);
void destroy_kmem_request_cache(void);
int process_response(struct conn_element *, struct tx_buf_ele *);
int rx_tx_message_transfer(struct conn_element *, struct rx_buf_ele *);
int exchange_info(struct conn_element *, int);
int dsm_send_info(struct conn_element *);
int dsm_recv_info(struct conn_element *);
int request_dsm_page(struct page *, struct subvirtual_machine *,
        struct subvirtual_machine *, uint64_t, void(*func)(struct tx_buf_ele *),
        int);
int dsm_request_page_pull(struct mm_struct *, struct subvirtual_machine *,
        struct subvirtual_machine *, unsigned long);
int tx_dsm_send(struct conn_element *, struct tx_buf_ele *);

/*
 * SYSFS
 */
void dsm_sysf_cleanup(struct dsm_module_state *);
int dsm_sysf_setup(struct dsm_module_state *);

#endif /* DSM_OP_H_ */
