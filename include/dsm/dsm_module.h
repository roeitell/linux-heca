/*
 *  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#ifndef DSM_MODULE_H_
#define DSM_MODULE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/byteorder/generic.h>
#include <linux/miscdevice.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/rculist.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/kobject.h>
#include <linux/writeback.h>

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
 * dsm_utils
 */

void __dsm_printk(unsigned int level, const char *path, int line,
        const char *format, ...);
#define dsm_printk(fmt, args...) \
    __dsm_printk(0, __FILE__, __LINE__, fmt, ##args);

/*
 *DSM OP
 */
unsigned int inet_addr(char *);

int get_max_pushed_reqs(struct conn_element *);

int create_rcm(struct dsm_module_state *, char *, int);
int destroy_rcm(struct dsm_module_state *);
int destroy_connection(struct conn_element *);
void create_page_request(struct conn_element *, struct tx_buf_ele *, u32, u32,
        u32, uint64_t, struct page*, u16, struct dsm_page_cache *,
        struct page_pool_ele *);
void create_page_pull_request(struct conn_element *, struct tx_buf_ele *, u32,
        u32, u32, uint64_t);
struct tx_buf_ele * try_get_next_empty_tx_ele(struct conn_element *);
struct tx_buf_ele * try_get_next_empty_tx_reply_ele(struct conn_element *);
int create_connection(struct rcm *, struct svm_data *);
int setup_connection(struct conn_element *, int);
int connect_client(struct rdma_cm_id *);
void release_ppe(struct conn_element *, struct tx_buf_ele *);
void release_tx_element(struct conn_element *, struct tx_buf_ele *);
void release_tx_element_reply(struct conn_element *, struct tx_buf_ele *);
void try_release_tx_element(struct conn_element *, struct tx_buf_ele *);
int setup_recv_wr(struct conn_element *);
int refill_recv_wr(struct conn_element *, struct rx_buf_ele *);
void reg_rem_info(struct conn_element *);
void release_svm_from_mr_descriptors(struct subvirtual_machine *);
void release_svm_tx_elements(struct subvirtual_machine *, struct conn_element*);
void release_svm_push_elements(struct subvirtual_machine *);
void surrogate_push_remote_svm(struct subvirtual_machine *,
        struct subvirtual_machine *);
void dsm_msg_cpy(struct dsm_message *, struct dsm_message *);

/*
 * CTL
 */

#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)
void remove_svm(u32, u32);
void remove_dsm(struct dsm *);

/*
 * search
 */
void insert_rb_conn(struct conn_element *);
struct conn_element* search_rb_conn(int);
void erase_rb_conn(struct conn_element *);
struct dsm_module_state * get_dsm_module_state(void);
struct dsm_module_state * create_dsm_module_state(void);
void destroy_dsm_module_state(void);
struct dsm *find_dsm(u32);
struct subvirtual_machine *find_local_svm_in_dsm(struct dsm *,
        struct mm_struct *);
struct subvirtual_machine *find_local_svm(struct mm_struct *);
struct subvirtual_machine *find_svm(struct dsm *, u32);
void insert_mr(struct dsm *, struct memory_region *);
struct memory_region *search_mr(struct dsm *, unsigned long);
int destroy_mrs(struct dsm *, int);
int remove_svm_from_mrs(struct dsm *, u32);
void dsm_clear_swp_entry_flag(struct mm_struct *, unsigned long, pte_t *, int);

/*
 * handler
 */
void schedule_delayed_request_flush(struct conn_element *);
void delayed_request_flush_work_fn(struct work_struct *);
void release_svm_queued_requests(struct subvirtual_machine *,
        struct tx_buffer *);
int client_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void listener_cq_handle(struct ib_cq *, void *);
int server_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
void recv_cq_handle(struct ib_cq *, void *);
void send_cq_handle(struct ib_cq *, void *);
void dsm_cq_event_handler(struct ib_event *, void *);
void send_cq_handle_work(struct work_struct *);
void recv_cq_handle_work(struct work_struct *);
void dsm_request_queue_merge(struct tx_buffer *);

/*
 * SR
 */
void init_kmem_defered_gup_cache(void);
void destroy_kmem_defered_gup_cache(void);
void defered_gup_work_fn(struct work_struct *);
int request_queue_empty(struct conn_element *);
void init_kmem_request_cache(void);
void destroy_kmem_request_cache(void);
void release_dsm_request(struct dsm_request *);
int process_page_redirect(struct conn_element *, struct tx_buf_ele *, u32);
int process_page_response(struct conn_element *, struct tx_buf_ele *);
int process_page_request_msg(struct conn_element *, struct dsm_message *msg);
int process_svm_status(struct conn_element *, struct rx_buf_ele *);
int process_pull_request(struct conn_element *, struct rx_buf_ele *);
int exchange_info(struct conn_element *, int);
int dsm_send_info(struct conn_element *);
int dsm_recv_info(struct conn_element *);
int request_dsm_page(struct page *, struct subvirtual_machine *,
        struct subvirtual_machine *, uint64_t, int (*func)(struct tx_buf_ele *),
        int, struct dsm_page_cache *, struct page_pool_ele *);
int dsm_request_page_pull(struct dsm *, struct subvirtual_machine *,
        struct page *, unsigned long, struct mm_struct *,
        struct memory_region *);
int tx_dsm_send(struct conn_element *, struct tx_buf_ele *);
int ack_msg(struct conn_element *, struct rx_buf_ele *);

/*
 * SYSFS
 */

void dsm_sysfs_cleanup(struct dsm_module_state *);
int dsm_sysfs_setup(struct dsm_module_state *);
void delete_svm_sysfs_entry(struct kobject *);
int create_dsm_sysfs_entry(struct dsm *, struct dsm_module_state *);
void delete_dsm_sysfs_entry(struct kobject *);
int create_svm_sysfs_entry(struct subvirtual_machine *);
int create_connection_sysfs_entry(struct con_element_sysfs *, struct kobject *,
        char*);
void delete_connection_sysfs_entry(struct con_element_sysfs *);

#endif /* DSM_OP_H_ */
