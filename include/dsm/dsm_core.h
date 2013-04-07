/*
 *
 */

#ifndef DSM_CORE_H_
#define DSM_CORE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/byteorder/generic.h>
#include <linux/miscdevice.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/rculist.h>
#include <linux/socket.h>
#include <linux/stat.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/page-flags.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/mmu_notifier.h>
#include <linux/mmu_context.h>
#include <linux/init.h>
#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/writeback.h>
#include <linux/swap.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <asm-generic/memory_model.h>
#include <asm-generic/mman-common.h>

#include "../../../mm/internal.h"
#include <dsm/dsm_struct.h>

/* dsm.c */
#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)
void __dsm_printk(unsigned int level, const char *path, int line,
        const char *format, ...);
#define dsm_printk(fmt, args...) \
    __dsm_printk(0, __FILE__, __LINE__, fmt, ##args);


/* dsm_base.c */
inline struct dsm_module_state *get_dsm_module_state(void);
struct dsm_module_state *create_dsm_module_state(void);
void destroy_dsm_module_state(void);
struct conn_element *search_rb_conn(int);
void insert_rb_conn(struct conn_element *);
void erase_rb_conn(struct conn_element *);
struct dsm *find_dsm(u32);
void remove_dsm(struct dsm *);
int create_dsm(struct private_data *, __u32);
inline struct subvirtual_machine *find_svm(struct dsm *, u32);
inline struct subvirtual_machine *find_local_svm_in_dsm(struct dsm *,
        struct mm_struct *);
inline struct subvirtual_machine *find_local_svm(struct mm_struct *);
struct subvirtual_machine *find_any_svm(struct dsm *, struct svm_list);
int create_svm(__u32, __u32, int);
inline void release_svm(struct subvirtual_machine *);
void remove_svm(u32, u32);
struct memory_region *find_mr(struct subvirtual_machine *, u32);
struct memory_region *search_mr(struct subvirtual_machine *,
        unsigned long);
int create_mr(__u32, __u32, void *, size_t, __u32 *, int);
int create_rcm(struct dsm_module_state *, char *, int);
int destroy_rcm(struct dsm_module_state *);

/* dsm_conn.c */
void init_kmem_request_cache(void);
void destroy_kmem_request_cache(void);
inline struct dsm_request *alloc_dsm_request(void);
inline void release_dsm_request(struct dsm_request *);
int add_dsm_request(struct dsm_request *, struct conn_element *, int, u32, u32,
        u32, u32, unsigned long, int (*)(struct tx_buf_ele *),
        struct dsm_page_cache *, struct page *, struct page_pool_ele *, int,
        struct dsm_message *);
inline int request_queue_empty(struct conn_element *);
inline int request_queue_full(struct conn_element *);
void dsm_request_queue_merge(struct tx_buffer *);
int dsm_send_tx_e(struct conn_element *, struct tx_buf_ele *, int, int, u32,
        u32, u32, u32, unsigned long, unsigned long, struct dsm_page_cache *,
        struct page *, struct page_pool_ele *, int,
        int (*)(struct tx_buf_ele *), struct dsm_message *);
void listener_cq_handle(struct ib_cq *, void *);
int server_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
inline void dsm_msg_cpy(struct dsm_message *, struct dsm_message *);
void release_tx_element(struct conn_element *, struct tx_buf_ele *);
void release_tx_element_reply(struct conn_element *, struct tx_buf_ele *);
void try_release_tx_element(struct conn_element *, struct tx_buf_ele *);
int connect_svm(__u32, __u32, char *, int);
unsigned int inet_addr(char *);
struct tx_buf_ele *try_get_next_empty_tx_ele(struct conn_element *, int);
struct tx_buf_ele *try_get_next_empty_tx_reply_ele(struct conn_element *);
int destroy_connection(struct conn_element *);
int tx_dsm_send(struct conn_element *, struct tx_buf_ele *);

/* dsm_ops.c */
void init_kmem_deferred_gup_cache(void);
void destroy_kmem_deferred_gup_cache(void);
int dsm_claim_page(struct subvirtual_machine *, struct subvirtual_machine *,
        struct memory_region *, unsigned long, struct page *, int);
int request_dsm_page(struct page *, struct subvirtual_machine *,
        struct subvirtual_machine *, struct memory_region *,
        unsigned long, int (*)(struct tx_buf_ele *), int,
        struct dsm_page_cache *, struct page_pool_ele *);
int process_pull_request(struct conn_element *, struct rx_buf_ele *);
int process_svm_status(struct conn_element *, struct rx_buf_ele *);
int process_page_redirect(struct conn_element *, struct tx_buf_ele *, u32);
int process_page_response(struct conn_element *, struct tx_buf_ele *);
int process_page_claim(struct conn_element *, struct dsm_message *);
int process_claim_ack(struct conn_element *, struct tx_buf_ele *,
        struct dsm_message *);
int dsm_process_query_info(struct tx_buf_ele *);
void deferred_gup_work_fn(struct work_struct *);
int process_page_request_msg(struct conn_element *, struct dsm_message *);
int dsm_process_request_query(struct conn_element *, struct rx_buf_ele *);
int dsm_request_page_pull(struct dsm *, struct subvirtual_machine *,
        struct page *, unsigned long, struct mm_struct *,
        struct memory_region *);
int ack_msg(struct conn_element *, struct dsm_message *, u32);
int do_unmap_range(struct dsm *, int, void *, void *);

/* dsm_pull.c */
int dsm_initiate_fault(struct mm_struct *, unsigned long, int);
void init_dsm_prefetch_cache_kmem(void);
void destroy_dsm_prefetch_cache_kmem(void);
int dsm_zero_pfn_init(void);
void dsm_zero_pfn_exit(void);
inline void dsm_release_pull_dpc(struct dsm_page_cache **);
void dequeue_and_gup_cleanup(struct subvirtual_machine *);
void delayed_gup_work_fn(struct work_struct *);
int dsm_pull_req_failure(struct dsm_page_cache *);
int dsm_swap_wrapper(struct mm_struct *, struct vm_area_struct *,
        unsigned long, pte_t *, pmd_t *, unsigned int, pte_t,
        swp_entry_t);
int dsm_trigger_page_pull(struct dsm *, struct subvirtual_machine *,
        struct memory_region *, unsigned long);
int dsm_write_fault(struct mm_struct *, struct vm_area_struct *, unsigned long,
        pmd_t *, pte_t *, spinlock_t *, unsigned int);

/* dsm_push.c */
inline int dsm_is_congested(void);
inline void dsm_push_cache_release(struct subvirtual_machine *,
        struct dsm_page_cache **, int);
struct dsm_page_cache *dsm_push_cache_get_remove(struct subvirtual_machine *,
        unsigned long);
int dsm_extract_pte_data(struct dsm_pte_data *, struct mm_struct *,
        unsigned long);
int dsm_pte_present(struct mm_struct *, unsigned long);
int dsm_try_unmap_page(struct subvirtual_machine *, unsigned long,
        struct subvirtual_machine *, int);
void dsm_invalidate_readers(struct subvirtual_machine *, unsigned long, u32);
int dsm_extract_page_from_remote(struct subvirtual_machine *,
        struct subvirtual_machine *, unsigned long, u16, pte_t *, 
        struct page **, u32 *, int);
struct page *dsm_find_normal_page(struct mm_struct *, unsigned long);
int dsm_prepare_page_for_push(struct subvirtual_machine *,
        struct svm_list, struct page *, unsigned long, struct mm_struct *, u32);
int dsm_cancel_page_push(struct subvirtual_machine *, unsigned long,
        struct page *);
int push_back_if_remote_dsm_page(struct page *);
int dsm_flag_page_remote(struct mm_struct *, struct dsm *, u32, unsigned long);
u32 dsm_query_pte_info(struct subvirtual_machine *, unsigned long);

/* dsm_struct.c */
void dsm_init_descriptors(void);
void dsm_destroy_descriptors(void);
u32 dsm_get_descriptor(u32, u32 *);
inline pte_t dsm_descriptor_to_pte(u32, u32);
inline struct svm_list dsm_descriptor_to_svms(u32);
void remove_svm_from_descriptors(struct subvirtual_machine *);
int swp_entry_to_dsm_data(swp_entry_t, struct dsm_swp_data *);
int dsm_swp_entry_same(swp_entry_t, swp_entry_t);
void dsm_clear_swp_entry_flag(struct mm_struct *, unsigned long, pte_t, int);
void init_dsm_cache_kmem(void);
void destroy_dsm_cache_kmem(void);
struct dsm_page_cache *dsm_alloc_dpc(struct subvirtual_machine *,
        unsigned long, struct svm_list, int, int);
void dsm_dealloc_dpc(struct dsm_page_cache **);
int dsm_cache_add(struct subvirtual_machine *, unsigned long, int, int,
        struct dsm_page_cache **);
struct dsm_page_cache *dsm_cache_get(struct subvirtual_machine *,
        unsigned long);
struct dsm_page_cache *dsm_cache_get_hold(struct subvirtual_machine *,
        unsigned long);
struct dsm_page_cache *dsm_cache_release(struct subvirtual_machine *,
        unsigned long);
void dsm_destroy_page_pool(struct conn_element *);
int dsm_init_page_pool(struct conn_element *);
struct page_pool_ele *dsm_fetch_ready_ppe(struct conn_element *);
struct page_pool_ele *dsm_prepare_ppe(struct conn_element *, struct page *);
void dsm_ppe_clear_release(struct conn_element *, struct page_pool_ele **);
int dsm_flag_page_read(struct subvirtual_machine *, unsigned long, u32);
u32 dsm_lookup_page_read(struct subvirtual_machine *, unsigned long);
u32 dsm_extract_page_read(struct subvirtual_machine *, unsigned long);
void init_dsm_reader_kmem(void);
void destroy_dsm_reader_kmem(void);
inline void dsm_free_page_reader(struct dsm_page_reader *);
struct dsm_page_reader *dsm_delete_readers(struct subvirtual_machine *,
        unsigned long);
struct dsm_page_reader *dsm_lookup_readers(struct subvirtual_machine *,
        unsigned long);
int dsm_add_reader(struct subvirtual_machine *, unsigned long, u32);

/* dsm_sysfs.c */
int create_svm_sysfs_entry(struct subvirtual_machine *);
void delete_svm_sysfs_entry(struct kobject *);
int create_dsm_sysfs_entry(struct dsm *, struct dsm_module_state *);
void delete_dsm_sysfs_entry(struct kobject *);
int create_connection_sysfs_entry(struct con_element_sysfs *,
        struct kobject *, char *);
void delete_connection_sysfs_entry(struct con_element_sysfs *);
int dsm_sysfs_setup(struct dsm_module_state *);
void dsm_sysfs_cleanup(struct dsm_module_state *);

#endif /* DSM_CORE_H_ */
