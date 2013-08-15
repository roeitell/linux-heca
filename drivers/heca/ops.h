#ifndef _HECA_OPS_H
#define _HECA_OPS_H

void init_kmem_deferred_gup_cache(void);
void destroy_kmem_deferred_gup_cache(void);
int heca_claim_page(struct heca_process *, struct heca_process *,
                struct heca_memory_region *, unsigned long, struct page *, int);
int heca_request_page(struct page *, struct heca_process *,
                struct heca_process *, struct heca_memory_region *,
                unsigned long, int (*)(struct tx_buffer_element *), int,
                struct heca_page_cache *, struct heca_page_pool_element *);
int heca_request_page_pull(struct heca_space *, struct heca_process *,
                struct page *, unsigned long, struct mm_struct *,
                struct heca_memory_region *);
int process_pull_request(struct heca_connection *,
                struct rx_buffer_element *);
int process_hproc_status(struct heca_connection *,
                struct rx_buffer_element *);
int process_page_redirect(struct heca_connection *,
                struct tx_buffer_element *, u32);
int process_page_response(struct heca_connection *,
                struct tx_buffer_element *);
int process_page_claim(struct heca_connection *, struct heca_message *);
int process_claim_ack(struct heca_connection *,
                struct tx_buffer_element *, struct heca_message *);
int process_page_request_msg(struct heca_connection *,
                struct heca_message *);
int process_request_query(struct heca_connection *,
                struct rx_buffer_element *);
int process_query_info(struct tx_buffer_element *);
void deferred_gup_work_fn(struct work_struct *);
int ack_msg(struct heca_connection *, struct heca_message *, u32);
int unmap_range(struct heca_space *, int, pid_t, unsigned long, unsigned long);


#endif /* _HECA_OPS_H */
