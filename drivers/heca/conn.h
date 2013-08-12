/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */

#ifndef _HECA_CONN_H
#define _HECA_CONN_H

#include <linux/in.h>
#include "struct.h"

void init_kmem_request_cache(void);
void destroy_kmem_request_cache(void);
inline struct dsm_request *alloc_dsm_request(void);
inline void release_dsm_request(struct dsm_request *);
int add_dsm_request(struct dsm_request *, struct conn_element *, u16, u32, u32,
                u32, u32, unsigned long, int (*)(struct tx_buf_ele *),
                struct dsm_page_cache *, struct page *, struct page_pool_ele *,
                int, struct dsm_message *);
inline int request_queue_empty(struct conn_element *);
inline int request_queue_full(struct conn_element *);
void dsm_request_queue_merge(struct tx_buffer *);
void create_page_reclaim_request(struct tx_buf_ele *, u32, u32
                , u32, u32, uint64_t);
void create_page_request(struct conn_element *, struct tx_buf_ele *, u32, u32,
                u32, u32, uint64_t, struct page *, struct dsm_page_cache *,
                struct page_pool_ele *);
void create_page_pull_request(struct conn_element *, struct tx_buf_ele *,
                u32, u32, u32, u32, uint64_t);
void listener_cq_handle(struct ib_cq *, void *);
int server_event_handler(struct rdma_cm_id *, struct rdma_cm_event *);
inline void dsm_msg_cpy(struct dsm_message *, struct dsm_message *);
void release_tx_element(struct conn_element *, struct tx_buf_ele *);
void release_tx_element_reply(struct conn_element *, struct tx_buf_ele *);
void try_release_tx_element(struct conn_element *, struct tx_buf_ele *);
int connect_svm(__u32, __u32, unsigned long, unsigned short);
unsigned long inet_addr(const char *);
char *inet_ntoa(unsigned long, char *, int);
struct tx_buf_ele *try_get_next_empty_tx_ele(struct conn_element *, int);
struct tx_buf_ele *try_get_next_empty_tx_reply_ele(struct conn_element *);
int destroy_connection(struct conn_element *);
int tx_dsm_send(struct conn_element *, struct tx_buf_ele *);
char *port_ntoa(unsigned short, char *, int);
char *sockaddr_ntoa(struct sockaddr_in *, char *, int);
char *conn_ntoa(struct sockaddr_in *, struct sockaddr_in *, char *, int);
int dsm_send_tx_e(struct conn_element *, struct tx_buf_ele *, int, int, u32,
                u32, u32, u32, unsigned long, unsigned long,
                struct dsm_page_cache *, struct page *,
                struct page_pool_ele *, int, int (*)(struct tx_buf_ele *),
                struct dsm_message *);

#endif /* _HECA_CONN_H */
