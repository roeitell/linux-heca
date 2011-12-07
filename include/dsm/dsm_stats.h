/*
 * dsm_stats
 */

#ifndef DSM_STATS_H
#define DSM_STATS_H

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/atomic.h>

struct tx_dsm_stats {
//bla bla to fill in later
};

struct con_element_stats {
        atomic64_t out;
        atomic64_t out_rdma;
        atomic64_t in;
        atomic64_t in_rdma;

        struct tx_dsm_stats * tx_dsm_stats;

};

struct dsm_memory_stats {
        atomic64_t fault;
        atomic64_t extract;

};

long long get_dsm_stats_page_fault(struct dsm_memory_stats *);
long long get_dsm_stats_page_extract(struct dsm_memory_stats *);
void dsm_stats_page_fault_update(struct dsm_memory_stats *);
void dsm_stats_page_extract_update(struct dsm_memory_stats *);
void reset_dsm_memory_stats(struct dsm_memory_stats *);

void dsm_stats_message_send_rdma_completion(struct con_element_stats *);
void dsm_stats_message_recv_completion(struct con_element_stats *);
void dsm_stats_message_recv_rdma_completion(struct con_element_stats *);
void dsm_stats_message_send_completion(struct con_element_stats *);
int create_dsm_connection_stats_data(struct con_element_stats *);
void reset_dsm_connection_stats(struct con_element_stats *);

#endif
