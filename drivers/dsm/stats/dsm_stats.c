/*
 * dsm_stats.c
 *
 *  Created on: 7 Dec 2011
 *      Author: jn
 */

/*
 * Statistic for dsm
 *
 */

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/atomic.h>
#include <dsm/dsm_stats.h>
#include <dsm/dsm_def.h>

static struct dsm_memory_stats memory_stats;

void dsm_stats_page_fault_update(struct dsm_memory_stats * stats) {
        stats = &memory_stats;
        atomic64_inc(&stats->fault);
}
EXPORT_SYMBOL( dsm_stats_page_fault_update);
void dsm_stats_page_extract_update(struct dsm_memory_stats *stats) {
        stats = &memory_stats;
        atomic64_inc(&stats->extract);
}
EXPORT_SYMBOL( dsm_stats_page_extract_update);

void reset_dsm_memory_stats(struct dsm_memory_stats * stats) {
        stats = &memory_stats;

        atomic64_set(&stats->fault, 0);
        atomic64_set(&stats->extract, 0);

}
EXPORT_SYMBOL( reset_dsm_memory_stats);

long long get_dsm_stats_page_fault(struct dsm_memory_stats * stats) {
        stats = &memory_stats;
        return atomic64_read(&stats->fault);
}
EXPORT_SYMBOL( get_dsm_stats_page_fault);
long long get_dsm_stats_page_extract(struct dsm_memory_stats *stats) {
        stats = &memory_stats;
        return atomic64_read(&stats->extract);
}
EXPORT_SYMBOL( get_dsm_stats_page_extract);

void dsm_stats_message_send_completion(struct con_element_stats * stats) {
        atomic64_inc(&stats->out);
}
EXPORT_SYMBOL( dsm_stats_message_send_completion);

void dsm_stats_message_send_rdma_completion(struct con_element_stats * stats) {
        atomic64_inc(&stats->out_rdma);
}
EXPORT_SYMBOL( dsm_stats_message_send_rdma_completion);
void dsm_stats_message_recv_completion(struct con_element_stats * stats) {
        atomic64_inc(&stats->in);
}
EXPORT_SYMBOL( dsm_stats_message_recv_completion);

void dsm_stats_message_recv_rdma_completion(struct con_element_stats * stats) {
        atomic64_inc(&stats->in_rdma);
}
EXPORT_SYMBOL( dsm_stats_message_recv_rdma_completion);

void reset_dsm_connection_stats(struct con_element_stats * stats) {

        atomic64_set(&stats->in, 0);
        atomic64_set(&stats->out, 0);
        atomic64_set(&stats->out_rdma, 0);
        atomic64_set(&stats->in_rdma, 0);

}
EXPORT_SYMBOL( reset_dsm_connection_stats);

int create_dsm_connection_stats_data(struct con_element_stats *stats) {

        reset_dsm_connection_stats(stats);
        return 0;
}
EXPORT_SYMBOL( create_dsm_connection_stats_data);

