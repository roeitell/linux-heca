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

//static dsm_stats dsm_stats;
//
//static inline struct dsm_stats *get_dsm_stats(void) {
//        return &dsm_stats;
//}
//
//struct dsm_stats {
//        struct proc_dir_entry *dsm_dir;
//        struct list_head dsm_connection_stats_list;
//};
//
//struct dsm_connection_stats_element {
//        struct proc_dir_entry *dir;
//        struct con_element_stats *stats;
//        struct list_head ptr;
//};

struct con_element_stats {
        atomic64_t out;
        atomic64_t out_rdma;
        atomic64_t in;
        atomic64_t in_rdma;

        s64 total_wait_to_wait_completion;
        s64 wait_to_wait_completion_min;
        s64 wait_to_wait_completion_max;
        s64 total_send_to_send_completion;
        s64 send_to_send_completion_min;
        s64 send_to_send_completion_max;
        s64 total_send_completion_to_reply_completion;
        s64 send_completion_to_reply_completion_min;
        s64 send_completion_to_reply_completion_max;
        s64 total_send_to_reply_completion;
        s64 send_to_reply_completion_min;
        s64 send_to_reply_completion_max;
        s64 total_entry_to_reply;
        s64 entry_to_reply_min;
        s64 entry_to_reply_max;
        u64 nb_total_processed;

        s64 total_send_reply_to_send_reply_completion;
        s64 send_reply_to_send_reply_completion_min;
        s64 send_reply_to_send_reply_completion_max;
        u64 nb_total_processed_send_reply;
        spinlock_t lock ;

        struct timespec t_start_bench;
        struct timespec t_end_bench;

};

struct tx_dsm_stats {
        struct timespec t_entry;
        struct timespec t_send;
        struct timespec t_send_completion;
        struct timespec t_reply;
};

#ifdef CONFIG_DSM_STATS

void dsm_stats_get_time_request(struct timespec *time);

void dsm_stats_set_time_request(struct tx_dsm_stats *stats,
                struct timespec time);

void dsm_stats_update_time_send(struct tx_dsm_stats *stats);

void dsm_stats_update_time_send_completion(struct tx_dsm_stats *stats);

void dsm_stats_update_time_recv_completion(struct tx_dsm_stats *stats);

void dsm_stats_message_send_completion(struct con_element_stats * stats);

void dsm_stats_message_send_rdma_completion(struct con_element_stats * stats);
void dsm_stats_message_recv_completion(struct con_element_stats * stats);

void dsm_stats_message_recv_rdma_completion(struct con_element_stats * stats);

void calc_dsm_stats_request_reply(struct con_element_stats *e_dsm_stats,
                struct tx_dsm_stats *tx_dsm_stats);

void calc_dsm_stats_reply(struct con_element_stats *e_dsm_stats,
                struct tx_dsm_stats *tx_dsm_stats);

int create_dsm_stats_data(struct con_element_stats *stats);

void reset_dsm_stats(struct con_element_stats * stats);

void print_dsm_stats(struct con_element_stats * stats);

#else

static inline int create_dsm_stats_data(struct con_element_stats *stats) {
        return 0;
}
static inline void reset_dsm_stats(struct con_element_stats * dsm_stats) {
}
static inline void print_dsm_stats(struct con_element_stats * dsm_stats) {
}
static inline void calc_dsm_stats(struct con_element_stats *e_dsm_stats,
                struct tx_dsm_stats *tx_dsm_stats) {
}
static inline void print_dsm_stats_time_detailed(
                struct con_element_stats * dsm_stats) {
}
extern void calc_dsm_stats_request_reply(struct con_element_stats *c_stats,
                struct tx_dsm_stats *tx_stats) {

}
extern void calc_dsm_stats_reply(struct con_element_stats *c_stats,
                struct tx_dsm_stats *tx_stats) {

}
static inline void dsm_stats_update_time_send(struct tx_dsm_stats *stats) {
}
static inline void dsm_stats_update_time_send_completion(
                struct tx_dsm_stats *stats) {
}
static inline void dsm_stats_get_time_request(struct timespec *time) {
}
static inline void dsm_stats_set_time_request(struct tx_dsm_stats *stats,
                struct timespec time) {
}
static inline void dsm_stats_update_time_recv_completion(
                struct tx_dsm_stats *stats) {
}

static inline void print_dsm_statss_time(struct con_element_stats * dsm_stats) {
}
static inline void print_dsm_statss_message_count(
                struct con_element_stats * dsm_stats) {
}
static inline void dsm_stats_message_recv_completion(
                struct con_element_stats * dsm_stats) {
}
static inline void dsm_stats_message_recv_rdma_completion(
                struct con_element_stats * dsm_stats) {
}
static inline void dsm_stats_message_send_completion(
                struct con_element_stats * dsm_stats) {
}
static inline void dsm_stats_message_send_rdma_completion(
                struct con_element_stats * dsm_stats) {
}
#endif

#endif
