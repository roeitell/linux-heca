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

void dsm_stats_get_time_request(struct timespec *time) {
        getnstimeofday(time);
}
EXPORT_SYMBOL( dsm_stats_get_time_request);

void dsm_stats_set_time_request(struct tx_dsm_stats *stats,
                struct timespec time) {
        stats->t_entry = time;
}
EXPORT_SYMBOL( dsm_stats_set_time_request);

void dsm_stats_update_time_send(struct tx_dsm_stats *stats) {
        getnstimeofday(&stats->t_send);
}
EXPORT_SYMBOL( dsm_stats_update_time_send);

void dsm_stats_update_time_send_completion(struct tx_dsm_stats *stats) {
        getnstimeofday(&stats->t_send_completion);
}
EXPORT_SYMBOL( dsm_stats_update_time_send_completion);

void dsm_stats_update_time_recv_completion(struct tx_dsm_stats *stats) {
        getnstimeofday(&stats->t_reply);
}
EXPORT_SYMBOL( dsm_stats_update_time_recv_completion);

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

void calc_dsm_stats_request_reply_full(struct con_element_stats *e_dsm_stats,
                struct tx_dsm_stats *tx_dsm_stats) {
        s64 ns;
        struct timespec time;

        time = timespec_sub(tx_dsm_stats->t_send, tx_dsm_stats->t_entry);
        ns = timespec_to_ns(&time);
        if (e_dsm_stats->wait_to_wait_completion_max < ns) {
                e_dsm_stats->wait_to_wait_completion_max = ns;
        } else if (e_dsm_stats->wait_to_wait_completion_min > ns) {
                e_dsm_stats->wait_to_wait_completion_min = ns;
        }
        e_dsm_stats->total_wait_to_wait_completion += ns;

        time = timespec_sub(tx_dsm_stats->t_send_completion,
                        tx_dsm_stats->t_send);
        ns = timespec_to_ns(&time);
        if (e_dsm_stats->send_to_send_completion_max < ns) {
                e_dsm_stats->send_to_send_completion_max = ns;
        } else if (e_dsm_stats->send_to_send_completion_min > ns) {
                e_dsm_stats->send_to_send_completion_min = ns;

        }
        e_dsm_stats->total_send_to_send_completion += ns;

        time = timespec_sub(tx_dsm_stats->t_reply,
                        tx_dsm_stats->t_send_completion);
        ns = timespec_to_ns(&time);
        if (e_dsm_stats->send_completion_to_reply_completion_max < ns) {
                e_dsm_stats->send_completion_to_reply_completion_max = ns;
        } else if (e_dsm_stats->send_completion_to_reply_completion_min > ns) {
                e_dsm_stats->send_completion_to_reply_completion_min = ns;
        }
        e_dsm_stats->total_send_completion_to_reply_completion += ns;

        time = timespec_sub(tx_dsm_stats->t_reply, tx_dsm_stats->t_send);
        ns = timespec_to_ns(&time);
        if (e_dsm_stats->send_to_reply_completion_max < ns) {
                e_dsm_stats->send_to_reply_completion_max = ns;
        } else if (e_dsm_stats->send_to_reply_completion_min > ns) {
                e_dsm_stats->send_to_reply_completion_min = ns;
        }
        e_dsm_stats->total_send_to_reply_completion += ns;

}

void calc_dsm_stats_request_reply(struct con_element_stats *e_dsm_stats,
                struct tx_dsm_stats *tx_dsm_stats) {
        s64 ns;

        struct timespec time;

        spin_lock(&e_dsm_stats->lock);
        getnstimeofday(&e_dsm_stats->t_end_bench);
        e_dsm_stats->nb_total_processed++;
        calc_dsm_stats_request_reply_full(e_dsm_stats, tx_dsm_stats);
        time = timespec_sub(tx_dsm_stats->t_reply, tx_dsm_stats->t_entry);
        ns = timespec_to_ns(&time);
        if (e_dsm_stats->entry_to_reply_max < ns) {
                e_dsm_stats->entry_to_reply_max = ns;
        } else if (e_dsm_stats->entry_to_reply_min > ns) {
                e_dsm_stats->entry_to_reply_min = ns;
        }
        e_dsm_stats->total_entry_to_reply += ns;

        spin_unlock(&e_dsm_stats->lock);

        return;
}
EXPORT_SYMBOL( calc_dsm_stats_request_reply);

void calc_dsm_stats_reply(struct con_element_stats *e_dsm_stats,
                struct tx_dsm_stats *tx_dsm_stats) {
        s64 ns;

        struct timespec time;

        spin_lock(&e_dsm_stats->lock);
        e_dsm_stats->nb_total_processed_send_reply++;
        time = timespec_sub(tx_dsm_stats->t_send_completion,
                        tx_dsm_stats->t_send);
        ns = timespec_to_ns(&time);
        if (e_dsm_stats->send_reply_to_send_reply_completion_max < ns) {
                e_dsm_stats->send_reply_to_send_reply_completion_max = ns;
        } else if (e_dsm_stats->send_reply_to_send_reply_completion_min > ns) {
                e_dsm_stats->send_reply_to_send_reply_completion_min = ns;
        }
        e_dsm_stats->total_send_reply_to_send_reply_completion += ns;

        spin_unlock(&e_dsm_stats->lock);

        return;
}
EXPORT_SYMBOL( calc_dsm_stats_reply);

static void print_dsm_stats_message_count(struct con_element_stats * stats) {
        u64 in = atomic64_read(&stats->in);
        u64 out = atomic64_read(&stats->out);
        u64 out_rdma = atomic64_read(&stats->out_rdma);
        u64 in_rdma = atomic64_read(&stats->in_rdma);
        u64 fly = out - in;
        printk(
                        "***************************************************************************************\n");
        printk(
                        "Messages        *OUT            *OUTRDMA        *IN             *INRDMA         *FLIGHT\n");
        printk(
                        "Messages        *%llu           *%llu           *%llu           *%llu           *%llu\n",
                        out, out_rdma, in, in_rdma, fly);
        printk(
                        "***************************************************************************************\n");

}
static void print_dsm_stats_time_detailed(struct con_element_stats * stats) {
        s64 avg;
        printk("************\n");
        avg = stats->total_wait_to_wait_completion / stats->nb_total_processed;
        printk("Wait to send Time (ns)\n");
        printk("TOTAL %lld |AVG %lld | MIN %lld | MAX %lld \n",
                        stats->total_wait_to_wait_completion, avg,
                        stats->wait_to_wait_completion_min,
                        stats->wait_to_wait_completion_max);

        printk("***********\n");
        avg = stats->total_send_to_send_completion / stats->nb_total_processed;
        printk("Send to Send completion Time (ns)\n");
        printk("TOTAL %lld | AVG %lld | MIN %lld | MAX %lld \n",
                        stats->total_send_to_send_completion, avg,
                        stats->send_to_send_completion_min,
                        stats->send_to_send_completion_max);

        printk("**********\n");
        avg = stats->total_send_completion_to_reply_completion
                        / stats->nb_total_processed;
        printk("send completion to reply completion (ns)\n");
        printk("TOTAL %lld | AVG %lld | MIN %lld | MAX %lld \n",
                        stats->total_send_completion_to_reply_completion, avg,
                        stats->send_completion_to_reply_completion_min,
                        stats->send_completion_to_reply_completion_max);

        printk("**********\n");
        avg = stats->total_send_to_reply_completion / stats->nb_total_processed;
        printk("send  to reply completion (ns)\n");
        printk("TOTAL %lld | AVG %lld | MIN %lld | MAX %lld \n",
                        stats->total_send_to_reply_completion, avg,
                        stats->send_to_reply_completion_min,
                        stats->send_to_reply_completion_max);

}

static void print_dsm_stats_time(struct con_element_stats * stats) {
        s64 avg;
        s64 nb_req_sec;
        s64 mb_sec_out;
        s64 mb_sec_in;
        s64 perceived_request_proc;

        struct timespec time;

        spin_lock(&stats->lock);
        if (stats->nb_total_processed_send_reply) {
                avg = stats->total_send_reply_to_send_reply_completion
                                / stats->nb_total_processed_send_reply;
                printk("nb Send Reply processed: %llu\n",
                                stats->nb_total_processed_send_reply);
                printk(
                                "Send Reply Time (ns)  AVG %lld | MIN %lld | MAX %lld \n",
                                avg,
                                stats->send_reply_to_send_reply_completion_min,
                                stats->send_reply_to_send_reply_completion_max);
                printk(
                                "*******************************************************************************\n");
        }
        if (stats->nb_total_processed) {

                printk("nb request processed: %llu\n",
                                stats->nb_total_processed);
                print_dsm_stats_time_detailed(stats);
                printk("**********\n");
                avg = stats->total_entry_to_reply / stats->nb_total_processed;
                printk("Total time from Request to reply (ns)\n");
                printk("  AVG %lld | MIN %lld | MAX %lld \n", avg,
                                stats->entry_to_reply_min,
                                stats->entry_to_reply_max);
                printk("**********\n");

                time = timespec_sub(stats->t_end_bench, stats->t_start_bench);
                avg = timespec_to_ns(&time);
                perceived_request_proc = avg / stats->nb_total_processed;
                nb_req_sec = (1000000000 * stats->nb_total_processed) / avg;
                mb_sec_out = (nb_req_sec * (sizeof(dsm_message) * 8))
                                / (1024 * 1024);
                mb_sec_in = (nb_req_sec * ((sizeof(dsm_message)) + PAGE_SIZE)
                                * 8) / (1024 * 1024);
                printk(
                                "Start benchmark %lld \n End Benchmark %lld \n total time %lld \n",
                                timespec_to_ns(&stats->t_start_bench),
                                timespec_to_ns(&stats->t_end_bench), avg);
                printk("Estimated GLOBAL bandwith (Request/s): %lld \n",
                                nb_req_sec);
                printk("Perceived Request churn : one request every %lld ns \n",
                                perceived_request_proc);
                printk(
                                "Estimated GLOBAL bandwith : a->b %lld (Mb/s) , b->a %lld (Mb/s)\n",
                                mb_sec_out, mb_sec_in);
        }
        spin_unlock(&stats->lock);
}

void reset_dsm_stats(struct con_element_stats * stats) {

        spin_lock(&stats->lock);
        atomic64_set(&stats->in, 0);
        atomic64_set(&stats->out, 0);
        atomic64_set(&stats->out_rdma, 0);
        atomic64_set(&stats->in_rdma, 0);
        stats->nb_total_processed = 0;
        stats->nb_total_processed_send_reply = 0;
        stats->total_entry_to_reply = 0;
        stats->total_send_completion_to_reply_completion = 0;
        stats->total_send_reply_to_send_reply_completion = 0;
        stats->total_send_to_send_completion = 0;
        stats->total_wait_to_wait_completion = 0;
        stats->entry_to_reply_max = 0;
        stats->entry_to_reply_min = 0x7FFFFFFFFFFFFFFF;
        stats->send_completion_to_reply_completion_max = 0;
        stats->send_completion_to_reply_completion_min = 0x7FFFFFFFFFFFFFFF;
        stats->send_reply_to_send_reply_completion_max = 0;
        stats->send_reply_to_send_reply_completion_min = 0x7FFFFFFFFFFFFFFF;
        stats->send_to_send_completion_max = 0;
        stats->send_to_send_completion_min = 0x7FFFFFFFFFFFFFFF;
        stats->wait_to_wait_completion_max = 0;
        stats->wait_to_wait_completion_min = 0x7FFFFFFFFFFFFFFF;
        getnstimeofday(&stats->t_start_bench);
        spin_unlock(&stats->lock);
}
EXPORT_SYMBOL( reset_dsm_stats);

int create_dsm_stats_data(struct con_element_stats *stats) {

        spin_lock_init(&stats->lock);
        reset_dsm_stats(stats);
        return 0;
}
EXPORT_SYMBOL( create_dsm_stats_data);

void print_dsm_stats(struct con_element_stats * stats) {
        print_dsm_stats_message_count(stats);
        print_dsm_stats_time(stats);
}
EXPORT_SYMBOL( print_dsm_stats);

//int register_dsm_stats() {
//        struct proc_dir_entry * dir;
//        struct dsm_stats * stats = get_dsm_stats();
//        INIT_LIST_HEAD(&stats->dsm_connection_stats_list);
//
//        dir = proc_mkdir("dsm", NULL);
//
//        if (dir == NULL) {
//                errk("[register_dsm_stats] couldn' create dsm dir\n");
//                return -1;
//        }
//        dir->owner = THIS_MODULE;
//        stats->dsm_dir = dir;
//
//}
//
//int deregister_dsm_stats() {
//        struct dsm_connection_stats_element *stats_e;
//        struct dsm_stats * stats = get_dsm_stats();
//        remove_proc_entry(stats->dsm_dir->name, NULL);
//        list_for_each_entry(stats_e, &stats->dsm_connection_stats_list, ptr)
//        {
//                remove_proc_entry(stats_e->dir->name, NULL);
//        }
//
//}
//
//void register_dsm_stats_connection() {
//
//}
//
//void deregister_dsm_stats_connection() {
//
//}
//
