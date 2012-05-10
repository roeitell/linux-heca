/*
 *
 */

#include <dsm/dsm_module.h>

#define DECLARE_SVM_SYSFS_ATTR(name)                                           \
    static inline ssize_t show_##name(struct kobject *kobj,                    \
            struct kobj_attribute *attr, char *buf)                            \
    {                                                                          \
        return sprintf(buf, "%lu\n", dsm_stats_read(                           \
         &(container_of(kobj, struct svm_sysfs, svm_kobject)->name )));        \
    }                                                                          \
    static struct kobj_attribute name = __ATTR(name, 0444, show_##name, NULL);

#define DECLARE_TXRX_SYSFS_SHOW_FUNC(name, context)                            \
    static inline ssize_t show_##name##_##context(struct kobject *kobj,        \
            struct kobj_attribute *attr, char *buf)                            \
    {                                                                          \
        return sprintf(buf, "%lu\n", dsm_stats_read(                           \
                    &(container_of(kobj, struct con_element_sysfs,             \
                    connection_##context##_kobject)->context##_stats.name)));  \
    }                                                                          \

#define DECLARE_TXRX_SYSFS_ATTR(name)                                          \
    DECLARE_TXRX_SYSFS_SHOW_FUNC(name, tx)                                     \
    DECLARE_TXRX_SYSFS_SHOW_FUNC(name, rx)                                     \
    static struct kobj_attribute tx_##name = __ATTR(name, 0444,                \
            show_##name##_tx, NULL);                                           \
    static struct kobj_attribute rx_##name = __ATTR(name, 0444,                \
            show_##name##_rx, NULL);

DECLARE_SVM_SYSFS_ATTR(nb_remote_fault);
DECLARE_SVM_SYSFS_ATTR(nb_remote_fault_success);
DECLARE_SVM_SYSFS_ATTR(nb_push_attempt);
DECLARE_SVM_SYSFS_ATTR(nb_push_success);
DECLARE_SVM_SYSFS_ATTR(nb_prefetch_attempt);
DECLARE_SVM_SYSFS_ATTR(nb_prefetch_success);
DECLARE_SVM_SYSFS_ATTR(nb_prefetch_failed_response);  /* per addr, not page */
DECLARE_SVM_SYSFS_ATTR(nb_push_failed_response);      /* per addr, not page */
DECLARE_SVM_SYSFS_ATTR(nb_answer_fault);
DECLARE_SVM_SYSFS_ATTR(nb_answer_fault_fail);
DECLARE_SVM_SYSFS_ATTR(nb_answer_attempt);
DECLARE_SVM_SYSFS_ATTR(nb_answer_attempt_fail);

DECLARE_TXRX_SYSFS_ATTR(request_page);
DECLARE_TXRX_SYSFS_ATTR(request_page_pull);
DECLARE_TXRX_SYSFS_ATTR(page_request_reply);
DECLARE_TXRX_SYSFS_ATTR(page_request_redirect);
DECLARE_TXRX_SYSFS_ATTR(page_info_update);
DECLARE_TXRX_SYSFS_ATTR(try_request_page);
DECLARE_TXRX_SYSFS_ATTR(try_request_page_fail);
DECLARE_TXRX_SYSFS_ATTR(err);

static struct attribute *svm_attrs[] = { &nb_remote_fault.attr, 
    &nb_remote_fault_success.attr, &nb_push_attempt.attr, &nb_push_success.attr,
    &nb_prefetch_attempt.attr, &nb_prefetch_success.attr,
    &nb_prefetch_failed_response.attr, &nb_push_failed_response.attr,
    &nb_answer_fault.attr, &nb_answer_attempt.attr, &nb_answer_fault_fail.attr,
    &nb_answer_attempt_fail.attr, NULL,
};
static struct attribute *tx_attrs[] = { &tx_request_page.attr,
    &tx_request_page_pull.attr, &tx_page_request_reply.attr,
    &tx_page_request_redirect.attr, &tx_page_info_update.attr,
    &tx_try_request_page.attr, &tx_try_request_page_fail.attr, &tx_err.attr,
    NULL,
};
static struct attribute *rx_attrs[] = { &rx_request_page.attr,
    &rx_request_page_pull.attr, &rx_page_request_reply.attr,
    &rx_page_request_redirect.attr, &rx_page_info_update.attr,
    &rx_try_request_page.attr, &rx_try_request_page_fail.attr, &rx_err.attr,
    NULL,
};

static struct attribute_group svm_attr_group = { .attrs = svm_attrs };
static struct attribute_group tx_connection_attr_group = { .attrs = tx_attrs };
static struct attribute_group rx_connection_attr_group = { .attrs = rx_attrs };



static void dsm_kobject_type_release(struct kobject *kobj)
{
    printk("Releasing kobject %p\n", kobj);
}

/* default kobject attribute operations */
static ssize_t kobj_dsm_attr_show(struct kobject *kobj, struct attribute *attr,
        char *buf)
{
    struct kobj_attribute *kattr;
    ssize_t ret = -EIO;

    kattr = container_of(attr, struct kobj_attribute, attr);
    if (kattr->show)
        ret = kattr->show(kobj, kattr, buf);
    return ret;
}

static ssize_t kobj_dsm_attr_store(struct kobject *kobj, struct attribute *attr,
        const char *buf, size_t count)
{
    struct kobj_attribute *kattr;
    ssize_t ret = -EIO;

    kattr = container_of(attr, struct kobj_attribute, attr);
    if (kattr->store)
        ret = kattr->store(kobj, kattr, buf, count);
    return ret;
}

static struct sysfs_ops kobj_dsm_sysfs_ops = { .show = kobj_dsm_attr_show,
    .store = kobj_dsm_attr_store, };

static struct kobj_type dsm_kobject_type = {
    .release = dsm_kobject_type_release, .sysfs_ops = &kobj_dsm_sysfs_ops, };

void reset_svm_stats(struct subvirtual_machine *svm)
{
    struct svm_sysfs *stats = &svm->svm_sysfs;

    dsm_stats_set(&stats->nb_remote_fault, 0);
    dsm_stats_set(&stats->nb_remote_fault_success, 0);
    dsm_stats_set(&stats->nb_push_attempt, 0);
    dsm_stats_set(&stats->nb_push_success, 0);
    dsm_stats_set(&stats->nb_prefetch_attempt, 0);
    dsm_stats_set(&stats->nb_prefetch_success, 0);
    dsm_stats_set(&stats->nb_prefetch_failed_response, 0);
    dsm_stats_set(&stats->nb_push_failed_response, 0);
    dsm_stats_set(&stats->nb_answer_fault, 0);
    dsm_stats_set(&stats->nb_answer_fault_fail, 0);
    dsm_stats_set(&stats->nb_answer_attempt, 0);
    dsm_stats_set(&stats->nb_answer_attempt_fail, 0);
}

static void cleanup_top_level_kobject(struct dsm_module_state *dsm_state)
{
    struct dsm_kobjects *dsm_kobjects = &dsm_state->dsm_kobjects;

    kobject_put(dsm_kobjects->rdma_kobject);
    kobject_del(dsm_kobjects->rdma_kobject);
    kobject_put(dsm_kobjects->domains_kobject);
    kobject_del(dsm_kobjects->domains_kobject);
    kobject_del(dsm_kobjects->dsm_glob_kobject);
    return;
}

static inline void reset_msg_stats(struct msg_stats *stats)
{
    dsm_stats_set(&stats->err, 0);
    dsm_stats_set(&stats->page_info_update, 0);
    dsm_stats_set(&stats->page_request_reply, 0);
    dsm_stats_set(&stats->request_page, 0);
    dsm_stats_set(&stats->request_page_pull, 0);
    dsm_stats_set(&stats->try_request_page, 0);
    dsm_stats_set(&stats->try_request_page_fail, 0);
    dsm_stats_set(&stats->page_request_redirect, 0);
}

void reset_dsm_connection_stats(struct con_element_sysfs *sysfs)
{
    reset_msg_stats(&sysfs->rx_stats);
    reset_msg_stats(&sysfs->tx_stats);
}

int create_svm_sysfs_entry(struct subvirtual_machine *svm)
{
    struct kobject *kobj = &svm->svm_sysfs.svm_kobject;
    int r;

    r = kobject_init_and_add(kobj, &dsm_kobject_type, &svm->dsm->dsm_kobject,
            "svm.%u", svm->svm_id);

    if (!r) {
        r = sysfs_create_group(kobj, &svm_attr_group);
        if (r) {
            kobject_put(kobj);
            kobject_del(kobj);
        }
    }

    return r;
}

void delete_svm_sysfs_entry(struct kobject *obj)
{
    kobject_put(obj);
    kobject_del(obj);
}

int create_dsm_sysfs_entry(struct dsm *dsm, struct dsm_module_state *dsm_state)
{
    return kobject_init_and_add(&dsm->dsm_kobject, &dsm_kobject_type,
            dsm_state->dsm_kobjects.domains_kobject, "dsm.%u", dsm->dsm_id);
}

void delete_dsm_sysfs_entry(struct kobject *obj)
{
    kobject_put(obj);
    kobject_del(obj);
}

int create_connection_sysfs_entry(struct con_element_sysfs *sysfs,
        struct kobject *root_kobj, char* name) 
{
    int r = kobject_init_and_add(&sysfs->connection_kobject, &dsm_kobject_type,
            root_kobj, name);

    if (!r) {
        r = kobject_init_and_add(&sysfs->connection_tx_kobject,
                &dsm_kobject_type, &sysfs->connection_kobject, "tx");
        if (!r) {
            r = sysfs_create_group(&sysfs->connection_tx_kobject,
                    &tx_connection_attr_group);
            if (r) {
                kobject_put(&sysfs->connection_tx_kobject);
                kobject_del(&sysfs->connection_tx_kobject);

            }
            if (!r) {
                r = kobject_init_and_add(&sysfs->connection_rx_kobject,
                        &dsm_kobject_type, &sysfs->connection_kobject, "rx");
                if (!r)
                    r = sysfs_create_group(&sysfs->connection_rx_kobject,
                            &rx_connection_attr_group);
                if (r) {
                    kobject_put(&sysfs->connection_rx_kobject);
                    kobject_del(&sysfs->connection_rx_kobject);

                }
            }
        }
    }
    return r;
}

void delete_connection_sysfs_entry(struct con_element_sysfs *sysfs)
{
    kobject_put(&sysfs->connection_rx_kobject);
    kobject_del(&sysfs->connection_rx_kobject);
    kobject_put(&sysfs->connection_tx_kobject);
    kobject_del(&sysfs->connection_tx_kobject);
    kobject_put(&sysfs->connection_kobject);
    kobject_del(&sysfs->connection_kobject);
}

int dsm_sysfs_setup(struct dsm_module_state *dsm_state)
{
    struct dsm_kobjects *dsm_kobjects = &dsm_state->dsm_kobjects;

    dsm_kobjects->dsm_glob_kobject = kobject_create_and_add("dsm", kernel_kobj);
    if (!dsm_kobjects->dsm_glob_kobject)
        goto err;
    dsm_kobjects->rdma_kobject = kobject_create_and_add("rdma_engine",
            dsm_kobjects->dsm_glob_kobject);
    if (!dsm_kobjects->rdma_kobject)
        goto err1;
    dsm_kobjects->domains_kobject = kobject_create_and_add("domains",
            dsm_kobjects->dsm_glob_kobject);
    if (!dsm_kobjects->domains_kobject)
        goto err2;

    return 0;

err2: 
    kobject_put(dsm_kobjects->rdma_kobject);
    kobject_del(dsm_kobjects->rdma_kobject);
err1: 
    kobject_del(dsm_kobjects->dsm_glob_kobject);
err: 
    return -ENOMEM;
}

void dsm_sysfs_cleanup(struct dsm_module_state *dsm_state)
{
    cleanup_top_level_kobject(dsm_state);
}

