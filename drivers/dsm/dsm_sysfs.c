/*
 *
 */

#include <dsm/dsm_module.h>

static void dsm_kobject_type_release(struct kobject * kobj) {
    //kfree(kobj);
    printk("Releasing kobject %p\n", kobj);
}

/* default kobject attribute operations */
static ssize_t kobj_dsm_attr_show(struct kobject *kobj, struct attribute *attr,
        char *buf) {
    struct kobj_attribute *kattr;
    ssize_t ret = -EIO;

    kattr = container_of(attr, struct kobj_attribute, attr);
    if (kattr->show)
        ret = kattr->show(kobj, kattr, buf);
    return ret;
}

static ssize_t kobj_dsm_attr_store(struct kobject *kobj, struct attribute *attr,
        const char *buf, size_t count) {
    struct kobj_attribute *kattr;
    ssize_t ret = -EIO;

    kattr = container_of(attr, struct kobj_attribute, attr);
    if (kattr->store)
        ret = kattr->store(kobj, kattr, buf, count);
    return ret;
}

const struct sysfs_ops kobj_dsm_sysfs_ops = { .show = kobj_dsm_attr_show, .store = kobj_dsm_attr_store, };

static struct kobj_type dsm_kobject_type = { .release = dsm_kobject_type_release, .sysfs_ops = &kobj_dsm_sysfs_ops, };

/*
 * SVM variable for user space statistics
 */

static ssize_t svm_show(struct kobject *kobj, struct kobj_attribute *attr,
        char *buf) {

    struct svm_sysfs *svm_sysfs = NULL;
    unsigned long var = 0;

    svm_sysfs = container_of(kobj, struct svm_sysfs , svm_kobject);

    if (strcmp(attr->attr.name, "nb_page_requested") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_requested);
    else if (strcmp(attr->attr.name, "nb_page_sent") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_sent);
    else if (strcmp(attr->attr.name, "nb_page_pull") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_pull);
    else if (strcmp(attr->attr.name, "nb_page_pull_fail") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_pull_fail);
    else if (strcmp(attr->attr.name, "nb_page_push_request") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_push_request);
    else if (strcmp(attr->attr.name, "nb_page_redirect") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_redirect);
    else if (strcmp(attr->attr.name, "nb_page_error") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_err);
    else if (strcmp(attr->attr.name, "nb_request_page_prefetch") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_requested_prefetch);
    else if (strcmp(attr->attr.name, "nb_page_request_success") == 0)
        var = dsm_stats_read(&svm_sysfs->stats.nb_page_request_success);
    else
        var = 0;

    return sprintf(buf, "%lu\n", var);

}
static struct kobj_attribute nb_page_request_success_attribute = __ATTR(nb_page_request_success, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_requested_attribute = __ATTR(nb_page_requested, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_sent_attribute = __ATTR(nb_page_sent, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_pull_attribute = __ATTR(nb_page_pull, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_pull_fail_attribute = __ATTR(nb_page_pull_fail, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_push_request_attribute = __ATTR(nb_page_push_request, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_error_attribute = __ATTR(nb_page_error, 0444, svm_show, NULL);
static struct kobj_attribute nb_page_redirect_attribute = __ATTR(nb_page_redirect, 0444, svm_show, NULL);
static struct kobj_attribute nb_request_page_prefetch_attribute = __ATTR(nb_request_page_prefetch, 0444, svm_show, NULL);

static struct attribute *svm_attrs[] = { &nb_page_requested_attribute.attr, &nb_page_request_success_attribute.attr, &nb_page_sent_attribute.attr, &nb_page_pull_attribute.attr, &nb_page_pull_fail_attribute.attr, &nb_page_push_request_attribute.attr, &nb_page_redirect_attribute.attr, &nb_page_error_attribute.attr, &nb_request_page_prefetch_attribute.attr, NULL, /* need to NULL terminate the list of attributes */
};

/*
 * An unnamed attribute group will put all of the attributes directly in
 * the kobject directory.  If we specify a name, a subdirectory will be
 * created for the attributes with the directory being the name of the
 * attribute group.
 */
static struct attribute_group svm_attr_group = { .attrs = svm_attrs, };

/*
 * RDMA connections statistics
 */

static long connection_show(struct msg_stats *stats,
        struct kobj_attribute *attr) {
    unsigned long var = 0;
    if (strcmp(attr->attr.name, "request_page") == 0)
        var = dsm_stats_read(&stats->request_page);
    else if (strcmp(attr->attr.name, "request_page_pull") == 0)
        var = dsm_stats_read(&stats->request_page_pull);
    else if (strcmp(attr->attr.name, "page_request_reply") == 0)
        var = dsm_stats_read(&stats->page_request_reply);
    else if (strcmp(attr->attr.name, "page_request_redirect") == 0)
        var = dsm_stats_read(&stats->page_request_redirect);
    else if (strcmp(attr->attr.name, "page_info_update") == 0)
        var = dsm_stats_read(&stats->page_info_update);
    else if (strcmp(attr->attr.name, "try_request_page") == 0)
        var = dsm_stats_read(&stats->try_request_page);
    else if (strcmp(attr->attr.name, "try_request_page_fail") == 0)
        var = dsm_stats_read(&stats->try_request_page_fail);
    else if (strcmp(attr->attr.name, "msg_err") == 0)
        var = dsm_stats_read(&stats->err);
    else
        var = 0;

    return var;
}

static ssize_t connection_tx_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf) {
    struct con_element_sysfs *cele_sysfs = NULL;
    unsigned long var;

    cele_sysfs = container_of(kobj,struct con_element_sysfs, connection_tx_kobject);

    var = connection_show(&cele_sysfs->tx_stats, attr);
    return sprintf(buf, "%lu\n", var);

}

static ssize_t connection_rx_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf) {
    struct con_element_sysfs *cele_sysfs = NULL;
    unsigned long var = 0;

    cele_sysfs = container_of(kobj,struct con_element_sysfs, connection_rx_kobject);

    var = connection_show(&cele_sysfs->rx_stats, attr);
    return sprintf(buf, "%lu\n", var);
}

static struct kobj_attribute tx_request_page_attribute = __ATTR(request_page, 0444, connection_tx_show, NULL);
static struct kobj_attribute tx_request_page_pull_attribute = __ATTR(request_page_pull, 0444, connection_tx_show, NULL);
static struct kobj_attribute tx_page_request_reply_attribute = __ATTR(page_request_reply, 0444, connection_tx_show, NULL);
static struct kobj_attribute tx_page_request_redirect_attribute = __ATTR(page_request_redirect, 0444, connection_tx_show,NULL);
static struct kobj_attribute tx_page_info_update_attribute = __ATTR(page_info_update, 0444, connection_tx_show,NULL);
static struct kobj_attribute tx_try_request_page_attribute = __ATTR(try_request_page, 0444, connection_tx_show,NULL);
static struct kobj_attribute tx_try_request_page_fail_attribute = __ATTR(try_request_page_fail, 0444, connection_tx_show,NULL);
static struct kobj_attribute tx_msg_err_attribute = __ATTR(msg_err, 0444, connection_tx_show,NULL);

static struct attribute *tx_connection_attrs[] = { &tx_request_page_attribute.attr, &tx_request_page_pull_attribute.attr, &tx_page_request_reply_attribute.attr, &tx_page_request_redirect_attribute.attr, &tx_page_info_update_attribute.attr, &tx_try_request_page_attribute.attr, &tx_try_request_page_fail_attribute.attr, &tx_msg_err_attribute.attr, NULL, /* need to NULL terminate the list of attributes */
};

static struct attribute_group tx_connection_attr_group = { .attrs = tx_connection_attrs, };

static struct kobj_attribute rx_request_page_attribute = __ATTR(request_page, 0444, connection_rx_show, NULL);
static struct kobj_attribute rx_request_page_pull_attribute = __ATTR(request_page_pull, 0444, connection_rx_show, NULL);
static struct kobj_attribute rx_page_request_reply_attribute = __ATTR(page_request_reply, 0444, connection_rx_show, NULL);
static struct kobj_attribute rx_page_request_redirect_attribute = __ATTR(page_request_redirect, 0444, connection_rx_show,NULL);
static struct kobj_attribute rx_page_info_update_attribute = __ATTR(page_info_update, 0444, connection_rx_show,NULL);
static struct kobj_attribute rx_try_request_page_attribute = __ATTR(try_request_page, 0444, connection_rx_show,NULL);
static struct kobj_attribute rx_try_request_page_fail_attribute = __ATTR(try_request_page_fail, 0444, connection_rx_show,NULL);
static struct kobj_attribute rx_msg_err_attribute = __ATTR(msg_err, 0444, connection_rx_show,NULL);

static struct attribute *rx_connection_attrs[] = { &rx_request_page_attribute.attr, &rx_request_page_pull_attribute.attr, &rx_page_request_reply_attribute.attr, &rx_page_request_redirect_attribute.attr, &rx_page_info_update_attribute.attr, &rx_try_request_page_attribute.attr, &rx_try_request_page_fail_attribute.attr, &rx_msg_err_attribute.attr, NULL, /* need to NULL terminate the list of attributes */
};

static struct attribute_group rx_connection_attr_group = { .attrs = rx_connection_attrs, };

static void cleanup_top_level_kobject(struct dsm_module_state *dsm_state) {
    struct dsm_kobjects *dsm_kobjects = &dsm_state->dsm_kobjects;

    kobject_put(dsm_kobjects->rdma_kobject);
    kobject_del(dsm_kobjects->rdma_kobject);
    kobject_put(dsm_kobjects->domains_kobject);
    kobject_del(dsm_kobjects->domains_kobject);
    kobject_del(dsm_kobjects->dsm_kobject);
    return;
}

int create_svm_sysfs_entry(struct subvirtual_machine *svm, char *ip) {
    struct kobject *kobj = &svm->svm_sysfs.svm_kobject, *kobj_ip;
    char id[11];
    int r;

    scnprintf(id, 11, "%x", svm->svm_id);
    r = kobject_init_and_add(kobj, &dsm_kobject_type, &svm->dsm->dsm_kobject,
            id, ip);

    if (!r) {
        r = sysfs_create_group(kobj, &svm_attr_group);
        if (r) {
            kobject_put(kobj);
            kobject_del(kobj);
        } else {
            kobj_ip = &svm->svm_sysfs.local;
            r = kobject_init_and_add(kobj_ip, &dsm_kobject_type, kobj, ip);
            if (r) {
                kobject_put(kobj_ip);
                kobject_del(kobj_ip);
            }
        }
    }

    return r;
}

void delete_svm_sysfs_entry(struct kobject *obj) {
    kobject_put(obj);
    kobject_del(obj);
}

int create_dsm_sysfs_entry(struct dsm *dsm, struct dsm_module_state *dsm_state) {
    char id[11];

    scnprintf(id, 11, "%x", dsm->dsm_id);
    return kobject_init_and_add(&dsm->dsm_kobject, &dsm_kobject_type,
            dsm_state->dsm_kobjects.domains_kobject, id);
}

void delete_dsm_sysfs_entry(struct kobject *obj) {
    kobject_put(obj);
    kobject_del(obj);
}

int create_connection_sysfs_entry(struct con_element_sysfs *sysfs,
        struct kobject *root_kobj, char* name) {

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

void delete_connection_entry(struct con_element_sysfs *sysfs) {
    kobject_put(&sysfs->connection_rx_kobject);
    kobject_del(&sysfs->connection_rx_kobject);
    kobject_put(&sysfs->connection_tx_kobject);
    kobject_del(&sysfs->connection_tx_kobject);
    kobject_put(&sysfs->connection_kobject);
    kobject_del(&sysfs->connection_kobject);
}

int dsm_sysf_setup(struct dsm_module_state *dsm_state) {

    struct dsm_kobjects *dsm_kobjects = &dsm_state->dsm_kobjects;

    dsm_kobjects->dsm_kobject = kobject_create_and_add("dsm", kernel_kobj);
    if (!dsm_kobjects->dsm_kobject)
        goto err;
    dsm_kobjects->rdma_kobject = kobject_create_and_add("rdma_engine",
            dsm_kobjects->dsm_kobject);
    if (!dsm_kobjects->rdma_kobject)
        goto err1;
    dsm_kobjects->domains_kobject = kobject_create_and_add("domains",
            dsm_kobjects->dsm_kobject);
    if (!dsm_kobjects->domains_kobject)
        goto err2;

    return 0;

    err2: kobject_put(dsm_kobjects->rdma_kobject);
    kobject_del(dsm_kobjects->rdma_kobject);
    err1: kobject_del(dsm_kobjects->dsm_kobject);
    err: return -ENOMEM;

}

void dsm_sysf_cleanup(struct dsm_module_state *dsm_state) {

    cleanup_top_level_kobject(dsm_state);

}

