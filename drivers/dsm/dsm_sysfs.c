#include <linux/kobject.h>
#include  <linux/sysfs.h>

#include <dsm/dsm_def.h>
#include <dsm/dsm_sysfs.h>
#include <dsm/dsm_stats.h>

static ssize_t memory_show(struct kobject *kobj, struct kobj_attribute *attr,
                char *buf) {
        long long var = 0;

        if (strcmp(attr->attr.name, "fault") == 0)
                var = get_dsm_stats_page_fault(NULL);
        else if (strcmp(attr->attr.name, "extract") == 0)
                var = get_dsm_stats_page_extract(NULL);
        else
                var = 0;

        return sprintf(buf, "%lld\n", var);
}

static ssize_t rdma_show(struct kobject *kobj, struct kobj_attribute *attr,
                char *buf) {
        long long var = 0;

        if (strcmp(attr->attr.name, "rdma_send") == 0)
                var = 0;
        else if (strcmp(attr->attr.name, "rdma_recv") == 0)
                var = 1;
        else if (strcmp(attr->attr.name, "rdma_write") == 0)
                var = 2;
        else if (strcmp(attr->attr.name, "rdma_write_recv") == 0)
                var = 3;
        else
                var = 0;

        return sprintf(buf, "%lld\n", var);
}

static struct kobj_attribute fault_attribute =
                __ATTR(fault, 0444, memory_show, NULL);
static struct kobj_attribute extract_attribute =
                __ATTR(extract, 0444, memory_show, NULL);

static struct attribute *mem_attrs[] = { &fault_attribute.attr,
                &extract_attribute.attr, NULL, /* need to NULL terminate the list of attributes */
};

/*
 * An unnamed attribute group will put all of the attributes directly in
 * the kobject directory.  If we specify a name, a subdirectory will be
 * created for the attributes with the directory being the name of the
 * attribute group.
 */
static struct attribute_group mem_attr_group = { .attrs = mem_attrs, };

static struct kobj_attribute rdma_send_attribute =
                __ATTR(rdma_send, 0444, rdma_show, NULL);
static struct kobj_attribute rdma_recv_attribute =
                __ATTR(rdma_recv, 0444, rdma_show, NULL);
static struct kobj_attribute rdma_write_attribute =
                __ATTR(rdma_write, 0444, rdma_show, NULL);
static struct kobj_attribute rdma_write_recv_attribute =
                __ATTR(rdma_write_recv, 0444, rdma_show,NULL);

static struct attribute *rdma_attrs[] = { &rdma_send_attribute.attr,
                &rdma_recv_attribute.attr, &rdma_write_attribute.attr,
                &rdma_write_recv_attribute.attr, NULL, /* need to NULL terminate the list of attributes */
};

static struct attribute_group rdma_attr_group = { .attrs = rdma_attrs, };

static void cleanup_top_level_kobject(struct rcm *rcm) {
        struct dsm_kobjects *dsm_kobjects = &rcm->dsm_kobjects;

        kobject_put(dsm_kobjects->rdma_kobject);
        kobject_del(dsm_kobjects->rdma_kobject);
        kobject_put(dsm_kobjects->memory_kobject);
        kobject_del(dsm_kobjects->memory_kobject);
        kobject_del(dsm_kobjects->dsm_kobject);
        return;
}

int dsm_sysf_setup(struct rcm *rcm) {

        struct dsm_kobjects *dsm_kobjects = &rcm->dsm_kobjects;

        dsm_kobjects->dsm_kobject = kobject_create_and_add("dsm", mm_kobj);
        if (!dsm_kobjects->dsm_kobject)
                goto err;

        dsm_kobjects->memory_kobject = kobject_create_and_add("memory",
                        dsm_kobjects->dsm_kobject);
        if (!dsm_kobjects->memory_kobject) {
                goto err1;

        }
        reset_dsm_memory_stats(NULL);
        if (sysfs_create_group(dsm_kobjects->memory_kobject, &mem_attr_group)) {
                goto err2;
        }

        dsm_kobjects->rdma_kobject = kobject_create_and_add("rdma_engine",
                        dsm_kobjects->dsm_kobject);
        if (!dsm_kobjects->rdma_kobject) {
                goto err2;

        }
        if (sysfs_create_group(dsm_kobjects->rdma_kobject, &rdma_attr_group)) {
                goto err3;
        }

        return 0;

        err3: kobject_put(dsm_kobjects->rdma_kobject);
        kobject_del(dsm_kobjects->rdma_kobject);
        err2: kobject_put(dsm_kobjects->memory_kobject);
        kobject_del(dsm_kobjects->memory_kobject);
        err1: kobject_del(dsm_kobjects->dsm_kobject);
        err: return -ENOMEM;

}

void dsm_sysf_cleanup(struct rcm *rcm) {

        cleanup_top_level_kobject(rcm);

}

