/*
 * drivers/dsm/dsm_sysfs.c
 *
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include <dsm/dsm_core.h>

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

static struct sysfs_ops kobj_dsm_sysfs_ops = { .show = kobj_dsm_attr_show, .store = kobj_dsm_attr_store, };

static struct kobj_type dsm_kobject_type = { .release = dsm_kobject_type_release, .sysfs_ops = &kobj_dsm_sysfs_ops, };

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

int create_svm_sysfs_entry(struct subvirtual_machine *svm)
{
    struct kobject *kobj = &svm->svm_sysfs.svm_kobject;
    int r;

    r = kobject_init_and_add(kobj, &dsm_kobject_type, &svm->dsm->dsm_kobject,
            "svm.%u", svm->svm_id);

    return r;
}

void delete_svm_sysfs_entry(struct kobject *obj)
{
    kobject_put(obj);
    kobject_del(obj);
}

int create_dsm_sysfs_entry(struct dsm *dsm, struct dsm_module_state *dsm_state) {
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

    return r;
}

void delete_connection_sysfs_entry(struct con_element_sysfs *sysfs)
{
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

    err2: kobject_put(dsm_kobjects->rdma_kobject);
    kobject_del(dsm_kobjects->rdma_kobject);
    err1: kobject_del(dsm_kobjects->dsm_glob_kobject);
    err: return -ENOMEM;
}

void dsm_sysfs_cleanup(struct dsm_module_state *dsm_state)
{
    cleanup_top_level_kobject(dsm_state);
}

