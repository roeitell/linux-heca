/*
 * Benoit Hudzia <benoit.hudzia@sap.com> 2011 (c)
 * Roei Tell <roei.tell@sap.com> 2012 (c)
 * Aidan Shribman <aidan.shribman@sap.com> 2012 (c)
 */
#include <dsm/dsm_core.h>

#define HECA_SYSFS_MODULE "heca"
#define HECA_SYSFS_RDMA "rdma"
#define HECA_SYSFS_CONN_FMT "cm_id-0x%p"
#define HECA_SYSFS_CONF "conf"
#define HECA_SYSFS_SVM_FMT "svm-%u"
#define HECA_SYSFS_DSM_FMT "dsm-%u"

static void dsm_kobject_type_release(struct kobject *kobj)
{
    dsm_printk(KERN_DEBUG "Releasing kobject %p", kobj);
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

static struct sysfs_ops kobj_dsm_sysfs_ops = { 
    .show = kobj_dsm_attr_show, 
    .store = kobj_dsm_attr_store, 
};

static struct kobj_type dsm_kobject_type = { 
    .release = dsm_kobject_type_release,
    .sysfs_ops = &kobj_dsm_sysfs_ops,
};

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
            HECA_SYSFS_SVM_FMT, svm->svm_id);
    return r;
}

void delete_svm_sysfs_entry(struct kobject *obj)
{
    kobject_put(obj);
    kobject_del(obj);
}

int create_dsm_sysfs_entry(struct dsm *dsm, struct dsm_module_state *dsm_state) {
    return kobject_init_and_add(&dsm->dsm_kobject, &dsm_kobject_type,
            dsm_state->dsm_kobjects.domains_kobject, HECA_SYSFS_DSM_FMT,
            dsm->dsm_id);
}

void delete_dsm_sysfs_entry(struct kobject *obj)
{
    kobject_put(obj);
    kobject_del(obj);
}

void delete_conn_sysfs_entry(struct conn_element *ele)
{
    kobject_put(&ele->kobj);
    kobject_del(&ele->kobj);
}

struct instance_attribute {
    struct attribute attr;
    ssize_t(*show)(struct conn_element *, char *);
    ssize_t(*store)(struct conn_element *, char *, size_t);
};

#define to_instance_conn(k) container_of(k, struct conn_element, kobj)
#define to_instance_attr(a) container_of(a, struct instance_attribute, attr)

static ssize_t conn_instance_show(struct kobject *k,
        struct attribute *a, char *buffer)
{
    struct conn_element *conn = to_instance_conn(k);
    struct instance_attribute *instance_attr = to_instance_attr(a);

    if (instance_attr->show)
        return instance_attr->show(conn, buffer);
    return 0;
}

static ssize_t instance_conn_local_show(struct conn_element *conn, char *data)
{
    char s[20];
    sockaddr_ntoa(&conn->local, s, sizeof s);
    return sprintf(data, "%s\n", s);
}

static ssize_t instance_conn_remote_show(struct conn_element *conn, char *data)
{
    char s[20];
    sockaddr_ntoa(&conn->remote, s, sizeof s);
    return sprintf(data, "%s\n", s);
}

#define INSTANCE_ATTR(_name, _mode, _show, _store)  \
    static struct instance_attribute attr_instance_##_name = {  \
            .attr   = {.name = __stringify(_name), .mode = _mode }, \
            .show   = _show,                    \
            .store  = _store,                   \
    };

INSTANCE_ATTR(conn_local, S_IRUGO, instance_conn_local_show, NULL);
INSTANCE_ATTR(conn_remote, S_IRUGO, instance_conn_remote_show, NULL);

static struct instance_attribute *conn_instance_attr[] = {
    &attr_instance_conn_local,
    &attr_instance_conn_remote,
    NULL
};

static struct sysfs_ops conn_instance_ops = {
    .show = conn_instance_show,
};

static struct kobj_type ktype_conn_instance = { 
    .release = dsm_kobject_type_release,
    .sysfs_ops = &conn_instance_ops,
    .default_attrs = (struct attribute **) conn_instance_attr,
};

int create_conn_sysfs_entry(struct conn_element *ele)
{
    int rc;

    struct kobject *root_kobj = 
        get_dsm_module_state()->dsm_kobjects.rdma_kobject;

    rc = kobject_init_and_add(&ele->kobj,
            &ktype_conn_instance, root_kobj, 
            HECA_SYSFS_CONN_FMT, ele->cm_id);

    if (!rc)
        goto done;

done:
    return rc;
}

int dsm_sysfs_setup(struct dsm_module_state *dsm_state)
{
    struct dsm_kobjects *dsm_kobjects = &dsm_state->dsm_kobjects;

    dsm_kobjects->dsm_glob_kobject = kobject_create_and_add(HECA_SYSFS_MODULE,
            kernel_kobj);
    if (!dsm_kobjects->dsm_glob_kobject)
        goto err;
    dsm_kobjects->rdma_kobject = kobject_create_and_add(HECA_SYSFS_RDMA,
            dsm_kobjects->dsm_glob_kobject);
    if (!dsm_kobjects->rdma_kobject)
        goto err1;
    dsm_kobjects->domains_kobject = kobject_create_and_add(HECA_SYSFS_CONF,
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

