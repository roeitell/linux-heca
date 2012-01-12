/*
 * rb.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_module.h>

static struct rcm *_rcm;

struct rcm * get_rcm(void) {
    return _rcm;
}
EXPORT_SYMBOL(get_rcm);
struct rcm ** get_pointer_rcm(void) {
    return &_rcm;
}
EXPORT_SYMBOL(get_pointer_rcm);

void remove_svm(struct subvirtual_machine *svm) {

    mutex_lock(&svm->dsm->dsm_mutex);

    if (svm->priv)
        svm->dsm->nb_local_svm--;
    radix_tree_delete(&svm->dsm->svm_mm_tree_root,
            (unsigned long) svm->id.svm_id);
    radix_tree_delete(&svm->dsm->svm_tree_root, (unsigned long) svm->id.svm_id);
    mutex_unlock(&svm->dsm->dsm_mutex);
    kfree(svm);

}
EXPORT_SYMBOL(remove_svm);

void remove_dsm(struct dsm * dsm) {

    struct subvirtual_machine *svm;
    struct rcm * rcm = get_rcm();

    mutex_lock(&rcm->rcm_mutex);
    list_del(&dsm->dsm_ptr);
    radix_tree_delete(&rcm->dsm_tree_root, (unsigned long) dsm->dsm_id);
    mutex_unlock(&rcm->rcm_mutex);

    while (!list_empty(&dsm->svm_list)) {

        svm = list_first_entry(&dsm->svm_list, struct subvirtual_machine, svm_ptr );
        remove_svm(svm);

    }

    mutex_destroy(dsm->dsm_mutex);
    kfree(dsm);

}
EXPORT_SYMBOL(remove_dsm);

static struct dsm* _find_dsm(struct radix_tree_root *root, unsigned long id) {
    struct dsm *dsm;
    struct dsm **dsmp;

    repeat: dsm = NULL;
    dsmp = (struct dsm **) radix_tree_lookup_slot(root, id);
    if (dsmp) {
        //NEED TO BE UPDATED TO 3.1
        dsm = radix_tree_deref_slot((void**) dsmp);
        if (unlikely(!dsm))
            goto out;
        if (radix_tree_deref_retry(dsm))
            goto repeat;

    }
    out: return dsm;
}

static struct subvirtual_machine* _find_svm_in_dsm(struct radix_tree_root *root,
        unsigned long id) {
    struct subvirtual_machine *svm;
    struct subvirtual_machine **svmp;

    repeat: svm = NULL;
    svmp = (struct subvirtual_machine **) radix_tree_lookup_slot(root, id);
    if (svmp) {
        //NEED TO BE UPDATED TO 3.1
        svm = radix_tree_deref_slot((void**) svmp);
        if (unlikely(!svm))
            goto out;
        if (radix_tree_deref_retry(svm))
            goto repeat;

    }
    out: return svm;
}

struct dsm *find_dsm(u32 id) {

    struct dsm *dsm = NULL;
    struct rcm * rcm = get_rcm();
    rcu_read_lock();
    dsm = _find_dsm(&rcm->dsm_tree_root, (unsigned long) id);
    rcu_read_unlock();
    return dsm;

}
EXPORT_SYMBOL(find_dsm);

struct subvirtual_machine *find_svm(struct dsm_vm_id *id) {

    struct dsm *dsm = NULL;
    struct subvirtual_machine *svm = NULL;
    struct rcm * rcm = get_rcm();
    rcu_read_lock();
    dsm = _find_dsm(&rcm->dsm_tree_root, (unsigned long) id->dsm_id);
    if (dsm) {
        svm = _find_svm_in_dsm(&dsm->svm_tree_root, id->svm_id);
    }
    rcu_read_unlock();
    return svm;
}
EXPORT_SYMBOL(find_svm);

struct subvirtual_machine *find_local_svm(struct dsm * dsm,
        struct mm_struct *mm) {

    struct subvirtual_machine *svm = NULL;

    rcu_read_lock();
    svm = _find_svm_in_dsm(&dsm->svm_mm_tree_root, (unsigned long) mm);
    rcu_read_unlock();
    return svm;
}
EXPORT_SYMBOL(find_local_svm);

void insert_rb_conn(struct conn_element *ele) {
    struct rb_root *root = &get_rcm()->root_conn;
    struct rb_node **new = &root->rb_node;
    struct rb_node *parent = NULL;
    struct conn_element *this;

    while (*new) {
        this = rb_entry(*new, struct conn_element, rb_node);
        parent = *new;
        if (ele->remote_node_ip < this->remote_node_ip)
            new = &((*new)->rb_left);
        else if (ele->remote_node_ip > this->remote_node_ip)
            new = &((*new)->rb_right);
    }

    rb_link_node(&ele->rb_node, parent, new);
    rb_insert_color(&ele->rb_node, root);

}
EXPORT_SYMBOL(insert_rb_conn);

// Return NULL if no element contained within tree.
struct conn_element* search_rb_conn(int node_ip) {
    struct rb_root *root = &get_rcm()->root_conn;
    struct rb_node *node = root->rb_node;
    struct conn_element *this = 0;

    while (node) {
        this = rb_entry(node, struct conn_element, rb_node);

        if (node_ip < this->remote_node_ip)
            node = node->rb_left;
        else if (node_ip > this->remote_node_ip)
            node = node->rb_right;
        else
            break;

    }

    return this;

}
EXPORT_SYMBOL(search_rb_conn);

// Function will free the element
void erase_rb_conn(struct rb_root *root, struct conn_element *ele) {
    BUG_ON(!ele);
    rb_erase(&ele->rb_node, root);
    kfree(ele);
}
EXPORT_SYMBOL(erase_rb_conn);

