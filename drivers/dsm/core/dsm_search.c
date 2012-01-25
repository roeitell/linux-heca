/*
 * rb.c
 *
 *  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

static struct dsm_module_state *dsm_state;

struct dsm_module_state * create_dsm_module_state(void) {
    dsm_state = kmalloc(sizeof(struct dsm_module_state), GFP_KERNEL);
    BUG_ON(!(dsm_state));
    INIT_RADIX_TREE(&dsm_state->dsm_tree_root, GFP_KERNEL);
    INIT_LIST_HEAD(&dsm_state->dsm_list);
    mutex_init(&dsm_state->dsm_state_mutex);
    dsm_state->dsm_wq = alloc_workqueue("dsm_wq", WQ_HIGHPRI | WQ_MEM_RECLAIM,0);
    return dsm_state;
}
EXPORT_SYMBOL(create_dsm_module_state);

void destroy_dsm_module_state(void) {
    mutex_destroy(&dsm_state->dsm_state_mutex);
    destroy_workqueue(dsm_state->dsm_wq);
    kfree(dsm_state);
}
EXPORT_SYMBOL(destroy_dsm_module_state);

struct dsm_module_state * get_dsm_module_state(void) {
    return dsm_state;
}
EXPORT_SYMBOL(get_dsm_module_state);

static struct dsm* _find_dsm(struct radix_tree_root *root, unsigned long id) {
    struct dsm *dsm;
    struct dsm **dsmp;

    repeat: dsm = NULL;
    dsmp = (struct dsm **) radix_tree_lookup_slot(root, id);
    if (dsmp) {

        dsm = radix_tree_deref_slot((void**) dsmp);
        if (unlikely(!dsm))
            goto out;
        if (radix_tree_exception(dsm)) {
            if (radix_tree_deref_retry(dsm))
                goto repeat;
            goto out;
        }

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

        svm = radix_tree_deref_slot((void**) svmp);
        if (unlikely(!svm))
            goto out;
        if (radix_tree_exception(svm)) {
            if (radix_tree_deref_retry(svm))
                goto repeat;
            goto out;
        }

    }
    out: return svm;
}

struct dsm *find_dsm(u32 id) {

    struct dsm *dsm = NULL;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    rcu_read_lock();
    dsm = _find_dsm(&dsm_state->dsm_tree_root, (unsigned long) id);
    rcu_read_unlock();
    return dsm;

}
EXPORT_SYMBOL(find_dsm);

struct subvirtual_machine *find_svm(struct dsm_vm_id *id) {

    struct dsm *dsm = NULL;
    struct subvirtual_machine *svm = NULL;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    rcu_read_lock();
    dsm = _find_dsm(&dsm_state->dsm_tree_root, (unsigned long) id->dsm_id);
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
    struct rb_root *root = &(get_dsm_module_state()->rcm->root_conn);
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
    struct rb_root *root = &(get_dsm_module_state()->rcm->root_conn);
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

void insert_mr(struct dsm *dsm, struct memory_region *mr) {
    struct rb_root *root = &dsm->mr_tree_root;
    struct rb_node **new = &root->rb_node;
    struct rb_node *parent = NULL;
    struct memory_region *this;
    write_seqlock(&dsm->mr_seq_lock);
    while (*new) {
        this = rb_entry(*new, struct memory_region, rb_node);
        parent = *new;
        if (mr->addr < this->addr)
            new = &((*new)->rb_left);
        else if (mr->addr > this->addr)
            new = &((*new)->rb_right);
    }

    rb_link_node(&mr->rb_node, parent, new);
    rb_insert_color(&mr->rb_node, root);
    write_sequnlock(&dsm->mr_seq_lock);
}
EXPORT_SYMBOL(insert_mr);

// Return NULL if no element contained within tree.
struct memory_region *search_mr(struct dsm *dsm, unsigned long addr) {
    struct rb_root *root = &dsm->mr_tree_root;
    struct rb_node *node = root->rb_node;
    struct memory_region *this = NULL;
    unsigned long seq;
    do {
        seq = read_seqbegin(&dsm->mr_seq_lock);
        while (node) {
            this = rb_entry(node, struct memory_region, rb_node);

            if (addr < this->addr)
                node = node->rb_left;
            else if (addr > this->addr)
                if (addr < (this->addr + this->sz))
                    break;
                else
                    node = node->rb_right;
            else
                break;

        }
    } while (read_seqretry(&dsm->mr_seq_lock, seq));
    return this;

}
EXPORT_SYMBOL(search_mr);

