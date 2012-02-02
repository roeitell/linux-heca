/*
 * rb.c
 **  Created on: 7 Jul 2011
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

static void clean_up_page_cache(struct subvirtual_machine *svm,
        struct memory_region *mr) {
    unsigned long addr;
    struct page *page = NULL;

    for (addr = mr->addr; addr < (addr + mr->sz); addr += PAGE_SIZE) {
        page = page_is_in_svm_page_cache(svm, addr);
        printk(
                "[clean_up_page_cache] trying to remove page from dsm page cache dsm/svm/addr/page_ptr  %d / %d / %p / %p\n",
                svm->dsm_id, svm->svm_id, (void *) addr, page);
        if (page) {
            printk(
                    "[clean_up_page_cache] trying to remove page from dsm page cache dsm/svm/addr/page_ptr  %d / %d / %p / %p\n",
                    svm->dsm_id, svm->svm_id, (void *) addr, page);
            delete_from_dsm_cache(svm, page, addr);
            synchronize_rcu();
        }
    }
}

void remove_svm(struct subvirtual_machine *svm) {

    struct dsm * dsm = svm->dsm;
    struct memory_region *mr = NULL;

    printk("[remove_svm] removing SVM : dsm %d svm %d  \n", svm->dsm_id,
            svm->svm_id);
    mutex_lock(&dsm->dsm_mutex);
    list_del(&svm->svm_ptr);
    radix_tree_delete(&dsm->svm_mm_tree_root, (unsigned long) svm->svm_id);
    if (svm->priv) {
        printk("[remove_svm] we have private data before decreasing %d \n",
                dsm->nb_local_svm);
        dsm->nb_local_svm--;
        radix_tree_delete(&dsm->svm_tree_root, (unsigned long) svm->svm_id);
    }
    write_seqlock(&dsm->mr_seq_lock);
    while (!list_empty(&svm->mr_list)) {
        mr = list_first_entry(&svm->mr_list, struct memory_region, ls );
        printk("[remove_svm] removing MR: addr %p, size %lu  \n",
                (void*) mr->addr, mr->sz);
        list_del(&mr->ls);
        rb_erase(&mr->rb_node, &dsm->mr_tree_root);
        //TODO need to be solved at some point ... what do we do if we have floatign page / request during crash ?
        //clean_up_page_cache(svm, mr);
        kfree(mr);

    }
    write_sequnlock(&dsm->mr_seq_lock);
    mutex_unlock(&dsm->dsm_mutex);
    synchronize_rcu();
    kfree(svm);

}
EXPORT_SYMBOL(remove_svm);

void remove_dsm(struct dsm * dsm) {

    struct subvirtual_machine *svm;
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    int i;

    printk("[remove_dsm] removing dsm %d  \n", dsm->dsm_id);
    mutex_lock(&dsm_state->dsm_state_mutex);
    list_del(&dsm->dsm_ptr);
    radix_tree_delete(&dsm_state->dsm_tree_root, (unsigned long) dsm->dsm_id);
    mutex_unlock(&dsm_state->dsm_state_mutex);
    synchronize_rcu();

    while (!list_empty(&dsm->svm_list)) {
        svm = list_first_entry(&dsm->svm_list, struct subvirtual_machine, svm_ptr );
        remove_svm(svm);
    }

    for (i = 0; dsm->svm_descriptors[i]; i++) {
        kfree(dsm->svm_descriptors[i]);
    }

    kfree(dsm);
}
EXPORT_SYMBOL(remove_dsm);

struct dsm *find_dsm(u32 id) {
    struct dsm_module_state *dsm_state = get_dsm_module_state();
    struct dsm *dsm;
    struct dsm **dsmp;
    struct radix_tree_root *root;

    rcu_read_lock();
    root = &dsm_state->dsm_tree_root;
    repeat: dsm = NULL;
    dsmp = (struct dsm **) radix_tree_lookup_slot(root, (unsigned long) id);
    if (dsmp) {
        dsm = radix_tree_deref_slot((void **) dsmp);
        if (unlikely(!dsm))
            goto out;
        if (radix_tree_exception(dsm)) {
            if (radix_tree_deref_retry(dsm))
                goto repeat;
        }
    }
    out: rcu_read_unlock();
    return dsm;
}
EXPORT_SYMBOL(find_dsm);

static struct subvirtual_machine *_find_svm_in_tree(struct radix_tree_root *root, 
        unsigned long svm_id) {

    struct subvirtual_machine *svm;
    struct subvirtual_machine **svmp;

    repeat: svm = NULL;
    svmp = (struct subvirtual_machine **) radix_tree_lookup_slot(root, 
        (unsigned long) svm_id);
    if (svmp) {
        svm = radix_tree_deref_slot((void**) svmp);
        if (unlikely(!svm))
            goto out;
        if (radix_tree_exception(svm)) {
            if (radix_tree_deref_retry(svm))
                goto repeat;
        }
    }

    out: return svm;
};

struct subvirtual_machine *find_svm(struct dsm *dsm, u32 svm_id) {
    struct subvirtual_machine *svm;

    rcu_read_lock();
    svm = _find_svm_in_tree(&dsm->svm_tree_root, (unsigned long) svm_id);
    rcu_read_unlock();

    return svm;
}
EXPORT_SYMBOL(find_svm);

struct subvirtual_machine *find_local_svm(struct dsm * dsm,
        struct mm_struct *mm) {
    struct subvirtual_machine *svm;

    rcu_read_lock();
    svm = _find_svm_in_tree(&dsm->svm_mm_tree_root, (unsigned long) mm);
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

