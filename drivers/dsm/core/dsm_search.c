/*
 * rb.c
 **  Created on: 7 Jul 2011
 *      Author: Benoit
 */

#include <dsm/dsm_module.h>

static struct dsm_module_state *dsm_state;

struct dsm_module_state * create_dsm_module_state(void) {
    dsm_state = kzalloc(sizeof(struct dsm_module_state), GFP_KERNEL);
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
    struct rb_node *node;
    struct conn_element *this = 0;

    for (node = root->rb_node; node; this = 0) {
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

/* svm_descriptors */
static inline void dsm_expand_dsc(struct dsm *dsm, u32 i, u32 ***sdsc) {
    dsm->svm_descriptors = kmalloc(sizeof(u32 *)*i*2, GFP_KERNEL);
    memcpy(dsm->svm_descriptors, *sdsc, sizeof(u32 *)*i);
    memset(dsm->svm_descriptors + sizeof(u32 *)*i, 0, sizeof(u32 *)*i);
    dsm->svm_descriptors[i*2-1] = (u32 *) -1;
    kfree(*sdsc);
    *sdsc = dsm->svm_descriptors;
}

u32 dsm_get_descriptor(struct dsm *dsm, u32 *svm_ids) {
    int i, j;
    u32 **sdsc;

    write_lock(&dsm->sdsc_lock);
    sdsc = dsm->svm_descriptors;
    for (i = 0; sdsc[i]; i++) {
        for (j = 0; sdsc[i][j]; j++) {
            if (sdsc[i][j] != svm_ids[j])
                goto next;
        }
        goto finish;
    next: continue;
    }

    if (sdsc[i] < 0) 
        dsm_expand_dsc(dsm, i, &sdsc);

    for (j = 0; svm_ids[j]; j++)
        ;
    sdsc[i] = kmalloc(sizeof(u32)*(j+1), GFP_KERNEL);
    memcpy(sdsc[i], svm_ids, sizeof(u32)*(j+1));

    finish: write_unlock(&dsm->sdsc_lock);
    return i;
};
EXPORT_SYMBOL(dsm_get_descriptor);

inline swp_entry_t svm_ids_to_swp_entry(struct dsm *dsm, u32 *svm_ids) {
    u64 val = dsm_get_descriptor(dsm, svm_ids);
    val = (val << 24) | dsm->dsm_id;
    return val_to_dsm_entry(val);
};
EXPORT_SYMBOL(svm_ids_to_swp_entry);

inline u32 *dsm_descriptor_to_svm_ids(struct dsm *dsm, u32 dsc) {
    u32 *svm_ids;

    read_lock(&dsm->sdsc_lock);
    svm_ids = dsm->svm_descriptors[dsc];
    read_unlock(&dsm->sdsc_lock);
    return svm_ids;
}
EXPORT_SYMBOL(dsm_descriptor_to_svm_ids);

inline struct dsm_vm_ids swp_entry_to_svm_ids(swp_entry_t entry) {
    struct dsm_vm_ids id;
    u64 val = dsm_entry_to_val(entry);

    id.dsm = find_dsm(val & 0xFFFFFF);
    if (id.dsm)
        id.svm_ids = dsm_descriptor_to_svm_ids(id.dsm, val >> 24);
    else
        id.svm_ids[0] = 0;

    return id;
};
EXPORT_SYMBOL(swp_entry_to_svm_ids);

void remove_svm_from_dsc(struct subvirtual_machine *svm) {
    u32 **sdsc;
    int i, j;

    write_lock(&svm->dsm->sdsc_lock);
    sdsc = svm->dsm->svm_descriptors;
    for (i = 0; sdsc[i]; i++) {
        int mod = 0;
        for (j = 0; sdsc[i][j]; j++) {
            if (mod)
                sdsc[i][j-1] = sdsc[i][j];
            if (sdsc[i][j] == svm->svm_id)
                mod = 1;
        }
    }
    write_unlock(&svm->dsm->sdsc_lock);
}
EXPORT_SYMBOL(remove_svm_from_dsc);

