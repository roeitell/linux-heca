/*
 * rb.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_rb.h>
#include <dsm/dsm_def.h>
#include <dsm/dsm_core.h>

static struct rcm *_rcm;

struct rcm * get_rcm(void) {
        return _rcm;
}
EXPORT_SYMBOL(get_rcm);
struct rcm ** get_pointer_rcm(void) {
        return &_rcm;
}
EXPORT_SYMBOL(get_pointer_rcm);

struct subvirtual_machine *find_svm(struct dsm_vm_id *id) {
        //return search_rb_route(_rcm, id);
        struct dsm *dsm;
        struct subvirtual_machine *svm;
        struct rcm * rcm = get_rcm();

        list_for_each_entry_rcu(dsm, &rcm->dsm_ls, ls)
        {
                if (dsm->dsm_id == id->dsm_id) {
                        list_for_each_entry_rcu(svm, &dsm->svm_ls, ls)
                        {
                                if (svm->id.svm_id == id->svm_id)
                                        return svm;

                        }
                }
        }

        return NULL;

}
EXPORT_SYMBOL(find_svm);

/*
 * Find and return SVM with pointer to process file desc private_data. *
 */
struct subvirtual_machine *find_local_svm(u16 dsm_id, struct mm_struct *mm) {
        struct subvirtual_machine *local_svm;
        struct dsm *dsm;
        struct rcm * rcm = get_rcm();

        list_for_each_entry_rcu(dsm, &rcm->dsm_ls, ls)
        {
                if (dsm->dsm_id == dsm_id) {
                        list_for_each_entry_rcu(local_svm, &dsm->svm_ls, ls)
                        {
                                if (local_svm->priv)
                                        if (local_svm->priv->mm == mm)
                                                return local_svm;

                        }

                }

        }

        return NULL;
}
EXPORT_SYMBOL(find_local_svm);

int page_local(unsigned long addr, struct dsm_vm_id *id, struct mm_struct *mm) {
        struct subvirtual_machine *svm = NULL;
        struct mem_region *mr = NULL;

        svm = find_local_svm(id->dsm_id, mm);

        if (svm) {
                list_for_each_entry_rcu(mr, &svm->mr_ls, ls)
                {
                        if (addr > mr->addr && addr <= (mr->addr + mr->sz)) {
                                return 1;
                        }
                }
        }

        return 0;
}
EXPORT_SYMBOL(page_local);

struct mem_region *find_mr(unsigned long addr, struct dsm_vm_id *id) {
        struct dsm *dsm;
        struct subvirtual_machine *svm;
        struct mem_region *mr;
        struct rcm * rcm = get_rcm();
        list_for_each_entry_rcu(dsm, &rcm->dsm_ls, ls)
        {
                if (dsm->dsm_id == id->dsm_id)
                list_for_each_entry_rcu(svm, &dsm->svm_ls, ls)
                {
                        if (svm->id.svm_id == id->svm_id)
                        list_for_each_entry_rcu(mr, &svm->mr_ls, ls)
                        {
                                if (addr >= mr->addr
                                                && addr <= (mr->addr + mr->sz))
                                        return mr;

                        }

                }

        }

        return NULL;

}
EXPORT_SYMBOL(find_mr);

struct mem_region *find_mr_source(unsigned long addr) {
        struct mm_struct *mm = current->mm;
        struct subvirtual_machine *svm;
        struct dsm *dsm;
        struct rcm * rcm = get_rcm();
        list_for_each_entry_rcu(dsm, &rcm->dsm_ls, ls)
        {
                list_for_each_entry_rcu(svm, &dsm->svm_ls, ls)
                {
                        if (svm->priv)
                                if (svm->priv->mm == mm) {
                                        // This isn't the optimised solution.  Refinding ptr to dsm.
                                        return find_mr(addr - svm->priv->offset,
                                                        &svm->id);

                                }

                }

        }

        return NULL;

}
EXPORT_SYMBOL(find_mr_source);

void insert_rb_conn(struct conn_element *ele) {
        struct rb_root *root = &get_rcm()->root_conn;
        struct rb_node **new = &root->rb_node;
        struct rb_node *parent = NULL;
        struct conn_element *this;

        while (*new) {
                this = rb_entry(*new, struct conn_element, rb_node);
                parent = *new;
                if (ele->remote_node_ip < this->remote_node_ip) {
                        new = &((*new)->rb_left);
                } else if (ele->remote_node_ip > this->remote_node_ip) {
                        new = &((*new)->rb_right);
                }
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

                if (node_ip < this->remote_node_ip) {
                        node = node->rb_left;

                } else if (node_ip > this->remote_node_ip) {
                        node = node->rb_right;

                } else
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

