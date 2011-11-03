/*
 * rb.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_rb.h>
#include <dsm/dsm_def.h>
#include <dsm/dsm_core.h>

void insert_rb_conn(struct rcm *rcm, struct conn_element *ele) {
        struct rb_root *root = &rcm->root_conn;
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

// Return NULL if no element contained within tree.
struct conn_element* search_rb_conn(struct rcm *rcm, int node_ip) {
        struct rb_root *root = &rcm->root_conn;
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

// Function will free the element
void erase_rb_conn(struct rb_root *root, struct conn_element *ele) {
        BUG_ON(!ele);

        rb_erase(&ele->rb_node, root);

        kfree(ele);
}

void red_page_insert(u64 pfn, struct dsm_vm_id *id, unsigned long addr) {
        struct rb_root *root = rcm_red_page_root();
        struct rb_node **new = &root->rb_node;
        struct rb_node *parent = NULL;
        struct red_page *this;
        struct red_page *rp = kmalloc(sizeof(*rp), GFP_KERNEL);

        rp->pfn = pfn;
        rp->id.dsm_id = id->dsm_id;
        rp->id.svm_id = id->svm_id;
        rp->addr = addr;

        while (*new) {
                this = rb_entry(*new, struct red_page, rb);

                parent = *new;

                if (rp->pfn < this->pfn) {
                        new = &((*new)->rb_left);

                } else if (rp->pfn > this->pfn) {
                        new = &((*new)->rb_right);

                }

                // DSM1  - need tests to ensure there no double entries!

        }

        rb_link_node(&rp->rb, parent, new);
        rb_insert_color(&rp->rb, root);

}

void red_page_erase(struct red_page *rp) {
        struct rb_root *root = rcm_red_page_root();

        rb_erase(&rp->rb, root);

        kfree(rp);
}

struct red_page *red_page_search(u64 pfn) {
        struct rb_root *root = rcm_red_page_root();
        struct rb_node *node = root->rb_node;
        struct red_page *this;

        while (node) {
                this = rb_entry(node, struct red_page, rb);

                if (pfn < this->pfn)
                        node = node->rb_left;
                else if (pfn > this->pfn)
                        node = node->rb_right;
                else
                        return this;

        }

        return NULL;

}

