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
struct rcm ** get_pointer_rcm(void) {
        return &_rcm;
}

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

