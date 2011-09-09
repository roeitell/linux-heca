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

    write_lock(&rcm->conn_lock);

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

    write_unlock(&rcm->conn_lock);

}

// Return NULL if no element contained within tree.
struct conn_element* search_rb_conn(struct rcm *rcm, int node_ip) {
    struct rb_root *root = &rcm->root_conn;
    struct rb_node *node = root->rb_node;
    struct conn_element *this = 0;

    read_lock(&rcm->conn_lock);

    while (node) {
        this = rb_entry(node, struct conn_element, rb_node);

        if (node_ip < this->remote_node_ip) {
            node = node->rb_left;

        } else if (node_ip > this->remote_node_ip) {
            node = node->rb_right;

        } else
            break;

    }

    read_unlock(&rcm->conn_lock);

    return this;

}

// Function will free the element
void erase_rb_conn(struct rb_root *root, struct conn_element *ele) {
    BUG_ON(!ele);

    rb_erase(&ele->rb_node, root);

    kfree(ele);
}

void insert_rb_route(struct rcm *rcm, struct route_element *rele) {
    struct rb_root *root = &rcm->root_route;
    struct rb_node **new = &root->rb_node;
    struct rb_node *parent = NULL;
    struct route_element *this;
    u32 rb_val;
    u32 val = dsm_vm_id_to_u32(&rele->id);

    write_lock(&rcm->route_lock);

    while (*new) {
        this = rb_entry(*new, struct route_element, rb_node);

        rb_val = dsm_vm_id_to_u32(&this->id);

        parent = *new;

        if (val < rb_val) {
            new = &((*new)->rb_left);

        } else if (val > rb_val) {
            new = &((*new)->rb_right);

        }

    }

    rb_link_node(&rele->rb_node, parent, new);
    rb_insert_color(&rele->rb_node, root);

    write_unlock(&rcm->route_lock);

}

// Return NULL if no element contained within tree.
struct route_element* search_rb_route(struct rcm *rcm, struct dsm_vm_id *id) {
    struct rb_root *root = &rcm->root_route;
    struct rb_node *node = root->rb_node;
    u32 rb_val;
    u32 val = dsm_vm_id_to_u32(id);
    struct route_element *this = NULL;

    read_lock(&rcm->route_lock);

    while (node) {
        this = rb_entry(node, struct route_element, rb_node);

        rb_val = dsm_vm_id_to_u32(&this->id);

        if (val < rb_val) {
            node = node->rb_left;

        } else if (val > rb_val) {
            node = node->rb_right;

        } else {
            read_unlock(&rcm->route_lock);
            return this;
        }

    }

    read_unlock(&rcm->route_lock);
    return NULL;

}

// Function will free the element
void erase_rb_route(struct rb_root *root, struct route_element *rele) {
    BUG_ON(!rele);

    rb_erase(&rele->rb_node, root);

    kfree(rele);

}

/*
 * page swap RB_TREE
 */
static void __insert_rb_swap(struct rb_root *root, struct swp_element *ele) {
    struct rb_node **new = &root->rb_node;
    struct rb_node *parent = NULL;
    struct swp_element *this;

    while (*new) {
        this = rb_entry(*new, struct swp_element, rb);

        parent = *new;

        if (ele->addr < this->addr) {
            new = &((*new)->rb_left);

        } else if (ele->addr > this->addr) {
            new = &((*new)->rb_right);

        }

        // DSM1  - need tests to ensure there no double entries!

    }

    rb_link_node(&ele->rb, parent, new);
    rb_insert_color(&ele->rb, root);

}

struct swp_element * insert_rb_swap(struct rb_root *root, unsigned long addr) {
    struct swp_element *ele = kmalloc(sizeof(*ele), GFP_KERNEL);

    if (!ele)
        return ele;

    ele->addr = addr;

    __insert_rb_swap(root, ele);

    return ele;

}

struct swp_element* search_rb_swap(struct rb_root *root, unsigned long addr) {
    struct rb_node *node = root->rb_node;
    struct swp_element *this;

    while (node) {
        this = rb_entry(node, struct swp_element, rb);

        if (addr < this->addr)
            node = node->rb_left;
        else if (addr > this->addr)
            node = node->rb_right;
        else
            return this;

    }

    return NULL;

}

void erase_rb_swap(struct rb_root *root, struct swp_element *ele) {
    BUG_ON(!ele);

    rb_erase(&ele->rb, root);

    kfree(ele);

}
