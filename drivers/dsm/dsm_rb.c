/*
 * rb.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_rb.h>
#include <dsm/dsm_def.h>

static u32 id_to_u32(dsm_vm_id *id)
{
	u32 val = id->dsm_id;

	val = val << 8;

	val |= id->vm_id;

	return val;

}

void insert_rb_conn(rcm *rcm, conn_element *ele)
{
	struct rb_root *root = &rcm->root_conn;
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	write_lock(&rcm->conn_lock);

	while (*new)
	{
		conn_element *this = rb_entry(*new, conn_element, rb_node);

		parent = *new;

		if (ele->remote_node_ip < this->remote_node_ip)
		{
			new = &((*new)->rb_left);
		}
		else
			if (ele->remote_node_ip > this->remote_node_ip)
			{
				new = &((*new)->rb_right);
			}
	}

	rb_link_node(&ele->rb_node, parent, new);
	rb_insert_color(&ele->rb_node, root);

	write_unlock(&rcm->conn_lock);

}

// Return NULL if no element contained within tree.
conn_element* search_rb_conn(rcm *rcm, int node_ip)
{
	struct rb_root *root = &rcm->root_conn;
	struct rb_node *node = root->rb_node;
	conn_element *this = 0;

	read_lock(&rcm->conn_lock);

	while (node)
	{
		this = rb_entry(node, conn_element, rb_node);

		if (node_ip < this->remote_node_ip)
		{
			node = node->rb_left;

		}
		else
			if (node_ip > this->remote_node_ip)
			{
				node = node->rb_right;

			}
			else
				break;

	}

	read_unlock(&rcm->conn_lock);

	return this;

}

// Function will free the element
void erase_rb_conn(struct rb_root *root, conn_element *ele)
{
	BUG_ON(!ele);

	rb_erase(&ele->rb_node, root);

	kfree(ele);
}

void insert_rb_route(rcm *rcm, route_element *rele)
{
	struct rb_root *root = &rcm->root_route;
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	u32 rb_val;
	u32 val = id_to_u32(&rele->id);

	write_lock(&rcm->route_lock);

	while (*new)
	{
		route_element *this = rb_entry(*new, route_element, rb_node);

		rb_val = id_to_u32(&this->id);

		parent = *new;

		if (val < rb_val)
		{
			new = &((*new)->rb_left);

		}
		else
			if (val > rb_val)
			{
				new = &((*new)->rb_right);

			}

	}

	rb_link_node(&rele->rb_node, parent, new);
	rb_insert_color(&rele->rb_node, root);

	write_unlock(&rcm->route_lock);

}
EXPORT_SYMBOL(insert_rb_route);

// Return NULL if no element contained within tree.
route_element* search_rb_route(rcm *rcm, dsm_vm_id *id)
{
	struct rb_root *root = &rcm->root_route;
	struct rb_node *node = root->rb_node;
	u32 rb_val;
	u32 val = id_to_u32(id);
	route_element *this = 0;

	read_lock(&rcm->route_lock);

	while (node)
	{
		this = rb_entry(node, route_element, rb_node);

		rb_val = id_to_u32(&this->id);

		if (val < rb_val)
		{
			node = node->rb_left;

		}
		else
			if (val > rb_val)
			{
				node = node->rb_right;

			}
			else
				break;

	}

	read_unlock(&rcm->route_lock);

	return this;

}
EXPORT_SYMBOL(search_rb_route);

// Function will free the element
void erase_rb_route(struct rb_root *root, route_element *rele)
{
	BUG_ON(!rele);

	rb_erase(&rele->rb_node, root);

	kfree(rele);

}
