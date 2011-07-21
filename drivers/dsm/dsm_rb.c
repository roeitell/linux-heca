/*
 * rb.c
 *
 *  Created on: 7 Jul 2011
 *      Author: john
 */

#include <dsm/dsm_rb.h>

void insert_rb_conn(struct rb_root *root, conn_element *ele)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*new)
	{
		conn_element *this = rb_entry(*new, conn_element, rb_node);

		parent = *new;

		if (ele->id < this->id)
		{
			new = &((*new)->rb_left);
		}
		else
			if (ele->id > this->id)
			{
				new = &((*new)->rb_right);
			}
	}

	rb_link_node(&ele->rb_node, parent, new);
	rb_insert_color(&ele->rb_node, root);
}

// Return NULL if no element contained within tree.
conn_element* search_rb_conn(struct rb_root *root, int id)
{
	struct rb_node *node = root->rb_node;

	while (node)
	{
		conn_element *this = rb_entry(node, conn_element, rb_node);

		if (id < this->id)
		{
			node = node->rb_left;
		}
		else
			if (id > this->id)
			{
				node = node->rb_right;
			}
			else
				return this;
	}

	return NULL;
}

// Function will free the element
void erase_rb_conn(struct rb_root *root, conn_element *ele)
{
	BUG_ON(!ele);

	rb_erase(&ele->rb_node, root);

	kfree(ele);
}


void insert_rb_route(struct rb_root *root, route_element *ele)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*new)
	{
		route_element *this = rb_entry(*new, route_element, rb_node);

		parent = *new;

		if (ele->id.vm_id < this->id.vm_id)
		{
			new = &((*new)->rb_left);
		}
		else
			if (ele->id.vm_id > this->id.vm_id)
			{
				new = &((*new)->rb_right);
			}
	}

	rb_link_node(&ele->rb_node, parent, new);
	rb_insert_color(&ele->rb_node, root);
}

// Return NULL if no element contained within tree.
route_element* search_rb_route(struct rb_root *root, int id)
{
	struct rb_node *node = root->rb_node;

	while (node)
	{
		route_element *this = rb_entry(node, route_element, rb_node);

		if (id < this->id.vm_id)
		{
			node = node->rb_left;
		}
		else
			if (id > this->id.vm_id)
			{
				node = node->rb_right;
			}
			else
				return this;
	}

	return NULL;
}

// Function will free the element
void erase_rb_route(struct rb_root *root, route_element *ele)
{
	BUG_ON(!ele);

	rb_erase(&ele->rb_node, root);

	kfree(ele);
}
