/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTL9617C_DESTINATION_TREE_FIXTURE_H
#define RTL9617C_DESTINATION_TREE_FIXTURE_H

/* Small, deliberately unbalanced owner-tree model for MMIO fault tests.
 * This models link/unlink/ownership only, NOT Linux balancing or complexity.
 * test_fe_destination_index.py links Linux tools/lib/rbtree.c for those. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef container_of
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#endif
struct rb_node {
 struct rb_node *rb_left,*rb_right,*parent;
 bool erased;
};
struct rb_root {struct rb_node *rb_node;unsigned int erases;};
#define RB_ROOT ((struct rb_root){0})
#define RB_EMPTY_ROOT(root) (!(root)->rb_node)
#define rb_entry(p,t,m) container_of(p,t,m)
static inline void rb_link_node(struct rb_node *node,struct rb_node *parent,
                               struct rb_node **link)
{
 node->rb_left=node->rb_right=NULL;
 node->parent=parent;node->erased=false;*link=node;
}
static inline void rb_insert_color(struct rb_node *node,struct rb_root *root)
{
 (void)node;(void)root;
}
static inline void destination_fixture_replace(struct rb_root *root,
                                               struct rb_node *old,
                                               struct rb_node *replacement)
{
 if(!old->parent)root->rb_node=replacement;
 else if(old->parent->rb_left==old)old->parent->rb_left=replacement;
 else {assert(old->parent->rb_right==old);old->parent->rb_right=replacement;}
 if(replacement)replacement->parent=old->parent;
}
static inline void rb_erase(struct rb_node *node,struct rb_root *root)
{
 assert(!node->erased);node->erased=true;root->erases++;
 /* Flow-release tests count their separate cookie erases without building
  * that unrelated tree. Destination owners always have actual links. */
 if(!root->rb_node){assert(!node->parent);return;}
 if(!node->rb_left)destination_fixture_replace(root,node,node->rb_right);
 else if(!node->rb_right)destination_fixture_replace(root,node,node->rb_left);
 else {
  struct rb_node *next=node->rb_right;
  while(next->rb_left)next=next->rb_left;
  if(next->parent!=node) {
   destination_fixture_replace(root,next,next->rb_right);
   next->rb_right=node->rb_right;next->rb_right->parent=next;
  }
  destination_fixture_replace(root,node,next);
  next->rb_left=node->rb_left;next->rb_left->parent=next;
 }
 node->rb_left=node->rb_right=node->parent=NULL;
}
#endif
